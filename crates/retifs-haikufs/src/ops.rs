//! The C side: Haiku's file system operations over a [`Volume`]. A vnode's
//! private data is its inode number (never 0), so there is nothing to free
//! per node; file, directory, attribute directory, attribute and query
//! cookies are boxes. Every operation runs inside `guard`, so a panic is an
//! I/O error, never an unwind into C. The volume's lock is never held while
//! calling into the kernel side (it may call back in).
//!
//! Changes are told to node monitors (`notify_*`), so Tracker windows and
//! People follow them; changes from elsewhere reach live queries.
//!
//! Live queries: a thread follows the namespace's changes (the daemon's
//! watch, as the FUSE mount does) and tells each live query what came and
//! went, through the port and token it was opened with.

use std::collections::HashSet;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use libretifs::{Client, Request, Response};

use crate::ffi::*;
use crate::query::{self, Expr};
use crate::log;
use crate::volume::{Attr, Fail, Handle, Hit, Kind, Mount, ROOT, Volume};

/// The mounted volume, behind a lock: userlandfs calls in from several
/// threads, and the live-query watcher holds it too.
struct Vol {
    id: dev_t,
    inner: Mutex<Volume>,
    store: std::path::PathBuf,
    ns: String,
    live: Mutex<Vec<Live>>,
    next_live: AtomicU64,
    watching: AtomicBool,
    unmounted: AtomicBool,
}

/// A live query: what it matches now, and where to tell changes.
struct Live {
    id: u64,
    expr: Expr,
    port: port_id,
    token: u32,
    hits: HashSet<Hit>,
}

struct DirCookie {
    entries: Vec<(String, i64)>,
    pos: usize,
}

struct QueryCookie {
    hits: Vec<Hit>,
    pos: usize,
    live: Option<u64>,
}

/// An attribute open for reading or writing: a written one is committed on
/// close (one change per attribute written, as `fs_write_attr` does it).
struct AttrCookie {
    name: String,
    attr: Attr,
    dirty: bool,
    new: bool,
}

fn errno(f: Fail) -> status_t {
    match f {
        Fail::NotFound => libc::ENOENT,
        Fail::Exists => libc::EEXIST,
        Fail::NotDir => libc::ENOTDIR,
        Fail::IsDir => libc::EISDIR,
        Fail::NotEmpty => libc::ENOTEMPTY,
        Fail::NotHere => libc::EPERM,
        Fail::Invalid => libc::EINVAL,
        Fail::Io => libc::EIO,
    }
}

unsafe fn c_name(name: *const c_char) -> String {
    unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned()
}

fn cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

fn guard(name: &str, f: impl FnOnce() -> status_t) -> status_t {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(_) => {
            log(&format!("{name}: panicked"));
            libc::EIO
        }
    }
}

/// The volume's private data is an `Arc<Vol>` (from `Arc::into_raw`).
unsafe fn vol<'a>(volume: *mut fs_volume) -> &'a Vol {
    unsafe { &*((*volume).private_volume as *const Vol) }
}

unsafe fn vol_arc(volume: *mut fs_volume) -> Arc<Vol> {
    let p = unsafe { (*volume).private_volume as *const Vol };
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

fn lock(v: &Vol) -> MutexGuard<'_, Volume> {
    v.inner.lock().unwrap_or_else(|e| e.into_inner())
}

unsafe fn ino(node: *mut fs_vnode) -> i64 {
    unsafe { (*node).private_node as i64 }
}

fn mode(kind: Kind) -> libc::mode_t {
    match kind {
        Kind::Dir => libc::S_IFDIR | 0o755,
        Kind::File { .. } => libc::S_IFREG | 0o644,
    }
}

/// Writes one directory entry into `buf` if it fits.
unsafe fn put_dirent(buf: *mut libc::dirent, size: usize, dev: dev_t, ino: i64, name: &str) -> bool {
    unsafe { put_dirent_in(buf, size, dev, ino, 0, name) }
}

/// The same, with the directory the entry is in (a query's results).
unsafe fn put_dirent_in(buf: *mut libc::dirent, size: usize, dev: dev_t, ino: i64, dir: i64, name: &str) -> bool {
    let off = std::mem::offset_of!(libc::dirent, d_name);
    let need = off + name.len() + 1;
    if need > size {
        return false;
    }
    let reclen = ((need + 7) & !7).min(size);
    unsafe {
        ptr::addr_of_mut!((*buf).d_dev).write(dev);
        ptr::addr_of_mut!((*buf).d_pdev).write(dev);
        ptr::addr_of_mut!((*buf).d_ino).write(ino);
        ptr::addr_of_mut!((*buf).d_pino).write(dir);
        ptr::addr_of_mut!((*buf).d_reclen).write(reclen as u16);
        let dst = (buf as *mut u8).add(off);
        ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
        dst.add(name.len()).write(0);
    }
    true
}

unsafe fn read_entries(cookie: *mut c_void, dev: dev_t, buf: *mut libc::dirent, size: usize, num: *mut u32) -> status_t {
    let c = unsafe { &mut *(cookie as *mut DirCookie) };
    let Some((name, ino)) = c.entries.get(c.pos) else {
        unsafe { *num = 0 };
        return B_OK;
    };
    if !unsafe { put_dirent(buf, size, dev, *ino, name) } {
        return libc::B_BUFFER_OVERFLOW;
    }
    c.pos += 1;
    unsafe { *num = 1 };
    B_OK
}

fn copy_out(data: &[u8], pos: i64, buffer: *mut c_void, length: *mut usize) -> status_t {
    let start = usize::try_from(pos).unwrap_or(usize::MAX).min(data.len());
    let n = unsafe { *length }.min(data.len() - start);
    unsafe {
        ptr::copy_nonoverlapping(data[start..].as_ptr(), buffer as *mut u8, n);
        *length = n;
    }
    B_OK
}

// ------------------------------------------------------------- the volume

unsafe extern "C" fn mount(volume: *mut fs_volume, _device: *const c_char, _flags: u32, args: *const c_char, root: *mut ino_t) -> status_t {
    guard("mount", || {
        let args = if args.is_null() { String::new() } else { unsafe { CStr::from_ptr(args) }.to_string_lossy().into_owned() };
        let v = match Mount::parse(&args).and_then(Volume::open) {
            Ok(v) => v,
            Err(e) => {
                log(&format!("mount {args:?}: {e}"));
                return libc::EINVAL;
            }
        };
        let id = unsafe { (*volume).id };
        let vol = Arc::new(Vol {
            id,
            store: v.mount.store.clone(),
            ns: v.mount.ns.clone(),
            inner: Mutex::new(v),
            live: Mutex::new(Vec::new()),
            next_live: AtomicU64::new(1),
            watching: AtomicBool::new(false),
            unmounted: AtomicBool::new(false),
        });
        watch(vol.clone());
        unsafe {
            (*volume).private_volume = Arc::into_raw(vol) as *mut c_void;
            (*volume).ops = &raw mut VOLUME_OPS;
            let s = publish_vnode(volume, ROOT, ROOT as *mut c_void, &raw mut VNODE_OPS, libc::S_IFDIR as c_int, 0);
            if s != B_OK {
                drop(Arc::from_raw((*volume).private_volume as *const Vol));
                return s;
            }
            *root = ROOT;
        }
        log(&format!("mounted {args:?} as device {id}"));
        B_OK
    })
}

unsafe extern "C" fn unmount(volume: *mut fs_volume) -> status_t {
    guard("unmount", || {
        // The root's reference, taken when mount published it, is the file
        // system's to give back: the kernel frees the root after this (and
        // asserts that the mount has no vnodes left).
        unsafe { crate::ffi::put_vnode(volume, ROOT) };
        let v = unsafe { Arc::from_raw((*volume).private_volume as *const Vol) };
        // The watcher, if any, sees this and lets go of its reference.
        v.unmounted.store(true, Ordering::Release);
        B_OK
    })
}

unsafe extern "C" fn read_fs_info(volume: *mut fs_volume, info: *mut fs_info) -> status_t {
    guard("read_fs_info", || {
        let v = unsafe { vol(volume) };
        let (ns, bytes) = {
            let mut vol = lock(v);
            (vol.mount.ns.clone(), vol.total_bytes())
        };
        let info = unsafe { &mut *info };
        *info = unsafe { std::mem::zeroed() };
        info.dev = v.id;
        info.root = ROOT;
        info.flags = B_FS_IS_PERSISTENT | B_FS_IS_SHARED | B_FS_HAS_ATTR | B_FS_HAS_MIME | B_FS_HAS_QUERY;
        info.block_size = 4096;
        info.io_size = 65536;
        // What's free is what the store's disk has (Tracker checks before a
        // copy); the capacity is that and the namespace, at least one block
        // (a volume without capacity isn't offered by Tracker's Find).
        let free = free_bytes(&v.store) / 4096;
        info.total_blocks = ((bytes.div_ceil(4096) + free) as off_t).max(1);
        info.free_blocks = free as off_t;
        fill(&mut info.volume_name, &ns);
        fill(&mut info.device_name, "retifs");
        fill(&mut info.fsh_name, "retifs");
        B_OK
    })
}

fn free_bytes(store: &std::path::Path) -> u64 {
    let Ok(p) = CString::new(store.as_os_str().as_encoded_bytes()) else { return 0 };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(p.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    st.f_bavail as u64 * st.f_frsize as u64
}

fn fill(dst: &mut [c_char], s: &str) {
    let room = dst.len() - 1; // the rest stays NUL
    for (d, b) in dst.iter_mut().zip(s.bytes().take(room)) {
        *d = b as c_char;
    }
}

unsafe extern "C" fn sync(_volume: *mut fs_volume) -> status_t {
    B_OK
}

unsafe extern "C" fn get_vnode(volume: *mut fs_volume, id: ino_t, node: *mut fs_vnode, kind: *mut c_int, flags: *mut u32, _reenter: bool) -> status_t {
    guard("get_vnode", || {
        let Some(k) = lock(unsafe { vol(volume) }).kind(id) else { return libc::ENOENT };
        unsafe {
            (*node).private_node = id as *mut c_void;
            (*node).ops = &raw mut VNODE_OPS;
            *kind = (mode(k) & libc::S_IFMT) as c_int;
            *flags = 0;
        }
        B_OK
    })
}

// ------------------------------------------------------------- the nodes

unsafe extern "C" fn lookup(volume: *mut fs_volume, dir: *mut fs_vnode, name: *const c_char, id: *mut ino_t) -> status_t {
    guard("lookup", || {
        let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        // The lock is released before get_vnode, which may call back in.
        let Some(found) = lock(unsafe { vol(volume) }).lookup(unsafe { ino(dir) }, &name) else { return libc::ENOENT };
        let mut private = ptr::null_mut();
        let s = unsafe { ffi_get_vnode(volume, found, &mut private) };
        if s == B_OK {
            unsafe { *id = found };
        }
        s
    })
}

unsafe fn ffi_get_vnode(volume: *mut fs_volume, id: ino_t, private: *mut *mut c_void) -> status_t {
    unsafe { crate::ffi::get_vnode(volume, id, private) }
}

unsafe extern "C" fn get_vnode_name(volume: *mut fs_volume, node: *mut fs_vnode, buffer: *mut c_char, size: usize) -> status_t {
    guard("get_vnode_name", || {
        let v = lock(unsafe { vol(volume) });
        let Some(path) = v.path(unsafe { ino(node) }) else { return libc::ENOENT };
        let name = retifs_tree::name(path);
        if name.len() + 1 > size {
            return libc::B_BUFFER_OVERFLOW;
        }
        unsafe {
            ptr::copy_nonoverlapping(name.as_ptr(), buffer as *mut u8, name.len());
            *buffer.add(name.len()) = 0;
        }
        B_OK
    })
}

unsafe extern "C" fn put_vnode(_volume: *mut fs_volume, _node: *mut fs_vnode, _reenter: bool) -> status_t {
    B_OK
}

unsafe extern "C" fn fsync(_volume: *mut fs_volume, _node: *mut fs_vnode, _data_only: bool) -> status_t {
    B_OK
}

unsafe extern "C" fn access(_volume: *mut fs_volume, _node: *mut fs_vnode, _mode: c_int) -> status_t {
    B_OK
}

unsafe extern "C" fn read_stat(volume: *mut fs_volume, node: *mut fs_vnode, st: *mut libc::stat) -> status_t {
    guard("read_stat", || {
        let v = unsafe { vol(volume) };
        let id = unsafe { ino(node) };
        let Some(k) = lock(v).kind(id) else { return libc::ENOENT };
        let (size, mtime_ms) = match k {
            Kind::Dir => (0, None),
            Kind::File { size, mtime_ms } => (size, mtime_ms),
        };
        let secs = mtime_ms.map_or(0, |ms| ms.div_euclid(1000)) as libc::time_t;
        let nsec = mtime_ms.map_or(0, |ms| ms.rem_euclid(1000) * 1_000_000) as libc::c_long;
        let st = unsafe { &mut *st };
        *st = unsafe { std::mem::zeroed() };
        st.st_dev = v.id;
        st.st_ino = id;
        st.st_mode = mode(k);
        st.st_nlink = if matches!(k, Kind::Dir) { 2 } else { 1 };
        st.st_uid = unsafe { libc::getuid() };
        st.st_gid = unsafe { libc::getgid() };
        st.st_size = size as libc::off_t;
        st.st_blksize = 4096;
        st.st_blocks = size.div_ceil(512) as libc::blkcnt_t;
        st.st_atime = secs;
        st.st_atime_nsec = nsec;
        st.st_mtime = secs;
        st.st_mtime_nsec = nsec;
        st.st_ctime = secs;
        st.st_ctime_nsec = nsec;
        st.st_crtime = secs;
        st.st_crtime_nsec = nsec;
        B_OK
    })
}

unsafe extern "C" fn open(volume: *mut fs_volume, node: *mut fs_vnode, open_mode: c_int, cookie: *mut *mut c_void) -> status_t {
    guard("open", || {
        let id = unsafe { ino(node) };
        let mut v = lock(unsafe { vol(volume) });
        match v.kind(id) {
            None => return libc::ENOENT,
            Some(Kind::Dir) if open_mode & libc::O_ACCMODE != libc::O_RDONLY => return libc::EISDIR,
            _ => {}
        }
        // Emptying what has no content (People opens a contact so) changes nothing.
        let truncate = open_mode & libc::O_TRUNC != 0 && open_mode & libc::O_ACCMODE != libc::O_RDONLY && v.has_content(id);
        let append = open_mode & libc::O_APPEND != 0;
        let mut h = Handle { truncate, append, dirty: truncate, ..Default::default() };
        if truncate && let Err(f) = v.session(id, &mut h) {
            return errno(f);
        }
        unsafe { *cookie = Box::into_raw(Box::new(h)) as *mut c_void };
        B_OK
    })
}

/// Commits what the handle wrote, and tells the file's watchers.
unsafe extern "C" fn close(volume: *mut fs_volume, node: *mut fs_vnode, cookie: *mut c_void) -> status_t {
    guard("close", || {
        let h = unsafe { &mut *(cookie as *mut Handle) };
        if !h.dirty {
            return B_OK;
        }
        let v = unsafe { vol(volume) };
        let id = unsafe { ino(node) };
        let dir = {
            let mut vol = lock(v);
            if let Err(f) = vol.commit(id, h) {
                return errno(f);
            }
            vol.parent_ino(id)
        };
        unsafe { notify_stat_changed(v.id, dir, id, B_STAT_SIZE | B_STAT_MODIFICATION_TIME) };
        B_OK
    })
}

unsafe extern "C" fn free_cookie(volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void) -> status_t {
    guard("free_cookie", || {
        let mut h = unsafe { Box::from_raw(cookie as *mut Handle) };
        if h.session.is_some() {
            lock(unsafe { vol(volume) }).abort(&mut h);
        }
        B_OK
    })
}

unsafe extern "C" fn write(volume: *mut fs_volume, node: *mut fs_vnode, cookie: *mut c_void, pos: off_t, buffer: *const c_void, length: *mut usize) -> status_t {
    guard("write", || {
        if pos < 0 {
            return libc::EINVAL;
        }
        let h = unsafe { &mut *(cookie as *mut Handle) };
        let data = unsafe { std::slice::from_raw_parts(buffer as *const u8, *length) };
        match lock(unsafe { vol(volume) }).write(unsafe { ino(node) }, h, pos as u64, data) {
            Ok(()) => B_OK,
            Err(f) => {
                unsafe { *length = 0 };
                errno(f)
            }
        }
    })
}

unsafe extern "C" fn read(volume: *mut fs_volume, node: *mut fs_vnode, cookie: *mut c_void, pos: off_t, buffer: *mut c_void, length: *mut usize) -> status_t {
    guard("read", || {
        if pos < 0 {
            return libc::EINVAL;
        }
        let mut v = lock(unsafe { vol(volume) });
        let id = unsafe { ino(node) };
        match v.kind(id) {
            Some(Kind::Dir) => return libc::EISDIR,
            None => return libc::ENOENT,
            Some(Kind::File { .. }) => {}
        }
        let h = (!cookie.is_null()).then(|| unsafe { &*(cookie as *const Handle) });
        match v.read(id, h, pos as u64, unsafe { *length } as u64) {
            Ok(data) => copy_out(&data, 0, buffer, length),
            Err(e) => {
                log(&format!("read: {e}"));
                libc::EIO
            }
        }
    })
}

unsafe extern "C" fn open_dir(volume: *mut fs_volume, node: *mut fs_vnode, cookie: *mut *mut c_void) -> status_t {
    guard("open_dir", || {
        let Some(entries) = lock(unsafe { vol(volume) }).list(unsafe { ino(node) }) else { return libc::ENOTDIR };
        unsafe { *cookie = Box::into_raw(Box::new(DirCookie { entries, pos: 0 })) as *mut c_void };
        B_OK
    })
}

unsafe extern "C" fn read_dir(volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void, buf: *mut libc::dirent, size: usize, num: *mut u32) -> status_t {
    guard("read_dir", || unsafe { read_entries(cookie, vol(volume).id, buf, size, num) })
}

unsafe extern "C" fn rewind_dir(_volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void) -> status_t {
    unsafe { (*(cookie as *mut DirCookie)).pos = 0 };
    B_OK
}

unsafe extern "C" fn close_dir(_volume: *mut fs_volume, _node: *mut fs_vnode, _cookie: *mut c_void) -> status_t {
    B_OK
}

unsafe extern "C" fn free_dir_cookie(_volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void) -> status_t {
    unsafe { drop(Box::from_raw(cookie as *mut DirCookie)) };
    B_OK
}

// ------------------------------------------------------------- attributes

unsafe extern "C" fn open_attr_dir(volume: *mut fs_volume, node: *mut fs_vnode, cookie: *mut *mut c_void) -> status_t {
    guard("open_attr_dir", || {
        let names = lock(unsafe { vol(volume) }).attr_names(unsafe { ino(node) });
        let entries = names.into_iter().map(|n| (n, 0)).collect();
        unsafe { *cookie = Box::into_raw(Box::new(DirCookie { entries, pos: 0 })) as *mut c_void };
        B_OK
    })
}

unsafe extern "C" fn open_attr(volume: *mut fs_volume, node: *mut fs_vnode, name: *const c_char, open_mode: c_int, cookie: *mut *mut c_void) -> status_t {
    guard("open_attr", || {
        let name = unsafe { c_name(name) };
        let Some(mut attr) = lock(unsafe { vol(volume) }).attr(unsafe { ino(node) }, &name) else { return libc::ENOENT };
        let truncate = open_mode & libc::O_TRUNC != 0 && open_mode & libc::O_ACCMODE != libc::O_RDONLY;
        if truncate {
            attr.data.clear();
        }
        unsafe { *cookie = Box::into_raw(Box::new(AttrCookie { name, attr, dirty: truncate, new: false })) as *mut c_void };
        B_OK
    })
}

/// `fs_write_attr` comes here: the attribute, new or (unless `O_EXCL`) the
/// one there, now of `type_code`.
unsafe extern "C" fn create_attr(volume: *mut fs_volume, node: *mut fs_vnode, name: *const c_char, type_code: u32, open_mode: c_int, cookie: *mut *mut c_void) -> status_t {
    guard("create_attr", || {
        let name = unsafe { c_name(name) };
        let there = lock(unsafe { vol(volume) }).attr(unsafe { ino(node) }, &name);
        if there.is_some() && open_mode & libc::O_EXCL != 0 {
            return libc::EEXIST;
        }
        let new = there.is_none();
        let data = match there {
            Some(a) if open_mode & libc::O_TRUNC == 0 => a.data,
            _ => Vec::new(),
        };
        let attr = Attr { type_code, data };
        unsafe { *cookie = Box::into_raw(Box::new(AttrCookie { name, attr, dirty: true, new })) as *mut c_void };
        B_OK
    })
}

unsafe extern "C" fn read_attr(_volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void, pos: off_t, buffer: *mut c_void, length: *mut usize) -> status_t {
    guard("read_attr", || {
        let c = unsafe { &*(cookie as *const AttrCookie) };
        copy_out(&c.attr.data, pos, buffer, length)
    })
}

unsafe extern "C" fn write_attr(_volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void, pos: off_t, buffer: *const c_void, length: *mut usize) -> status_t {
    guard("write_attr", || {
        let Ok(pos) = usize::try_from(pos) else { return libc::EINVAL };
        let c = unsafe { &mut *(cookie as *mut AttrCookie) };
        let n = unsafe { *length };
        let data = unsafe { std::slice::from_raw_parts(buffer as *const u8, n) };
        if c.attr.data.len() < pos + n {
            c.attr.data.resize(pos + n, 0);
        }
        c.attr.data[pos..pos + n].copy_from_slice(data);
        c.dirty = true;
        B_OK
    })
}

/// Commits a written attribute, and tells the node's watchers.
unsafe extern "C" fn close_attr(volume: *mut fs_volume, node: *mut fs_vnode, cookie: *mut c_void) -> status_t {
    guard("close_attr", || {
        let c = unsafe { &mut *(cookie as *mut AttrCookie) };
        if !c.dirty {
            return B_OK;
        }
        c.dirty = false;
        let v = unsafe { vol(volume) };
        let id = unsafe { ino(node) };
        let (new, dir) = {
            let mut vol = lock(v);
            match vol.set_attr(id, &c.name, c.attr.clone()) {
                Ok(new) => (new || c.new, vol.parent_ino(id)),
                Err(f) => {
                    log(&format!("write attribute {:?}: {f:?}", c.name));
                    return errno(f);
                }
            }
        };
        let name = cstring(&c.name);
        unsafe { notify_attribute_changed(v.id, dir, id, name.as_ptr(), if new { B_ATTR_CREATED } else { B_ATTR_CHANGED }) };
        B_OK
    })
}

unsafe extern "C" fn read_attr_stat(_volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void, st: *mut libc::stat) -> status_t {
    guard("read_attr_stat", || {
        let c = unsafe { &*(cookie as *const AttrCookie) };
        let st = unsafe { &mut *st };
        *st = unsafe { std::mem::zeroed() };
        st.st_size = c.attr.data.len() as libc::off_t;
        st.st_type = c.attr.type_code;
        st.st_mode = libc::S_IFREG | 0o644;
        B_OK
    })
}

unsafe extern "C" fn free_attr_cookie(_volume: *mut fs_volume, _node: *mut fs_vnode, cookie: *mut c_void) -> status_t {
    unsafe { drop(Box::from_raw(cookie as *mut AttrCookie)) };
    B_OK
}

unsafe extern "C" fn remove_attr(volume: *mut fs_volume, node: *mut fs_vnode, name: *const c_char) -> status_t {
    guard("remove_attr", || {
        let name = unsafe { c_name(name) };
        let v = unsafe { vol(volume) };
        let id = unsafe { ino(node) };
        let dir = {
            let mut vol = lock(v);
            if let Err(f) = vol.remove_attr(id, &name) {
                return errno(f);
            }
            vol.parent_ino(id)
        };
        let name = cstring(&name);
        unsafe { notify_attribute_changed(v.id, dir, id, name.as_ptr(), B_ATTR_REMOVED) };
        B_OK
    })
}

// ------------------------------------------------------------- changes

/// A new file: made, opened (the cookie), and in the kernel's hands (as a
/// lookup leaves it).
unsafe extern "C" fn create(volume: *mut fs_volume, dir: *mut fs_vnode, name: *const c_char, open_mode: c_int, _perms: c_int, cookie: *mut *mut c_void, new_id: *mut ino_t) -> status_t {
    guard("create", || {
        let name = unsafe { c_name(name) };
        let v = unsafe { vol(volume) };
        let d = unsafe { ino(dir) };
        let made = lock(v).create(d, &name);
        let id = match made {
            Ok(id) => id,
            Err(f) => return errno(f),
        };
        let mut private = ptr::null_mut();
        let s = unsafe { ffi_get_vnode(volume, id, &mut private) };
        if s != B_OK {
            return s;
        }
        let (truncate, append) = (open_mode & libc::O_TRUNC != 0, open_mode & libc::O_APPEND != 0);
        unsafe {
            *cookie = Box::into_raw(Box::new(Handle { truncate, append, ..Default::default() })) as *mut c_void;
            *new_id = id;
        }
        let n = cstring(&name);
        unsafe { notify_entry_created(v.id, d, n.as_ptr(), id) };
        B_OK
    })
}

unsafe extern "C" fn create_dir(volume: *mut fs_volume, parent: *mut fs_vnode, name: *const c_char, _perms: c_int) -> status_t {
    guard("create_dir", || {
        let name = unsafe { c_name(name) };
        let v = unsafe { vol(volume) };
        let d = unsafe { ino(parent) };
        let made = lock(v).mkdir(d, &name);
        match made {
            Ok(id) => {
                let n = cstring(&name);
                unsafe { notify_entry_created(v.id, d, n.as_ptr(), id) };
                B_OK
            }
            Err(f) => errno(f),
        }
    })
}

unsafe extern "C" fn remove_dir(volume: *mut fs_volume, parent: *mut fs_vnode, name: *const c_char) -> status_t {
    guard("remove_dir", || {
        let name = unsafe { c_name(name) };
        let v = unsafe { vol(volume) };
        let d = unsafe { ino(parent) };
        let gone = lock(v).rmdir(d, &name);
        match gone {
            Ok(id) => {
                let n = cstring(&name);
                unsafe { notify_entry_removed(v.id, d, n.as_ptr(), id) };
                B_OK
            }
            Err(f) => errno(f),
        }
    })
}

unsafe extern "C" fn unlink(volume: *mut fs_volume, dir: *mut fs_vnode, name: *const c_char) -> status_t {
    guard("unlink", || {
        let name = unsafe { c_name(name) };
        let v = unsafe { vol(volume) };
        let d = unsafe { ino(dir) };
        let gone = lock(v).unlink(d, &name);
        match gone {
            Ok(id) => {
                let n = cstring(&name);
                unsafe { notify_entry_removed(v.id, d, n.as_ptr(), id) };
                B_OK
            }
            Err(f) => errno(f),
        }
    })
}

unsafe extern "C" fn rename(volume: *mut fs_volume, from_dir: *mut fs_vnode, from_name: *const c_char, to_dir: *mut fs_vnode, to_name: *const c_char) -> status_t {
    guard("rename", || {
        let (from, to) = unsafe { (c_name(from_name), c_name(to_name)) };
        let v = unsafe { vol(volume) };
        let (fd, td) = unsafe { (ino(from_dir), ino(to_dir)) };
        let moved = lock(v).rename(fd, &from, td, &to);
        match moved {
            Ok((id, replaced)) => {
                let (f, t) = (cstring(&from), cstring(&to));
                unsafe {
                    if let Some(old) = replaced {
                        notify_entry_removed(v.id, td, t.as_ptr(), old);
                    }
                    notify_entry_moved(v.id, fd, f.as_ptr(), td, t.as_ptr(), id);
                }
                B_OK
            }
            Err(f) => errno(f),
        }
    })
}

/// Size (a truncation, one new version) and modification time; the rest a
/// record doesn't have.
unsafe extern "C" fn write_stat(volume: *mut fs_volume, node: *mut fs_vnode, st: *const libc::stat, mask: u32) -> status_t {
    guard("write_stat", || {
        let v = unsafe { vol(volume) };
        let id = unsafe { ino(node) };
        let st = unsafe { &*st };
        let dir = {
            let mut vol = lock(v);
            if mask & B_STAT_SIZE != 0 {
                let mut h = Handle::default();
                let r = vol.truncate(id, &mut h, st.st_size.max(0) as u64).and_then(|()| vol.commit(id, &mut h));
                if let Err(f) = r {
                    vol.abort(&mut h);
                    return errno(f);
                }
            }
            if mask & B_STAT_MODIFICATION_TIME != 0 {
                let ms = st.st_mtime as i64 * 1000 + st.st_mtime_nsec as i64 / 1_000_000;
                // A directory has no time of its own to keep.
                if let Err(f) = vol.set_mtime(id, ms)
                    && f != Fail::NotFound
                {
                    return errno(f);
                }
            }
            vol.parent_ino(id)
        };
        unsafe { notify_stat_changed(v.id, dir, id, mask) };
        B_OK
    })
}

// ------------------------------------------------------------- indexes

unsafe extern "C" fn open_index_dir(volume: *mut fs_volume, cookie: *mut *mut c_void) -> status_t {
    guard("open_index_dir", || {
        let entries = lock(unsafe { vol(volume) }).indexes().into_iter().map(|(n, _)| (n, 0)).collect();
        unsafe { *cookie = Box::into_raw(Box::new(DirCookie { entries, pos: 0 })) as *mut c_void };
        B_OK
    })
}

unsafe extern "C" fn read_index_dir(volume: *mut fs_volume, cookie: *mut c_void, buf: *mut libc::dirent, size: usize, num: *mut u32) -> status_t {
    guard("read_index_dir", || unsafe { read_entries(cookie, vol(volume).id, buf, size, num) })
}

unsafe extern "C" fn rewind_index_dir(_volume: *mut fs_volume, cookie: *mut c_void) -> status_t {
    unsafe { (*(cookie as *mut DirCookie)).pos = 0 };
    B_OK
}

unsafe extern "C" fn close_index_dir(_volume: *mut fs_volume, _cookie: *mut c_void) -> status_t {
    B_OK
}

unsafe extern "C" fn free_index_dir_cookie(_volume: *mut fs_volume, cookie: *mut c_void) -> status_t {
    unsafe { drop(Box::from_raw(cookie as *mut DirCookie)) };
    B_OK
}

unsafe extern "C" fn read_index_stat(volume: *mut fs_volume, name: *const c_char, st: *mut libc::stat) -> status_t {
    guard("read_index_stat", || {
        let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        let Some((_, t)) = lock(unsafe { vol(volume) }).indexes().into_iter().find(|(n, _)| *n == name) else { return libc::ENOENT };
        let st = unsafe { &mut *st };
        *st = unsafe { std::mem::zeroed() };
        st.st_type = t;
        st.st_mode = libc::S_IFREG | 0o444;
        B_OK
    })
}

// ------------------------------------------------------------- queries

unsafe extern "C" fn open_query(volume: *mut fs_volume, text: *const c_char, flags: u32, port: port_id, token: u32, cookie: *mut *mut c_void) -> status_t {
    guard("open_query", || {
        let text = unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned();
        let expr = match query::parse(&text) {
            Ok(e) => e,
            Err(e) => {
                log(&format!("query {text:?}: {e}"));
                return libc::EINVAL;
            }
        };
        let v = unsafe { vol(volume) };
        let hits = match lock(v).query(&expr) {
            Ok(h) => h,
            Err(e) => {
                log(&format!("query {text:?}: {e}"));
                return libc::EIO;
            }
        };
        let live = (flags & B_LIVE_QUERY != 0).then(|| {
            let id = v.next_live.fetch_add(1, Ordering::Relaxed);
            let l = Live { id, expr, port, token, hits: hits.iter().cloned().collect() };
            v.live.lock().unwrap_or_else(|e| e.into_inner()).push(l);
            watch(unsafe { vol_arc(volume) });
            id
        });
        unsafe { *cookie = Box::into_raw(Box::new(QueryCookie { hits, pos: 0, live })) as *mut c_void };
        B_OK
    })
}

unsafe extern "C" fn read_query(volume: *mut fs_volume, cookie: *mut c_void, buf: *mut libc::dirent, size: usize, num: *mut u32) -> status_t {
    guard("read_query", || {
        let dev = unsafe { vol(volume) }.id;
        let c = unsafe { &mut *(cookie as *mut QueryCookie) };
        let Some(h) = c.hits.get(c.pos) else {
            unsafe { *num = 0 };
            return B_OK;
        };
        if !unsafe { put_dirent_in(buf, size, dev, h.ino, h.dir, &h.name) } {
            return libc::B_BUFFER_OVERFLOW;
        }
        c.pos += 1;
        unsafe { *num = 1 };
        B_OK
    })
}

unsafe extern "C" fn rewind_query(_volume: *mut fs_volume, cookie: *mut c_void) -> status_t {
    unsafe { (*(cookie as *mut QueryCookie)).pos = 0 };
    B_OK
}

unsafe extern "C" fn close_query(volume: *mut fs_volume, cookie: *mut c_void) -> status_t {
    guard("close_query", || {
        if let Some(id) = unsafe { &*(cookie as *const QueryCookie) }.live {
            unsafe { vol(volume) }.live.lock().unwrap_or_else(|e| e.into_inner()).retain(|l| l.id != id);
        }
        B_OK
    })
}

unsafe extern "C" fn free_query_cookie(_volume: *mut fs_volume, cookie: *mut c_void) -> status_t {
    unsafe { drop(Box::from_raw(cookie as *mut QueryCookie)) };
    B_OK
}

/// Starts the volume's watcher once (at mount): a long poll on the
/// namespace's changes on a thread of its own, and after each change
/// `on_change`. Ends when the volume is unmounted.
fn watch(v: Arc<Vol>) {
    if v.watching.swap(true, Ordering::AcqRel) {
        return;
    }
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
        let mut since = 0;
        while !v.unmounted.load(Ordering::Acquire) {
            let Ok(mut client) = rt.block_on(Client::connect(&v.store)) else {
                std::thread::sleep(Duration::from_secs(5)); // the daemon restarting
                continue;
            };
            // Short polls, so an unmount is noticed soon.
            while !v.unmounted.load(Ordering::Acquire) {
                match rt.block_on(client.call(Request::Watch { ns: v.ns.clone(), since, timeout_ms: 5_000 })) {
                    Ok(Response::Changed { count }) => {
                        if count != since {
                            since = count;
                            on_change(&v);
                        }
                    }
                    _ => break,
                }
            }
        }
    });
}

/// Changes at once beyond which only what's near the top is told (a large
/// library's first sync: a Tracker window shows the top folders).
const MANY_CHANGES: usize = 2000;

/// After a change to the namespace (here, or another member's arriving):
/// the tree is read again, node monitors are told what came, went and
/// changed (so a Tracker window fills as a library syncs), and live queries
/// what they match now.
fn on_change(v: &Vol) {
    let mut entries: Vec<(u8, i64, i64, String)> = Vec::new();
    let mut notes = Vec::new();
    {
        let mut lives = v.live.lock().unwrap_or_else(|e| e.into_inner());
        let mut vol = lock(v);
        let before = vol.snapshot();
        if let Err(e) = vol.refresh(true) {
            log(&format!("after a change: {e}"));
            return;
        }
        let after = vol.snapshot();
        // 0 came, 1 went, 2 changed.
        let mut changes: Vec<(u8, String)> = Vec::new();
        for (p, n) in &after {
            match before.get(p) {
                None => changes.push((0, p.clone())),
                Some(o) if o != n => changes.push((2, p.clone())),
                _ => {}
            }
        }
        changes.extend(before.keys().filter(|p| !after.contains_key(*p)).map(|p| (1, p.clone())));
        if changes.len() > MANY_CHANGES {
            changes.retain(|(_, p)| p.matches('/').count() <= 2);
        }
        for (k, p) in changes {
            if p == "/" {
                continue;
            }
            let dir = vol.ino(retifs_tree::parent(&p));
            let ino = vol.ino(&p);
            entries.push((k, dir, ino, retifs_tree::name(&p).to_string()));
        }
        for l in lives.iter_mut() {
            let Ok(now) = vol.query(&l.expr) else { continue };
            let now: HashSet<Hit> = now.into_iter().collect();
            notes.extend(now.difference(&l.hits).map(|h| (true, l.port, l.token, h.clone())));
            notes.extend(l.hits.difference(&now).map(|h| (false, l.port, l.token, h.clone())));
            l.hits = now;
        }
    }
    for (k, dir, ino, name) in entries {
        let Ok(name) = CString::new(name) else { continue };
        unsafe {
            match k {
                0 => notify_entry_created(v.id, dir, name.as_ptr(), ino),
                1 => notify_entry_removed(v.id, dir, name.as_ptr(), ino),
                _ => notify_stat_changed(v.id, dir, ino, B_STAT_SIZE | B_STAT_MODIFICATION_TIME),
            };
        }
    }
    for (came, port, token, h) in notes {
        let Ok(name) = CString::new(h.name) else { continue };
        let s = unsafe {
            if came {
                notify_query_entry_created(port, token as i32, v.id, h.dir, name.as_ptr(), h.ino)
            } else {
                notify_query_entry_removed(port, token as i32, v.id, h.dir, name.as_ptr(), h.ino)
            }
        };
        if s != B_OK {
            log(&format!("live query notice: {s}"));
        }
    }
}

// ------------------------------------------------------------- the module

unsafe extern "C" fn std_ops(op: i32) -> status_t {
    match op {
        B_MODULE_INIT | B_MODULE_UNINIT => B_OK,
        _ => libc::EINVAL,
    }
}

static mut VOLUME_OPS: fs_volume_ops = fs_volume_ops {
    unmount: Some(unmount),
    read_fs_info: Some(read_fs_info),
    sync: Some(sync),
    get_vnode: Some(get_vnode),
    open_index_dir: Some(open_index_dir),
    close_index_dir: Some(close_index_dir),
    free_index_dir_cookie: Some(free_index_dir_cookie),
    read_index_dir: Some(read_index_dir),
    rewind_index_dir: Some(rewind_index_dir),
    read_index_stat: Some(read_index_stat),
    open_query: Some(open_query),
    close_query: Some(close_query),
    free_query_cookie: Some(free_query_cookie),
    read_query: Some(read_query),
    rewind_query: Some(rewind_query),
    ..unsafe { std::mem::zeroed() }
};

static mut VNODE_OPS: fs_vnode_ops = fs_vnode_ops {
    lookup: Some(lookup),
    get_vnode_name: Some(get_vnode_name),
    put_vnode: Some(put_vnode),
    fsync: Some(fsync),
    access: Some(access),
    unlink: Some(unlink),
    rename: Some(rename),
    read_stat: Some(read_stat),
    write_stat: Some(write_stat),
    create: Some(create),
    open: Some(open),
    close: Some(close),
    free_cookie: Some(free_cookie),
    read: Some(read),
    write: Some(write),
    create_dir: Some(create_dir),
    remove_dir: Some(remove_dir),
    open_dir: Some(open_dir),
    close_dir: Some(close_dir),
    free_dir_cookie: Some(free_dir_cookie),
    read_dir: Some(read_dir),
    rewind_dir: Some(rewind_dir),
    open_attr_dir: Some(open_attr_dir),
    close_attr_dir: Some(close_dir),
    free_attr_dir_cookie: Some(free_dir_cookie),
    read_attr_dir: Some(read_dir),
    rewind_attr_dir: Some(rewind_dir),
    create_attr: Some(create_attr),
    open_attr: Some(open_attr),
    close_attr: Some(close_attr),
    free_attr_cookie: Some(free_attr_cookie),
    read_attr: Some(read_attr),
    write_attr: Some(write_attr),
    read_attr_stat: Some(read_attr_stat),
    remove_attr: Some(remove_attr),
    ..unsafe { std::mem::zeroed() }
};

static mut FS_MODULE: file_system_module_info = file_system_module_info {
    info: module_info { name: c"file_systems/retifs/v1".as_ptr(), flags: 0, std_ops: Some(std_ops) },
    short_name: c"retifs".as_ptr(),
    pretty_name: c"retifs".as_ptr(),
    flags: 0,
    mount: Some(mount),
    ..unsafe { std::mem::zeroed() }
};

/// What userlandfs looks up in a Haiku-interface module: its modules,
/// null-terminated.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)]
pub static mut modules: [*mut module_info; 2] = [&raw mut FS_MODULE as *mut module_info, ptr::null_mut()];
