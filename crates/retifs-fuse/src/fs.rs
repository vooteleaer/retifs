//! The FUSE frontend (ADR-0002): translates file operations into the local
//! record API (ADR-0004). It holds no keys and no store; `retifsd` does.

use std::{
    collections::HashMap,
    ffi::OsStr,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, ReplyXattr, Request as Req, TimeOrNow,
};
use libretifs::{AttrValue, Client, RecordView, Request, Response, TxStep};

use crate::tree::{self, Node, Tree, QUERY_DIR};

/// How long the kernel may cache entries and attributes, and how often the
/// tree is re-read from the daemon (other members' writes show up after this).
const TTL: Duration = Duration::from_secs(1);
const XATTR_PREFIX: &str = "user.retifs.";
/// `user.retifs.local`: computed, whether a file's content is on this device.
const LOCAL_XATTR: &str = "local";
/// Content kept in memory for reads, at most.
const CACHE_BYTES: usize = 256 << 20;

enum Entry {
    Dir,
    File { size: u64, mtime_ms: Option<i64> },
    Link(String),
}

struct Handle {
    path: String,
    /// The whole content once read or written; written back on flush if dirty.
    buf: Option<Vec<u8>>,
    dirty: bool,
}

pub struct RetifsFs {
    rt: tokio::runtime::Runtime,
    client: Client,
    ns: String,
    tree: Tree,
    records: HashMap<String, RecordView>,
    loaded: Option<Instant>,
    inodes: HashMap<String, u64>,
    paths: Vec<String>,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    content: HashMap<String, Vec<u8>>,
    queries: HashMap<String, (Instant, Vec<(String, String)>)>,
    uid: u32,
    gid: u32,
    started: SystemTime,
    /// How long a read may wait for content that isn't here yet.
    wait: Duration,
}

pub fn mount(store: &Path, ns: &str, mountpoint: &Path, wait: Duration) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    let client = rt.block_on(Client::connect(store)).map_err(|e| format!("can't reach retifsd at {}: {e}", store.display()))?;
    let fs = RetifsFs {
        rt,
        client,
        ns: ns.to_string(),
        tree: Tree::default(),
        records: HashMap::new(),
        loaded: None,
        inodes: HashMap::from([("/".to_string(), 1)]),
        paths: vec![String::new(), "/".to_string()],
        handles: HashMap::new(),
        next_fh: 1,
        content: HashMap::new(),
        queries: HashMap::new(),
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        started: SystemTime::now(),
        wait,
    };
    let opts = [MountOption::FSName(format!("retifs:{ns}")), MountOption::Subtype("retifs".into()), MountOption::DefaultPermissions];
    fuser::mount2(fs, mountpoint, &opts).map_err(|e| e.to_string())
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl RetifsFs {
    fn call(&mut self, req: Request) -> Result<Response, i32> {
        match self.rt.block_on(self.client.call(req)) {
            Ok(Response::Error { message }) => {
                eprintln!("retifs-mount: {message}");
                Err(libc::EIO)
            }
            Ok(r) => Ok(r),
            Err(e) => {
                eprintln!("retifs-mount: retifsd: {e}");
                Err(libc::EIO)
            }
        }
    }

    fn records(&mut self, terms: Vec<String>) -> Result<Vec<RecordView>, i32> {
        match self.call(Request::Query { ns: self.ns.clone(), terms, at: None })? {
            Response::Records { records } => Ok(records),
            _ => Err(libc::EIO),
        }
    }

    /// Re-reads the namespace if the tree is older than the TTL (or `force`).
    fn refresh(&mut self, force: bool) {
        if !force && self.loaded.is_some_and(|t| t.elapsed() < TTL) {
            return;
        }
        if let Ok(records) = self.records(Vec::new()) {
            self.tree = Tree::build(&records);
            self.records = records.into_iter().map(|r| (r.id.clone(), r)).collect();
            self.loaded = Some(Instant::now());
        }
    }

    fn ino(&mut self, path: &str) -> u64 {
        if let Some(i) = self.inodes.get(path) {
            return *i;
        }
        let i = self.paths.len() as u64;
        self.paths.push(path.to_string());
        self.inodes.insert(path.to_string(), i);
        i
    }

    fn path(&self, ino: u64) -> Option<String> {
        self.paths.get(ino as usize).filter(|p| !p.is_empty()).cloned()
    }

    /// A query directory's entries: (name, symlink target), cached for the TTL.
    fn query(&mut self, dir: &str) -> Vec<(String, String)> {
        if let Some((t, v)) = self.queries.get(dir)
            && t.elapsed() < TTL
        {
            return v.clone();
        }
        let terms = tree::query_terms(tree::name(dir));
        self.refresh(false);
        let found = self.records(terms).unwrap_or_default();
        let mut out: Vec<(String, String)> = Vec::new();
        for r in found {
            // Where the tree put it (its path, or its place under .records).
            let Some(at) = self.tree.nodes.iter().find(|(_, n)| n.id() == Some(r.id.as_str())).map(|(p, _)| p.clone()) else { continue };
            let mut name = tree::name(&at).to_string();
            if out.iter().any(|(n, _)| *n == name) {
                name = format!("{name}~{}", &r.id[..8]);
            }
            out.push((name, format!("../..{at}")));
        }
        self.queries.insert(dir.to_string(), (Instant::now(), out.clone()));
        out
    }

    fn entry(&mut self, path: &str) -> Option<Entry> {
        self.refresh(false);
        if let Some(n) = self.tree.get(path) {
            return Some(match n {
                Node::Dir { .. } => Entry::Dir,
                Node::File { size, mtime_ms, .. } => {
                    let open = self.handles.values().find(|h| h.path == path && h.buf.is_some());
                    Entry::File { size: open.map_or(*size, |h| h.buf.as_ref().unwrap().len() as u64), mtime_ms: *mtime_ms }
                }
            });
        }
        let up = tree::parent(path);
        if up == QUERY_DIR {
            return Some(Entry::Dir); // any name under /.query is a query
        }
        if tree::parent(up) == QUERY_DIR {
            let name = tree::name(path).to_string();
            return self.query(up).into_iter().find(|(n, _)| *n == name).map(|(_, target)| Entry::Link(target));
        }
        None
    }

    fn attr(&mut self, path: &str, e: &Entry) -> FileAttr {
        let ino = self.ino(path);
        let (kind, perm, size, mtime) = match e {
            Entry::Dir => (FileType::Directory, 0o755, 0, self.started),
            Entry::File { size, mtime_ms } => {
                let t = mtime_ms.map_or(self.started, |ms| UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64));
                (FileType::RegularFile, 0o644, *size, t)
            }
            Entry::Link(target) => (FileType::Symlink, 0o777, target.len() as u64, self.started),
        };
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm,
            nlink: if matches!(e, Entry::Dir) { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn file_id(&self, path: &str) -> Option<(String, Option<String>)> {
        match self.tree.get(path)? {
            Node::File { id, cap, .. } => Some((id.clone(), cap.clone())),
            Node::Dir { .. } => None,
        }
    }

    /// Part of a file's content, fetched from peers if it isn't here yet.
    fn read_range(&mut self, cap: &str, offset: u64, len: u64) -> Result<Vec<u8>, i32> {
        let req = Request::ReadRange { cap: cap.to_string(), ns: Some(self.ns.clone()), offset, len, wait_ms: self.wait.as_millis() as u64 };
        match self.call(req)? {
            Response::Range { data } => Ok(data),
            _ => Err(libc::EIO),
        }
    }

    /// A file's whole content (to change it), fetched if it isn't here yet.
    fn read_content(&mut self, cap: Option<String>) -> Result<Vec<u8>, i32> {
        let Some(cap) = cap else { return Ok(Vec::new()) };
        if let Some(c) = self.content.get(&cap) {
            return Ok(c.clone());
        }
        match self.call(Request::ReadRange { cap: cap.clone(), ns: Some(self.ns.clone()), offset: 0, len: u64::MAX, wait_ms: self.wait.as_millis() as u64 })? {
            Response::Range { data } => {
                if self.content.values().map(Vec::len).sum::<usize>() + data.len() > CACHE_BYTES {
                    self.content.clear();
                }
                self.content.insert(cap, data.clone());
                Ok(data)
            }
            _ => Err(libc::EIO),
        }
    }

    fn set(&mut self, id: &str, attrs: Vec<(String, AttrValue)>, unset: Vec<String>, data: Option<Vec<u8>>) -> Result<(), i32> {
        self.call(Request::RecordSet { ns: self.ns.clone(), id: id.to_string(), attrs, unset, data })?;
        self.refresh(true);
        Ok(())
    }

    fn create_record(&mut self, attrs: Vec<(String, AttrValue)>, data: Option<Vec<u8>>) -> Result<String, i32> {
        match self.call(Request::RecordCreate { ns: self.ns.clone(), attrs, data })? {
            Response::Records { records } if !records.is_empty() => {
                self.refresh(true);
                Ok(records[0].id.clone())
            }
            _ => Err(libc::EIO),
        }
    }

    /// Writes a handle's content back as the record's new content.
    fn write_back(&mut self, fh: u64) -> Result<(), i32> {
        let Some(h) = self.handles.get_mut(&fh) else { return Ok(()) };
        if !h.dirty {
            return Ok(());
        }
        h.dirty = false;
        let (path, data) = (h.path.clone(), h.buf.clone().unwrap_or_default());
        self.refresh(false);
        let (id, _) = self.file_id(&path).ok_or(libc::ENOENT)?;
        self.set(&id, vec![("mtime".into(), AttrValue::Int(now_ms()))], Vec::new(), Some(data))
    }

    fn writable_path(&self, path: &str) -> Result<(), i32> {
        if tree::is_virtual(path) { Err(libc::EPERM) } else { Ok(()) }
    }
}

fn os(name: &OsStr) -> Result<&str, i32> {
    name.to_str().ok_or(libc::EINVAL)
}

impl Filesystem for RetifsFs {
    fn init(&mut self, _req: &Req, config: &mut KernelConfig) -> Result<(), libc::c_int> {
        // O_TRUNC arrives with open, not as a separate truncate: one version per write.
        let _ = config.add_capabilities(fuser::consts::FUSE_ATOMIC_O_TRUNC);
        self.refresh(true);
        Ok(())
    }

    fn lookup(&mut self, _req: &Req, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let (Some(dir), Ok(name)) = (self.path(parent), os(name)) else { return reply.error(libc::ENOENT) };
        let path = tree::join(&dir, name);
        let mut found = self.entry(&path);
        // Not found in a view that may be stale (a record made a moment ago by
        // another program or member): look again before saying so.
        if found.is_none() && self.loaded.is_some_and(|t| t.elapsed() > Duration::from_millis(100)) {
            self.refresh(true);
            found = self.entry(&path);
        }
        match found {
            Some(e) => {
                let a = self.attr(&path, &e);
                reply.entry(&TTL, &a, 0)
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Req, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(path) = self.path(ino) else { return reply.error(libc::ENOENT) };
        match self.entry(&path) {
            Some(e) => {
                let a = self.attr(&path, &e);
                reply.attr(&TTL, &a)
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn readlink(&mut self, _req: &Req, ino: u64, reply: ReplyData) {
        let Some(path) = self.path(ino) else { return reply.error(libc::ENOENT) };
        match self.entry(&path) {
            Some(Entry::Link(target)) => reply.data(target.as_bytes()),
            _ => reply.error(libc::EINVAL),
        }
    }

    fn readdir(&mut self, _req: &Req, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        let Some(dir) = self.path(ino) else { return reply.error(libc::ENOENT) };
        self.refresh(false);
        let mut list: Vec<(String, FileType)> = vec![(".".into(), FileType::Directory), ("..".into(), FileType::Directory)];
        if tree::parent(&dir) == QUERY_DIR {
            list.extend(self.query(&dir).into_iter().map(|(n, _)| (n, FileType::Symlink)));
        } else {
            for (name, path) in self.tree.children(&dir) {
                let kind = if matches!(self.tree.get(&path), Some(Node::Dir { .. })) { FileType::Directory } else { FileType::RegularFile };
                list.push((name, kind));
            }
        }
        for (i, (name, kind)) in list.into_iter().enumerate().skip(offset as usize) {
            let child = if name == "." || name == ".." { ino } else { self.ino(&tree::join(&dir, &name)) };
            if reply.add(child, (i + 1) as i64, kind, &name) {
                break;
            }
        }
        reply.ok()
    }

    fn open(&mut self, _req: &Req, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(path) = self.path(ino) else { return reply.error(libc::ENOENT) };
        self.refresh(false);
        match self.tree.get(&path) {
            Some(Node::File { .. }) => {}
            Some(Node::Dir { .. }) => return reply.error(libc::EISDIR),
            None => return reply.error(libc::ENOENT),
        }
        let truncate = flags & libc::O_TRUNC != 0 && flags & libc::O_ACCMODE != libc::O_RDONLY;
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, Handle { path, buf: truncate.then(Vec::new), dirty: truncate });
        reply.opened(fh, 0)
    }

    fn read(&mut self, _req: &Req, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock: Option<u64>, reply: ReplyData) {
        let Some(h) = self.handles.get(&fh) else { return reply.error(libc::EBADF) };
        if let Some(b) = &h.buf {
            // Being written: the buffer is the content.
            let start = (offset as usize).min(b.len());
            let end = (start + size as usize).min(b.len());
            return reply.data(&b[start..end]);
        }
        // Only the range asked for, fetched if it isn't here (a 1 GB file read
        // for its header costs about one chunk).
        let path = h.path.clone();
        let Some(cap) = self.file_id(&path).and_then(|(_, c)| c) else { return reply.data(&[]) };
        match self.read_range(&cap, offset.max(0) as u64, size as u64) {
            Ok(d) => reply.data(&d),
            Err(e) => reply.error(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(&mut self, _req: &Req, _ino: u64, fh: u64, offset: i64, data: &[u8], _wf: u32, _flags: i32, _lock: Option<u64>, reply: ReplyWrite) {
        let Some(h) = self.handles.get(&fh) else { return reply.error(libc::EBADF) };
        if h.buf.is_none() {
            let path = h.path.clone();
            let cap = self.file_id(&path).and_then(|(_, c)| c);
            match self.read_content(cap) {
                Ok(d) => self.handles.get_mut(&fh).unwrap().buf = Some(d),
                Err(e) => return reply.error(e),
            }
        }
        let h = self.handles.get_mut(&fh).unwrap();
        let buf = h.buf.as_mut().unwrap();
        let end = offset as usize + data.len();
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[offset as usize..end].copy_from_slice(data);
        h.dirty = true;
        reply.written(data.len() as u32)
    }

    fn flush(&mut self, _req: &Req, _ino: u64, fh: u64, _lock: u64, reply: ReplyEmpty) {
        match self.write_back(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn release(&mut self, _req: &Req, _ino: u64, fh: u64, _flags: i32, _lock: Option<u64>, _flush: bool, reply: ReplyEmpty) {
        let r = self.write_back(fh);
        self.handles.remove(&fh);
        match r {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn fsync(&mut self, _req: &Req, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        match self.write_back(fh) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Req,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path(ino) else { return reply.error(libc::ENOENT) };
        self.refresh(false);
        if let Some(size) = size {
            let Some((id, cap)) = self.file_id(&path) else { return reply.error(libc::EISDIR) };
            let open = fh.filter(|f| self.handles.contains_key(f));
            match open {
                Some(f) => {
                    if self.handles[&f].buf.is_none() {
                        match self.read_content(cap) {
                            Ok(d) => self.handles.get_mut(&f).unwrap().buf = Some(d),
                            Err(e) => return reply.error(e),
                        }
                    }
                    let h = self.handles.get_mut(&f).unwrap();
                    h.buf.as_mut().unwrap().resize(size as usize, 0);
                    h.dirty = true;
                }
                None => {
                    // A truncate without an open file: a new version now.
                    let mut data = match self.read_content(cap) {
                        Ok(d) => d,
                        Err(e) => return reply.error(e),
                    };
                    data.resize(size as usize, 0);
                    if let Err(e) = self.set(&id, vec![("mtime".into(), AttrValue::Int(now_ms()))], Vec::new(), Some(data)) {
                        return reply.error(e);
                    }
                }
            }
        } else if let Some(t) = mtime
            && let Some((id, _)) = self.file_id(&path)
        {
            let ms = match t {
                TimeOrNow::Now => now_ms(),
                TimeOrNow::SpecificTime(t) => t.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0),
            };
            if let Err(e) = self.set(&id, vec![("mtime".into(), AttrValue::Int(ms))], Vec::new(), None) {
                return reply.error(e);
            }
        }
        match self.entry(&path) {
            Some(e) => {
                let a = self.attr(&path, &e);
                reply.attr(&TTL, &a)
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn create(&mut self, _req: &Req, parent: u64, name: &OsStr, _mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
        let (Some(dir), Ok(name)) = (self.path(parent), os(name)) else { return reply.error(libc::ENOENT) };
        let path = tree::join(&dir, name);
        if let Err(e) = self.writable_path(&path) {
            return reply.error(e);
        }
        let attrs = vec![("path".into(), AttrValue::Str(path.clone())), ("mtime".into(), AttrValue::Int(now_ms()))];
        if let Err(e) = self.create_record(attrs, Some(Vec::new())) {
            return reply.error(e);
        }
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, Handle { path: path.clone(), buf: Some(Vec::new()), dirty: false });
        match self.entry(&path) {
            Some(e) => {
                let a = self.attr(&path, &e);
                reply.created(&TTL, &a, 0, fh, 0)
            }
            None => reply.error(libc::EIO),
        }
    }

    fn mkdir(&mut self, _req: &Req, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        let (Some(dir), Ok(name)) = (self.path(parent), os(name)) else { return reply.error(libc::ENOENT) };
        let path = tree::join(&dir, name);
        if let Err(e) = self.writable_path(&path) {
            return reply.error(e);
        }
        self.refresh(false);
        if self.tree.get(&path).is_some() {
            return reply.error(libc::EEXIST);
        }
        let attrs = vec![("path".into(), AttrValue::Str(path.clone())), ("type".into(), AttrValue::Str("directory".into()))];
        if let Err(e) = self.create_record(attrs, None) {
            return reply.error(e);
        }
        let a = self.attr(&path, &Entry::Dir);
        reply.entry(&TTL, &a, 0)
    }

    fn unlink(&mut self, _req: &Req, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let (Some(dir), Ok(name)) = (self.path(parent), os(name)) else { return reply.error(libc::ENOENT) };
        let path = tree::join(&dir, name);
        self.refresh(false);
        let Some((id, _)) = self.file_id(&path) else { return reply.error(libc::ENOENT) };
        match self.call(Request::RecordDelete { ns: self.ns.clone(), id }) {
            Ok(_) => {
                self.refresh(true);
                reply.ok()
            }
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&mut self, _req: &Req, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let (Some(dir), Ok(name)) = (self.path(parent), os(name)) else { return reply.error(libc::ENOENT) };
        let path = tree::join(&dir, name);
        self.refresh(false);
        match self.tree.get(&path) {
            Some(Node::Dir { id }) => {
                if !self.tree.children(&path).is_empty() {
                    return reply.error(libc::ENOTEMPTY);
                }
                if let Some(id) = id.clone()
                    && let Err(e) = self.call(Request::RecordDelete { ns: self.ns.clone(), id })
                {
                    return reply.error(e);
                }
                self.refresh(true);
                reply.ok()
            }
            Some(_) => reply.error(libc::ENOTDIR),
            None => reply.error(libc::ENOENT),
        }
    }

    fn rename(&mut self, _req: &Req, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
        let (Some(d1), Some(d2), Ok(n1), Ok(n2)) = (self.path(parent), self.path(newparent), os(name), os(newname)) else {
            return reply.error(libc::ENOENT);
        };
        let (from, to) = (tree::join(&d1, n1), tree::join(&d2, n2));
        if let Err(e) = self.writable_path(&to) {
            return reply.error(e);
        }
        self.refresh(true);
        let moving = self.tree.records_under(&from);
        if moving.is_empty() && !matches!(self.tree.get(&from), Some(Node::Dir { .. })) {
            return reply.error(libc::ENOENT);
        }
        // Replacing a file (how editors save: write a temporary file, rename
        // it over the original). The original record stays, with its ID,
        // attributes and history; it takes the new content, and the
        // temporary record goes.
        if let Some(Node::File { id: target, .. }) = self.tree.get(&to).cloned() {
            let Some(Node::File { id: source, cap, .. }) = self.tree.get(&from).cloned() else {
                return reply.error(libc::ENOTDIR);
            };
            let data = match self.read_content(cap) {
                Ok(d) => d,
                Err(e) => return reply.error(e),
            };
            let mtime = self.records.get(&source).and_then(|r| r.attrs.iter().find(|(k, _)| k == "mtime")).map(|(_, v)| v.clone());
            let attrs = vec![("mtime".into(), mtime.unwrap_or(AttrValue::Int(now_ms())))];
            // One commit: the target takes the content, the temporary record goes.
            let steps = vec![
                TxStep::Set { id: target, attrs, unset: Vec::new(), data: Some(data) },
                TxStep::Delete { id: source },
            ];
            if let Err(e) = self.call(Request::Transaction { ns: self.ns.clone(), steps }) {
                return reply.error(e);
            }
            // The kernel now has `from`'s inode at `to`: point both at the target.
            if let Some(ino) = self.inodes.remove(&from) {
                self.paths[ino as usize] = to.clone();
                if let Some(old) = self.inodes.insert(to.clone(), ino) {
                    self.paths[old as usize] = String::new();
                }
            }
            for h in self.handles.values_mut().filter(|h| h.path == from) {
                h.path = to.clone();
            }
            self.refresh(true);
            return reply.ok();
        } else if matches!(self.tree.get(&to), Some(Node::Dir { .. })) && !self.tree.children(&to).is_empty() {
            return reply.error(libc::ENOTEMPTY);
        }
        // Every record below moves in one commit: other members never see half a move.
        let steps: Vec<TxStep> = moving
            .into_iter()
            .map(|(p, id)| TxStep::Set {
                id,
                attrs: vec![("path".into(), AttrValue::Str(format!("{to}{}", &p[from.len()..])))],
                unset: Vec::new(),
                data: None,
            })
            .collect();
        if !steps.is_empty()
            && let Err(e) = self.call(Request::Transaction { ns: self.ns.clone(), steps })
        {
            return reply.error(e);
        }
        // The kernel keeps the moved inodes: their paths follow, and a replaced
        // file's inode no longer names anything.
        let moved: Vec<(String, u64)> = self
            .inodes
            .iter()
            .filter(|(p, _)| **p == from || p.starts_with(&format!("{from}/")))
            .map(|(p, i)| (p.clone(), *i))
            .collect();
        for (p, ino) in moved {
            let new = format!("{to}{}", &p[from.len()..]);
            self.inodes.remove(&p);
            if let Some(old) = self.inodes.insert(new.clone(), ino) {
                self.paths[old as usize] = String::new();
            }
            self.paths[ino as usize] = new;
        }
        // Open handles follow the file.
        for h in self.handles.values_mut() {
            if h.path == from || h.path.starts_with(&format!("{from}/")) {
                h.path = format!("{to}{}", &h.path[from.len()..]);
            }
        }
        self.refresh(true);
        reply.ok()
    }

    fn getxattr(&mut self, _req: &Req, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
        let (Some(path), Ok(name)) = (self.path(ino), os(name)) else { return reply.error(libc::ENOENT) };
        self.refresh(false);
        let Some(key) = name.strip_prefix(XATTR_PREFIX) else { return reply.error(libc::ENODATA) };
        // Computed, not stored: whether the content is on this device (ADR-0005).
        if key == LOCAL_XATTR
            && let Some((_, cap)) = self.file_id(&path)
        {
            let v = match cap {
                None => "yes".to_string(),
                Some(cap) => match self.call(Request::Status { cap }) {
                    Ok(Response::Status(st)) => match st.total_chunks {
                        Some(t) if st.local_chunks >= t && st.missing_nodes == 0 => "yes".into(),
                        _ if st.local_chunks == 0 => "no".into(),
                        Some(t) => format!("partial ({}/{} chunks)", st.local_chunks, t),
                        None => format!("partial ({} chunks)", st.local_chunks),
                    },
                    _ => return reply.error(libc::EIO),
                },
            };
            return xattr_reply(reply, v.as_bytes(), size);
        }
        let Some(id) = self.tree.get(&path).and_then(|n| n.id()).map(str::to_string) else { return reply.error(libc::ENODATA) };
        let Some(v) = self.records.get(&id).and_then(|r| r.attrs.iter().find(|(k, _)| k == key)).map(|(_, v)| tree::format_value(v))
        else {
            return reply.error(libc::ENODATA);
        };
        xattr_reply(reply, v.as_bytes(), size)
    }

    fn listxattr(&mut self, _req: &Req, ino: u64, size: u32, reply: ReplyXattr) {
        let Some(path) = self.path(ino) else { return reply.error(libc::ENOENT) };
        self.refresh(false);
        let mut out = Vec::new();
        if self.file_id(&path).is_some() {
            out.extend_from_slice(format!("{XATTR_PREFIX}{LOCAL_XATTR}").as_bytes());
            out.push(0);
        }
        if let Some(r) = self.tree.get(&path).and_then(|n| n.id()).and_then(|id| self.records.get(id)) {
            for (k, _) in &r.attrs {
                out.extend_from_slice(XATTR_PREFIX.as_bytes());
                out.extend_from_slice(k.as_bytes());
                out.push(0);
            }
        }
        xattr_reply(reply, &out, size)
    }

    fn setxattr(&mut self, _req: &Req, ino: u64, name: &OsStr, value: &[u8], _flags: i32, _position: u32, reply: ReplyEmpty) {
        let (Some(path), Ok(name)) = (self.path(ino), os(name)) else { return reply.error(libc::ENOENT) };
        let Some(key) = name.strip_prefix(XATTR_PREFIX) else { return reply.error(libc::ENOTSUP) };
        let Ok(text) = std::str::from_utf8(value) else { return reply.error(libc::EINVAL) };
        self.refresh(false);
        let Some(id) = self.tree.get(&path).and_then(|n| n.id()).map(str::to_string) else { return reply.error(libc::EPERM) };
        let v = tree::parse_value(text);
        if key == "path" && !matches!(&v, AttrValue::Str(p) if tree::normalize(p).is_some_and(|p| !tree::is_virtual(&p))) {
            return reply.error(libc::EINVAL);
        }
        match self.set(&id, vec![(key.to_string(), v)], Vec::new(), None) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn removexattr(&mut self, _req: &Req, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        let (Some(path), Ok(name)) = (self.path(ino), os(name)) else { return reply.error(libc::ENOENT) };
        let Some(key) = name.strip_prefix(XATTR_PREFIX) else { return reply.error(libc::ENODATA) };
        self.refresh(false);
        let Some(id) = self.tree.get(&path).and_then(|n| n.id()).map(str::to_string) else { return reply.error(libc::ENODATA) };
        if !self.records.get(&id).is_some_and(|r| r.attrs.iter().any(|(k, _)| k == key)) {
            return reply.error(libc::ENODATA);
        }
        match self.set(&id, Vec::new(), vec![key.to_string()], None) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
}

fn xattr_reply(reply: ReplyXattr, data: &[u8], size: u32) {
    if size == 0 {
        reply.size(data.len() as u32)
    } else if data.len() > size as usize {
        reply.error(libc::ERANGE)
    } else {
        reply.data(data)
    }
}

