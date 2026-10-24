//! The FUSE frontend (ADR-0002): translates file operations into the local
//! record API (ADR-0004). It holds no keys and no store; `retifsd` does.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
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
/// Without a change notice, the namespace is re-read at least this often.
const RESYNC: Duration = Duration::from_secs(30);
/// `user.retifs.local`: computed, whether a file's content is on this device.
const LOCAL_XATTR: &str = "local";

enum Entry {
    Dir,
    File { size: u64, mtime_ms: Option<i64> },
    Link(String),
}

struct Handle {
    path: String,
    /// The daemon's write session once this handle writes (or truncates):
    /// written ranges are spooled there, never held whole here.
    session: Option<u64>,
    /// The content's size as written so far (with a session).
    size: u64,
    /// Opened with O_TRUNC: the session starts from empty content.
    truncate: bool,
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
    queries: HashMap<String, (Instant, Vec<(String, String)>)>,
    uid: u32,
    gid: u32,
    started: SystemTime,
    /// How long a read may wait for content that isn't here yet.
    wait: Duration,
    /// Set by the watcher thread when the namespace changed.
    changed: Arc<AtomicBool>,
}

/// `via`: the namespace is on another of the user's nodes; every request
/// goes there over a Link (ADR-0019).
pub fn mount(store: &Path, ns: &str, mountpoint: &Path, wait: Duration, via: Option<String>) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    let client = rt.block_on(Client::connect(store)).map_err(|e| format!("can't reach retifsd at {}: {e}", store.display()))?.via(via.clone());
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
        queries: HashMap::new(),
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        started: SystemTime::now(),
        wait,
        changed: watch(store, ns, via),
    };
    let opts = [MountOption::FSName(format!("retifs:{ns}")), MountOption::Subtype("retifs".into()), MountOption::DefaultPermissions];
    fuser::mount2(fs, mountpoint, &opts).map_err(|e| e.to_string())
}

/// Watches namespace `ns` on a thread of its own (a long poll on the local
/// API) and raises the flag on every change, so the mount re-reads it only
/// when something changed: a local write, or another member's merged in.
fn watch(store: &Path, ns: &str, via: Option<String>) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(true));
    let (store, ns, out) = (store.to_path_buf(), ns.to_string(), flag.clone());
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
        let mut since = 0;
        loop {
            let Ok(client) = rt.block_on(Client::connect(&store)) else {
                std::thread::sleep(Duration::from_secs(5)); // the daemon restarting
                continue;
            };
            let mut client = client.via(via.clone());
            // Until the connection fails (then reconnect).
            while let Ok(Response::Changed { count }) = rt.block_on(client.call(Request::Watch { ns: ns.clone(), since, timeout_ms: 30_000 })) {
                if count != since {
                    since = count;
                    out.store(true, Ordering::Release);
                }
            }
            out.store(true, Ordering::Release);
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    flag
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
    /// Re-reads the namespace if it changed (the watcher says so), if `force`,
    /// or at the latest every RESYNC in case the watcher missed something.
    fn refresh(&mut self, force: bool) {
        let changed = self.changed.swap(false, Ordering::AcqRel);
        if !force && !changed && self.loaded.is_some_and(|t| t.elapsed() < RESYNC) {
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
                    let open = self.handles.values().find(|h| h.path == path && h.session.is_some());
                    Entry::File { size: open.map_or(*size, |h| h.size), mtime_ms: *mtime_ms }
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

    /// The handle's write session, started on first need: from the file's
    /// current content, or empty if it was opened with O_TRUNC.
    fn session(&mut self, fh: u64) -> Result<u64, i32> {
        let h = self.handles.get(&fh).ok_or(libc::EBADF)?;
        if let Some(s) = h.session {
            return Ok(s);
        }
        let (path, truncate) = (h.path.clone(), h.truncate);
        self.refresh(false);
        let (id, _) = self.file_id(&path).ok_or(libc::ENOENT)?;
        match self.call(Request::WriteBegin { ns: self.ns.clone(), id, truncate })? {
            Response::Session { session, size } => {
                let h = self.handles.get_mut(&fh).ok_or(libc::EBADF)?;
                h.session = Some(session);
                h.size = size;
                Ok(session)
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

    /// Commits a handle's writes as the record's new content (one version).
    fn write_back(&mut self, fh: u64) -> Result<(), i32> {
        let Some(h) = self.handles.get_mut(&fh) else { return Ok(()) };
        if !h.dirty {
            return Ok(());
        }
        if h.session.is_none() {
            // Opened with O_TRUNC and never written: commit the empty content.
            self.session(fh)?;
        }
        let h = self.handles.get_mut(&fh).ok_or(libc::EBADF)?;
        let session = h.session.take().ok_or(libc::EIO)?;
        h.dirty = false;
        h.truncate = false;
        self.call(Request::WriteCommit { session, attrs: vec![("mtime".into(), AttrValue::Int(now_ms()))] })?;
        self.refresh(true);
        Ok(())
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
        self.handles.insert(fh, Handle { path, session: None, size: 0, truncate, dirty: truncate });
        if truncate && let Err(e) = self.session(fh) {
            self.handles.remove(&fh);
            return reply.error(e);
        }
        reply.opened(fh, 0)
    }

    fn read(&mut self, _req: &Req, _ino: u64, fh: u64, offset: i64, size: u32, _flags: i32, _lock: Option<u64>, reply: ReplyData) {
        let Some(h) = self.handles.get(&fh) else { return reply.error(libc::EBADF) };
        if let Some(session) = h.session {
            // Being written: the content as it would be committed now.
            return match self.call(Request::WriteRead { session, offset: offset.max(0) as u64, len: size as u64 }) {
                Ok(Response::Range { data }) => reply.data(&data),
                Ok(_) => reply.error(libc::EIO),
                Err(e) => reply.error(e),
            };
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
        // Straight to the daemon's spool: nothing of the file is kept here.
        let session = match self.session(fh) {
            Ok(s) => s,
            Err(e) => return reply.error(e),
        };
        let offset = offset.max(0) as u64;
        if let Err(e) = self.call(Request::WriteAt { session, offset, data: data.to_vec() }) {
            return reply.error(e);
        }
        let h = self.handles.get_mut(&fh).unwrap();
        h.size = h.size.max(offset + data.len() as u64);
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
        if let Some(Handle { session: Some(session), .. }) = self.handles.remove(&fh) {
            let _ = self.call(Request::WriteAbort { session });
        }
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
            if self.file_id(&path).is_none() {
                return reply.error(libc::EISDIR);
            }
            // On the open file's session, or (truncate without an open file) a
            // session of its own, committed at once as a new version.
            let (f, own) = match fh.filter(|f| self.handles.contains_key(f)) {
                Some(f) => (f, false),
                None => {
                    let f = self.next_fh;
                    self.next_fh += 1;
                    self.handles.insert(f, Handle { path: path.clone(), session: None, size: 0, truncate: false, dirty: false });
                    (f, true)
                }
            };
            let result = self.session(f).and_then(|session| self.call(Request::WriteTruncate { session, size }).map(|_| ()));
            if let Some(h) = self.handles.get_mut(&f) {
                h.size = size;
                h.dirty = true;
            }
            let result = if own { result.and_then(|()| self.write_back(f)) } else { result };
            if own {
                self.handles.remove(&f);
            }
            if let Err(e) = result {
                return reply.error(e);
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
        self.handles.insert(fh, Handle { path: path.clone(), session: None, size: 0, truncate: false, dirty: false });
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
        let attrs = vec![("path".into(), AttrValue::Str(path.clone())), ("type".into(), AttrValue::Str(libretifs::types::DIRECTORY.into()))];
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
            let mtime = self.records.get(&source).and_then(|r| r.attrs.iter().find(|(k, _)| k == "mtime")).map(|(_, v)| v.clone());
            let attrs = vec![("mtime".into(), mtime.unwrap_or(AttrValue::Int(now_ms())))];
            // One commit: the target takes the content (by reference, nothing
            // copied), the temporary record goes.
            let (data, blocks) = match cap {
                Some(cap) => (None, Some(vec![cap])),
                None => (Some(Vec::new()), None),
            };
            let steps = vec![
                TxStep::Set { id: target, attrs, unset: Vec::new(), data, blocks },
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
                blocks: None,
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

