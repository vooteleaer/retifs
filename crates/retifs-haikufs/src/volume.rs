//! A mounted namespace: the file tree (`retifs-tree`) over the records the
//! local daemon serves, with inode numbers, directory listings, content
//! reads and attributes as Haiku typed attributes. Plain Rust; the C side is
//! in `ops`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use libretifs::{AttrValue, Client, RecordView, Request, Response, TxStep};
use retifs_tree::{self as tree, Node, Tree};

/// How long a listing or stat may use the tree before it is read again.
const FRESH: Duration = Duration::from_secs(5);
pub const ROOT: i64 = 1;

/// The Haiku attribute that holds a file's MIME type.
pub const MIME_ATTR: &str = "BEOS:TYPE";

pub struct Mount {
    pub ns: String,
    pub store: PathBuf,
    pub wait: Duration,
}

impl Mount {
    /// `ns=NAME [store=DIR] [wait=SECONDS]`, as given to `mount -p`.
    pub fn parse(args: &str) -> Result<Mount, String> {
        let mut ns = None;
        let mut store = None;
        let mut wait = Duration::from_secs(30);
        for part in args.split_whitespace() {
            match part.split_once('=') {
                Some(("ns", v)) => ns = Some(v.to_string()),
                Some(("store", v)) => store = Some(PathBuf::from(v)),
                Some(("wait", v)) => wait = Duration::from_secs(v.parse().map_err(|_| format!("wait={v}: seconds"))?),
                _ => return Err(format!("unknown mount parameter {part:?} (ns=NAME [store=DIR] [wait=SECONDS])")),
            }
        }
        Ok(Mount {
            ns: ns.ok_or("no ns=NAME: which namespace to mount")?,
            store: store.unwrap_or_else(libretifs::default_store_dir),
            wait,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Dir,
    File { size: u64, mtime_ms: Option<i64> },
}

/// An attribute as Haiku stores it: a type code and the bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    pub type_code: u32,
    pub data: Vec<u8>,
}

/// Why a change was refused; `ops` makes these errno values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fail {
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NotEmpty,
    /// Not a place a record can be (`/Unfiled`, `/.query`).
    NotHere,
    Invalid,
    /// retifsd said no, or isn't there (logged).
    Io,
}

/// An open file. Writes go to a write session in the daemon (started on the
/// first write, or at open with `O_TRUNC`), committed as one new version on
/// close, as the FUSE mount does.
#[derive(Debug, Default)]
pub struct Handle {
    pub session: Option<u64>,
    /// The content's size as written so far (with a session).
    pub size: u64,
    pub truncate: bool,
    /// Opened with `O_APPEND`: every write goes to the end (the file system's
    /// job on Haiku, as BFS does it).
    pub append: bool,
    pub dirty: bool,
}

/// Attributes kept by this mount only: Tracker's own (`_trk/…`, window
/// places and the like, a device's business) and any on a directory that has
/// no record. Gone on unmount.
const LOCAL_ATTR_PREFIX: &str = "_trk/";

pub struct Volume {
    rt: tokio::runtime::Runtime,
    client: Client,
    pub mount: Mount,
    tree: Tree,
    records: HashMap<String, RecordView>,
    loaded: Option<Instant>,
    inodes: HashMap<String, i64>,
    /// Inode number → path; 0 unused, 1 the root.
    paths: Vec<String>,
    local_attrs: HashMap<(i64, String), Attr>,
}

impl Volume {
    pub fn open(mount: Mount) -> Result<Volume, String> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        let client = rt
            .block_on(Client::connect(&mount.store))
            .map_err(|e| format!("can't reach retifsd at {}: {e}", mount.store.display()))?;
        let mut v = Volume {
            rt,
            client,
            mount,
            tree: Tree::default(),
            records: HashMap::new(),
            loaded: None,
            inodes: HashMap::from([("/".to_string(), ROOT)]),
            paths: vec![String::new(), "/".to_string()],
            local_attrs: HashMap::new(),
        };
        v.refresh(true)?;
        Ok(v)
    }

    fn call(&mut self, req: Request) -> Result<Response, String> {
        let answer = match self.rt.block_on(self.client.call(req.clone())) {
            Ok(r) => Ok(r),
            // retifsd restarted (an update, saved settings): the connection
            // is gone. Connect again and ask once more.
            Err(_) => match self.rt.block_on(Client::connect(&self.mount.store)) {
                Ok(c) => {
                    self.client = c;
                    self.rt.block_on(self.client.call(req))
                }
                Err(e) => Err(e),
            },
        };
        match answer {
            Ok(Response::Error { message }) => Err(message),
            Ok(r) => Ok(r),
            Err(e) => Err(format!("retifsd: {e}")),
        }
    }

    /// Reads the namespace again when the tree is older than [`FRESH`].
    pub fn refresh(&mut self, force: bool) -> Result<(), String> {
        if !force && self.loaded.is_some_and(|t| t.elapsed() < FRESH) {
            return Ok(());
        }
        match self.call(Request::Query { ns: self.mount.ns.clone(), terms: Vec::new(), at: None })? {
            Response::Records { records } => {
                self.tree = Tree::build(&records);
                self.records = records.into_iter().map(|r| (r.id.clone(), r)).collect();
                self.loaded = Some(Instant::now());
                Ok(())
            }
            _ => Err("unexpected answer to a query".into()),
        }
    }

    /// The inode number of `path`, given out on first sight and kept for the
    /// mount's life (paths are the identity, as in the FUSE mount).
    pub fn ino(&mut self, path: &str) -> i64 {
        if let Some(i) = self.inodes.get(path) {
            return *i;
        }
        let i = self.paths.len() as i64;
        self.paths.push(path.to_string());
        self.inodes.insert(path.to_string(), i);
        i
    }

    pub fn path(&self, ino: i64) -> Option<&str> {
        self.paths.get(usize::try_from(ino).ok()?).map(String::as_str).filter(|p| !p.is_empty())
    }

    pub fn kind(&mut self, ino: i64) -> Option<Kind> {
        let _ = self.refresh(false);
        let path = self.path(ino)?.to_string();
        match self.tree.get(&path)? {
            Node::Dir { .. } => Some(Kind::Dir),
            Node::File { size, mtime_ms, .. } => Some(Kind::File { size: *size, mtime_ms: *mtime_ms }),
        }
    }

    /// `name` in directory `dir`: its inode number.
    pub fn lookup(&mut self, dir: i64, name: &str) -> Option<i64> {
        let _ = self.refresh(false);
        let dir_path = self.path(dir)?.to_string();
        let p = match name {
            "." => dir_path,
            ".." => tree::parent(&dir_path).to_string(),
            _ => tree::join(&dir_path, name),
        };
        self.tree.get(&p)?;
        Some(self.ino(&p))
    }

    /// A directory's entries, `.` and `..` first: (name, inode number).
    pub fn list(&mut self, dir: i64) -> Option<Vec<(String, i64)>> {
        let _ = self.refresh(false);
        let path = self.path(dir)?.to_string();
        if !matches!(self.tree.get(&path)?, Node::Dir { .. }) {
            return None;
        }
        let parent = tree::parent(&path).to_string();
        let mut out = vec![(".".to_string(), dir), ("..".to_string(), self.ino(&parent))];
        for (name, child) in self.tree.children(&path) {
            let i = self.ino(&child);
            out.push((name, i));
        }
        Some(out)
    }

    /// Part of a file's content, fetched from peers if it isn't here yet; of
    /// a file being written, as it would be committed now.
    pub fn read(&mut self, ino: i64, handle: Option<&Handle>, offset: u64, len: u64) -> Result<Vec<u8>, String> {
        if let Some(session) = handle.and_then(|h| h.session) {
            return match self.call(Request::WriteRead { session, offset, len })? {
                Response::Range { data } => Ok(data),
                _ => Err("unexpected answer to a read".into()),
            };
        }
        let path = self.path(ino).ok_or("no such node")?.to_string();
        let cap = match self.tree.get(&path) {
            Some(Node::File { cap: Some(cap), .. }) => cap.clone(),
            Some(Node::File { cap: None, .. }) => return Ok(Vec::new()),
            _ => return Err("not a file".into()),
        };
        let req = Request::ReadRange { cap, ns: Some(self.mount.ns.clone()), offset, len, wait_ms: self.mount.wait.as_millis() as u64 };
        match self.call(req)? {
            Response::Range { data } => Ok(data),
            _ => Err("unexpected answer to a read".into()),
        }
    }

    fn record(&self, ino: i64) -> Option<&RecordView> {
        let id = self.tree.get(self.path(ino)?)?.id()?;
        self.records.get(id)
    }

    /// The node's attribute names: the record's attributes, `BEOS:TYPE` when
    /// its `type` is a MIME type (Tracker shows files by it), People's
    /// `META:` ones on a contact, and the ones this mount keeps.
    pub fn attr_names(&mut self, ino: i64) -> Vec<String> {
        let _ = self.refresh(false);
        let mut names: Vec<String> = Vec::new();
        if let Some(r) = self.record(ino) {
            names.extend(r.attrs.iter().map(|(k, _)| k.clone()));
            if mime(r).is_some() {
                names.push(MIME_ATTR.to_string());
            }
            if is_person(r) {
                names.extend(crate::person::shown(|k| has(r, k)).into_iter().map(|(a, _)| a.to_string()));
            }
        }
        names.extend(self.local_attrs.keys().filter(|(i, _)| *i == ino).map(|(_, n)| n.clone()));
        names
    }

    pub fn attr(&mut self, ino: i64, name: &str) -> Option<Attr> {
        let _ = self.refresh(false);
        if let Some(a) = self.local_attrs.get(&(ino, name.to_string())) {
            return Some(a.clone());
        }
        let r = self.record(ino)?;
        if name == MIME_ATTR {
            let m = mime(r)?;
            return Some(Attr { type_code: crate::types::B_MIME_STRING_TYPE, data: c_string(m) });
        }
        let key = if is_person(r) { crate::person::key_for(name, |k| has(r, k)).unwrap_or(name) } else { name };
        let (_, v) = r.attrs.iter().find(|(k, _)| k == key)?;
        Some(haiku_attr(v))
    }
}

/// Changes: files, directories, contents and attributes, each one commit
/// (a move of a directory with all below it too, as in the FUSE mount).
impl Volume {
    fn act(&mut self, req: Request) -> Result<Response, Fail> {
        self.call(req).map_err(|e| {
            crate::log(&format!("retifsd: {e}"));
            Fail::Io
        })
    }

    fn file_id(&self, ino: i64) -> Option<(String, Option<String>)> {
        match self.tree.get(self.path(ino)?)? {
            Node::File { id, cap, .. } => Some((id.clone(), cap.clone())),
            Node::Dir { .. } => None,
        }
    }

    fn create_record(&mut self, attrs: Vec<(String, AttrValue)>, data: Option<Vec<u8>>) -> Result<String, Fail> {
        match self.act(Request::RecordCreate { ns: self.mount.ns.clone(), attrs, data })? {
            Response::Records { records } if !records.is_empty() => {
                self.refresh(true).map_err(|_| Fail::Io)?;
                Ok(records[0].id.clone())
            }
            _ => Err(Fail::Io),
        }
    }

    fn set(&mut self, id: &str, attrs: Vec<(String, AttrValue)>, unset: Vec<String>) -> Result<(), Fail> {
        self.act(Request::RecordSet { ns: self.mount.ns.clone(), id: id.to_string(), attrs, unset, data: None })?;
        self.refresh(true).map_err(|_| Fail::Io)
    }

    /// Where a new entry `name` in `dir` would be, if it can be there.
    fn new_path(&mut self, dir: i64, name: &str) -> Result<String, Fail> {
        let dir = self.path(dir).ok_or(Fail::NotFound)?.to_string();
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(Fail::Invalid);
        }
        let p = tree::join(&dir, name);
        if tree::is_virtual(&p) {
            return Err(Fail::NotHere);
        }
        Ok(p)
    }

    /// A new, empty file `name` in `dir`: its inode number.
    pub fn create(&mut self, dir: i64, name: &str) -> Result<i64, Fail> {
        let p = self.new_path(dir, name)?;
        self.refresh(true).map_err(|_| Fail::Io)?;
        if self.tree.get(&p).is_some() {
            return Err(Fail::Exists);
        }
        let attrs = vec![("path".into(), AttrValue::Str(p.clone())), ("mtime".into(), AttrValue::Int(now_ms()))];
        self.create_record(attrs, Some(Vec::new()))?;
        Ok(self.ino(&p))
    }

    pub fn mkdir(&mut self, dir: i64, name: &str) -> Result<i64, Fail> {
        let p = self.new_path(dir, name)?;
        self.refresh(true).map_err(|_| Fail::Io)?;
        if self.tree.get(&p).is_some() {
            return Err(Fail::Exists);
        }
        let attrs = vec![("path".into(), AttrValue::Str(p.clone())), ("type".into(), AttrValue::Str(libretifs::types::DIRECTORY.into()))];
        self.create_record(attrs, None)?;
        Ok(self.ino(&p))
    }

    /// Deletes file `name` in `dir`: the inode number it had.
    pub fn unlink(&mut self, dir: i64, name: &str) -> Result<i64, Fail> {
        let p = tree::join(self.path(dir).ok_or(Fail::NotFound)?, name);
        self.refresh(true).map_err(|_| Fail::Io)?;
        let id = match self.tree.get(&p) {
            Some(Node::File { id, .. }) => id.clone(),
            Some(Node::Dir { .. }) => return Err(Fail::IsDir),
            None => return Err(Fail::NotFound),
        };
        self.act(Request::RecordDelete { ns: self.mount.ns.clone(), id })?;
        self.refresh(true).map_err(|_| Fail::Io)?;
        Ok(self.ino(&p))
    }

    pub fn rmdir(&mut self, dir: i64, name: &str) -> Result<i64, Fail> {
        let p = tree::join(self.path(dir).ok_or(Fail::NotFound)?, name);
        self.refresh(true).map_err(|_| Fail::Io)?;
        match self.tree.get(&p) {
            Some(Node::Dir { id }) => {
                let id = id.clone();
                if !self.tree.children(&p).is_empty() {
                    return Err(Fail::NotEmpty);
                }
                if tree::is_virtual(&p) {
                    return Err(Fail::NotHere);
                }
                if let Some(id) = id {
                    self.act(Request::RecordDelete { ns: self.mount.ns.clone(), id })?;
                }
                self.refresh(true).map_err(|_| Fail::Io)?;
                Ok(self.ino(&p))
            }
            Some(_) => Err(Fail::NotDir),
            None => Err(Fail::NotFound),
        }
    }

    /// Moves `from_name` in `from_dir` to `to_name` in `to_dir`: the moved
    /// node's inode number, and the replaced one's if a file was replaced.
    /// Replacing a file (how editors save) keeps the original record, its ID,
    /// attributes and history: it takes the new content, the other goes.
    pub fn rename(&mut self, from_dir: i64, from_name: &str, to_dir: i64, to_name: &str) -> Result<(i64, Option<i64>), Fail> {
        let from = tree::join(self.path(from_dir).ok_or(Fail::NotFound)?, from_name);
        let to = self.new_path(to_dir, to_name)?;
        if tree::is_virtual(&from) {
            return Err(Fail::NotHere);
        }
        if from == to {
            return Ok((self.ino(&from), None));
        }
        if to.starts_with(&format!("{from}/")) {
            return Err(Fail::Invalid);
        }
        self.refresh(true).map_err(|_| Fail::Io)?;
        let moving = self.tree.records_under(&from);
        if moving.is_empty() && !matches!(self.tree.get(&from), Some(Node::Dir { .. })) {
            return Err(Fail::NotFound);
        }
        let mut replaced = None;
        if let Some(Node::File { id: target, .. }) = self.tree.get(&to).cloned() {
            let Some(Node::File { id: source, cap, .. }) = self.tree.get(&from).cloned() else { return Err(Fail::IsDir) };
            let mtime = self.records.get(&source).and_then(|r| r.attrs.iter().find(|(k, _)| k == "mtime")).map(|(_, v)| v.clone());
            let (data, blocks) = match cap {
                Some(cap) => (None, Some(vec![cap])),
                None => (Some(Vec::new()), None),
            };
            let steps = vec![
                TxStep::Set { id: target, attrs: vec![("mtime".into(), mtime.unwrap_or(AttrValue::Int(now_ms())))], unset: Vec::new(), data, blocks },
                TxStep::Delete { id: source },
            ];
            self.act(Request::Transaction { ns: self.mount.ns.clone(), steps })?;
            replaced = self.inodes.get(&to).copied();
        } else {
            match self.tree.get(&to) {
                Some(Node::Dir { .. }) if !self.tree.children(&to).is_empty() => return Err(Fail::NotEmpty),
                Some(Node::Dir { .. }) if matches!(self.tree.get(&from), Some(Node::File { .. })) => return Err(Fail::IsDir),
                _ => {}
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
            if !steps.is_empty() {
                self.act(Request::Transaction { ns: self.mount.ns.clone(), steps })?;
            }
        }
        // The kernel keeps the moved inodes: their paths follow; a replaced
        // file's inode no longer names anything.
        let moved: Vec<(String, i64)> =
            self.inodes.iter().filter(|(p, _)| **p == from || p.starts_with(&format!("{from}/"))).map(|(p, i)| (p.clone(), *i)).collect();
        for (p, ino) in moved {
            let new = format!("{to}{}", &p[from.len()..]);
            self.inodes.remove(&p);
            if let Some(old) = self.inodes.insert(new.clone(), ino) {
                self.paths[old as usize] = String::new();
            }
            self.paths[ino as usize] = new;
        }
        self.refresh(true).map_err(|_| Fail::Io)?;
        Ok((self.ino(&to), replaced))
    }

    /// Whether the record has content (a contact, all attributes, has none).
    pub fn has_content(&self, ino: i64) -> bool {
        self.file_id(ino).is_some_and(|(_, cap)| cap.is_some())
    }

    /// The handle's write session, started on first need: from the file's
    /// content, or empty if it was opened with `O_TRUNC`.
    pub fn session(&mut self, ino: i64, h: &mut Handle) -> Result<u64, Fail> {
        if let Some(s) = h.session {
            return Ok(s);
        }
        let _ = self.refresh(false);
        let (id, _) = self.file_id(ino).ok_or(Fail::NotFound)?;
        match self.act(Request::WriteBegin { ns: self.mount.ns.clone(), id, truncate: h.truncate })? {
            Response::Session { session, size } => {
                h.session = Some(session);
                h.size = size;
                Ok(session)
            }
            _ => Err(Fail::Io),
        }
    }

    /// Straight to the daemon's spool: nothing of the file is kept here.
    pub fn write(&mut self, ino: i64, h: &mut Handle, offset: u64, data: &[u8]) -> Result<(), Fail> {
        let session = self.session(ino, h)?;
        let offset = if h.append { h.size } else { offset };
        self.act(Request::WriteAt { session, offset, data: data.to_vec() })?;
        h.size = h.size.max(offset + data.len() as u64);
        h.dirty = true;
        Ok(())
    }

    pub fn truncate(&mut self, ino: i64, h: &mut Handle, size: u64) -> Result<(), Fail> {
        let session = self.session(ino, h)?;
        self.act(Request::WriteTruncate { session, size })?;
        h.size = size;
        h.dirty = true;
        Ok(())
    }

    /// Commits a handle's writes as the record's new content (one version).
    pub fn commit(&mut self, ino: i64, h: &mut Handle) -> Result<(), Fail> {
        if !h.dirty {
            return Ok(());
        }
        // Opened with O_TRUNC and never written: commit the empty content.
        self.session(ino, h)?;
        let session = h.session.take().ok_or(Fail::Io)?;
        h.dirty = false;
        h.truncate = false;
        self.act(Request::WriteCommit { session, attrs: vec![("mtime".into(), AttrValue::Int(now_ms()))] })?;
        self.refresh(true).map_err(|_| Fail::Io)
    }

    /// Drops a handle's uncommitted writes.
    pub fn abort(&mut self, h: &mut Handle) {
        if let Some(session) = h.session.take() {
            let _ = self.act(Request::WriteAbort { session });
        }
    }

    pub fn set_mtime(&mut self, ino: i64, ms: i64) -> Result<(), Fail> {
        let (id, _) = self.file_id(ino).ok_or(Fail::NotFound)?;
        self.set(&id, vec![("mtime".into(), AttrValue::Int(ms))], Vec::new())
    }

    /// Writes attribute `name`: into the record (People's `META:` ones into
    /// the keys they show, `BEOS:TYPE` as its `type`), or kept by this mount
    /// (Tracker's own; any on a directory without a record). Whether it is
    /// new.
    pub fn set_attr(&mut self, ino: i64, name: &str, a: Attr) -> Result<bool, Fail> {
        let _ = self.refresh(false);
        let record = self.record(ino).map(|r| (r.id.clone(), is_person(r), r.attrs.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>()));
        let Some((id, person, keys)) = record.filter(|_| !name.starts_with(LOCAL_ATTR_PREFIX)) else {
            return Ok(self.local_attrs.insert((ino, name.to_string()), a).is_none());
        };
        let (key, value) = if name == MIME_ATTR {
            let t = from_haiku(&a);
            if !matches!(&t, AttrValue::Str(s) if s.contains('/')) {
                return Err(Fail::Invalid);
            }
            ("type".to_string(), t)
        } else {
            let key = if person { crate::person::key_for(name, |k| keys.iter().any(|h| h == k)).unwrap_or(name) } else { name };
            (key.to_string(), from_haiku(&a))
        };
        if key == "path" && !matches!(&value, AttrValue::Str(p) if tree::normalize(p).is_some_and(|p| !tree::is_virtual(&p))) {
            return Err(Fail::Invalid);
        }
        let new = !keys.contains(&key);
        // An empty string from People is a field cleared.
        if matches!(&value, AttrValue::Str(s) if s.is_empty()) && key != "type" {
            if new {
                return Ok(false);
            }
            self.set(&id, Vec::new(), vec![key])?;
        } else {
            self.set(&id, vec![(key, value)], Vec::new())?;
        }
        Ok(new)
    }

    pub fn remove_attr(&mut self, ino: i64, name: &str) -> Result<(), Fail> {
        if self.local_attrs.remove(&(ino, name.to_string())).is_some() {
            return Ok(());
        }
        let _ = self.refresh(false);
        let r = self.record(ino).ok_or(Fail::NotFound)?;
        let key = if name == MIME_ATTR {
            "type"
        } else if is_person(r) {
            crate::person::key_for(name, |k| has(r, k)).unwrap_or(name)
        } else {
            name
        };
        if !has(r, key) {
            return Err(Fail::NotFound);
        }
        let (id, key) = (r.id.clone(), key.to_string());
        self.set(&id, Vec::new(), vec![key])
    }

    /// The directory an inode is in (for change notices).
    pub fn parent_ino(&mut self, ino: i64) -> i64 {
        let p = self.path(ino).map(|p| tree::parent(p).to_string()).unwrap_or_else(|| "/".into());
        self.ino(&p)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn has(r: &RecordView, key: &str) -> bool {
    r.attrs.iter().any(|(k, _)| k == key)
}

/// A contact (ADR-0025): People's attributes show on it.
fn is_person(r: &RecordView) -> bool {
    matches!(r.attrs.iter().find(|(k, _)| k == "type").map(|(_, v)| v), Some(AttrValue::Str(t)) if libretifs::types::is(t, libretifs::types::PERSON))
}

/// A Haiku attribute as a retifs value: strings (without the terminating
/// NUL), integers, floats and booleans as themselves, anything else as bytes.
pub fn from_haiku(a: &Attr) -> AttrValue {
    use crate::types::*;
    let d = &a.data;
    match a.type_code {
        B_STRING_TYPE | B_MIME_STRING_TYPE => {
            let end = d.iter().position(|b| *b == 0).unwrap_or(d.len());
            AttrValue::Str(String::from_utf8_lossy(&d[..end]).into_owned())
        }
        B_INT64_TYPE | B_TIME_TYPE if d.len() == 8 => AttrValue::Int(i64::from_ne_bytes(d[..8].try_into().unwrap())),
        B_UINT64_TYPE if d.len() == 8 => AttrValue::Int(u64::from_ne_bytes(d[..8].try_into().unwrap()) as i64),
        B_INT32_TYPE if d.len() == 4 => AttrValue::Int(i32::from_ne_bytes(d[..4].try_into().unwrap()) as i64),
        B_UINT32_TYPE if d.len() == 4 => AttrValue::Int(u32::from_ne_bytes(d[..4].try_into().unwrap()) as i64),
        B_INT16_TYPE if d.len() == 2 => AttrValue::Int(i16::from_ne_bytes(d[..2].try_into().unwrap()) as i64),
        B_DOUBLE_TYPE if d.len() == 8 => AttrValue::Float(f64::from_ne_bytes(d[..8].try_into().unwrap())),
        B_FLOAT_TYPE if d.len() == 4 => AttrValue::Float(f32::from_ne_bytes(d[..4].try_into().unwrap()) as f64),
        B_BOOL_TYPE if d.len() == 1 => AttrValue::Bool(d[0] != 0),
        _ => AttrValue::Bytes(d.clone()),
    }
}

/// A query's match: the node, its directory and its name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hit {
    pub dir: i64,
    pub ino: i64,
    pub name: String,
}

/// A node as a query sees it: Haiku's own attributes and the record's.
struct NodeView<'a> {
    name: &'a str,
    kind: &'a Node,
    record: Option<&'a RecordView>,
}

impl crate::query::Subject for NodeView<'_> {
    fn get(&self, attr: &str) -> Option<AttrValue> {
        match attr {
            "name" => Some(AttrValue::Str(self.name.to_string())),
            "size" => match self.kind {
                Node::File { size, .. } => Some(AttrValue::Int(*size as i64)),
                Node::Dir { .. } => Some(AttrValue::Int(0)),
            },
            "last_modified" => match self.kind {
                Node::File { mtime_ms: Some(ms), .. } => Some(AttrValue::Int(ms.div_euclid(1000))),
                _ => None,
            },
            MIME_ATTR => self.record.and_then(mime).map(|m| AttrValue::Str(m.to_string())),
            k => self.record?.attrs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()),
        }
    }
}

impl Volume {
    /// The nodes matching a Haiku query. Its exact string parts go to
    /// retifsd as terms first, so a library held only in part answers from
    /// its index; records found that way join the tree.
    pub fn query(&mut self, expr: &crate::query::Expr) -> Result<Vec<Hit>, String> {
        let terms = crate::query::pushdown(expr);
        let candidates: Option<std::collections::HashSet<String>> = if terms.is_empty() {
            self.refresh(false)?;
            None
        } else {
            let found = match self.call(Request::Query { ns: self.mount.ns.clone(), terms, at: None })? {
                Response::Records { records } => records,
                _ => return Err("unexpected answer to a query".into()),
            };
            let ids = found.iter().map(|r| r.id.clone()).collect();
            let mut new = false;
            for r in found {
                new |= !self.records.contains_key(&r.id);
                self.records.insert(r.id.clone(), r);
            }
            if new {
                let all: Vec<RecordView> = self.records.values().cloned().collect();
                self.tree = Tree::build(&all);
            }
            Some(ids)
        };
        let mut hits = Vec::new();
        let matched: Vec<String> = self
            .tree
            .nodes
            .iter()
            .filter(|(p, _)| !matches!(p.as_str(), "/" | tree::QUERY_DIR | tree::RECORDS_DIR))
            .filter(|(_, n)| candidates.as_ref().is_none_or(|c| n.id().is_some_and(|id| c.contains(id))))
            .filter(|(p, n)| {
                let view = NodeView { name: tree::name(p), kind: n, record: n.id().and_then(|id| self.records.get(id)) };
                expr.matches(&view)
            })
            .map(|(p, _)| p.clone())
            .collect();
        for p in matched {
            let dir = self.ino(tree::parent(&p));
            let ino = self.ino(&p);
            hits.push(Hit { dir, ino, name: tree::name(&p).to_string() });
        }
        Ok(hits)
    }

    /// The tree as it is now: every path and its node (to compare with the
    /// next, and tell Tracker what came, went and changed).
    pub fn snapshot(&self) -> std::collections::BTreeMap<String, Node> {
        self.tree.nodes.clone()
    }

    /// The namespace's size: its files' sizes together. Reported as the
    /// volume's capacity (Tracker offers only volumes with one for Find).
    pub fn total_bytes(&mut self) -> u64 {
        let _ = self.refresh(false);
        self.tree.nodes.values().map(|n| if let Node::File { size, .. } = n { *size } else { 0 }).sum()
    }

    /// The volume's indexes as `lsindex` lists them: Haiku's own and every
    /// attribute key in the namespace, typed by its first value seen. retifs
    /// answers any attribute; these say which ones exist.
    pub fn indexes(&mut self) -> Vec<(String, u32)> {
        use crate::types::*;
        let _ = self.refresh(false);
        let mut out = vec![
            ("name".to_string(), B_STRING_TYPE),
            ("size".to_string(), B_INT64_TYPE),
            ("last_modified".to_string(), B_INT64_TYPE),
            (MIME_ATTR.to_string(), B_STRING_TYPE),
        ];
        let mut seen: std::collections::BTreeMap<&str, u32> = Default::default();
        for r in self.records.values() {
            for (k, v) in &r.attrs {
                seen.entry(k.as_str()).or_insert_with(|| haiku_attr(v).type_code);
            }
        }
        out.extend(seen.into_iter().filter(|(k, _)| !out.iter().any(|(o, _)| o == k)).map(|(k, t)| (k.to_string(), t)).collect::<Vec<_>>());
        out
    }
}

/// The record's `type`, if it is a MIME type (`application/x-vnd.…`).
fn mime(r: &RecordView) -> Option<&str> {
    match r.attrs.iter().find(|(k, _)| k == "type").map(|(_, v)| v) {
        Some(AttrValue::Str(t)) if t.contains('/') && !t.contains(char::is_whitespace) => Some(t),
        _ => None,
    }
}

fn c_string(s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    b
}

/// A retifs value as a Haiku attribute: strings as `B_STRING_TYPE` (with the
/// terminating NUL, as Haiku stores them), integers as `B_INT64_TYPE`,
/// floats as `B_DOUBLE_TYPE`, booleans as `B_BOOL_TYPE`, bytes as
/// `B_RAW_TYPE`, anything else as its text form.
pub fn haiku_attr(v: &AttrValue) -> Attr {
    use crate::types::*;
    match v {
        AttrValue::Str(s) => Attr { type_code: B_STRING_TYPE, data: c_string(s) },
        AttrValue::Int(i) => Attr { type_code: B_INT64_TYPE, data: i.to_ne_bytes().to_vec() },
        AttrValue::Float(f) => Attr { type_code: B_DOUBLE_TYPE, data: f.to_ne_bytes().to_vec() },
        AttrValue::Bool(b) => Attr { type_code: B_BOOL_TYPE, data: vec![*b as u8] },
        AttrValue::Bytes(b) => Attr { type_code: B_RAW_TYPE, data: b.clone() },
        other => Attr { type_code: B_STRING_TYPE, data: c_string(&tree::format_value(other)) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_parameters() {
        let m = Mount::parse("ns=family store=/boot/home/rstore wait=5").unwrap();
        assert_eq!((m.ns.as_str(), m.store, m.wait), ("family", PathBuf::from("/boot/home/rstore"), Duration::from_secs(5)));
        assert!(Mount::parse("store=/x").is_err());
        assert!(Mount::parse("ns=a bogus").is_err());
    }

    #[test]
    fn values_as_haiku_attributes() {
        let s = haiku_attr(&AttrValue::Str("Tartu".into()));
        assert_eq!((s.type_code, s.data), (crate::types::B_STRING_TYPE, b"Tartu\0".to_vec()));
        let i = haiku_attr(&AttrValue::Int(42));
        assert_eq!((i.type_code, i.data), (crate::types::B_INT64_TYPE, 42i64.to_ne_bytes().to_vec()));
        let l = haiku_attr(&AttrValue::List(vec![AttrValue::Int(1), AttrValue::Str("a".into())]));
        assert_eq!((l.type_code, l.data), (crate::types::B_STRING_TYPE, b"[1, \"a\"]\0".to_vec()));
    }

    #[test]
    fn haiku_attributes_as_values() {
        use crate::types::*;
        // Strings round-trip; what Haiku keeps after the NUL is dropped.
        for v in [AttrValue::Str("Mari".into()), AttrValue::Int(-7), AttrValue::Float(1.5), AttrValue::Bool(true)] {
            assert_eq!(from_haiku(&haiku_attr(&v)), v);
        }
        assert_eq!(from_haiku(&Attr { type_code: B_STRING_TYPE, data: b"Tartu\0junk".to_vec() }), AttrValue::Str("Tartu".into()));
        assert_eq!(from_haiku(&Attr { type_code: B_INT32_TYPE, data: 5i32.to_ne_bytes().to_vec() }), AttrValue::Int(5));
        // An icon or anything else: its bytes.
        let icon = Attr { type_code: 0x5649_434e, data: vec![1, 2, 3] };
        assert_eq!(from_haiku(&icon), AttrValue::Bytes(vec![1, 2, 3]));
    }
}
