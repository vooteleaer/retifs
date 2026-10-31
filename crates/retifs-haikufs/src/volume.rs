//! A mounted namespace: the file tree (`retifs-tree`) over the records the
//! local daemon serves, with inode numbers, directory listings, content
//! reads and attributes as Haiku typed attributes. Plain Rust; the C side is
//! in `ops`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use libretifs::{AttrValue, Client, RecordView, Request, Response};
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
pub struct Attr {
    pub type_code: u32,
    pub data: Vec<u8>,
}

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
        };
        v.refresh(true)?;
        Ok(v)
    }

    fn call(&mut self, req: Request) -> Result<Response, String> {
        match self.rt.block_on(self.client.call(req)) {
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

    /// Part of a file's content, fetched from peers if it isn't here yet.
    pub fn read(&mut self, ino: i64, offset: u64, len: u64) -> Result<Vec<u8>, String> {
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

    /// The node's attribute names: the record's attributes, and `BEOS:TYPE`
    /// when its `type` is a MIME type (Tracker shows files by it).
    pub fn attr_names(&mut self, ino: i64) -> Vec<String> {
        let _ = self.refresh(false);
        let Some(r) = self.record(ino) else { return Vec::new() };
        let mut names: Vec<String> = r.attrs.iter().map(|(k, _)| k.clone()).collect();
        if mime(r).is_some() {
            names.push(MIME_ATTR.to_string());
        }
        names
    }

    pub fn attr(&mut self, ino: i64, name: &str) -> Option<Attr> {
        let _ = self.refresh(false);
        let r = self.record(ino)?;
        if name == MIME_ATTR {
            let m = mime(r)?;
            return Some(Attr { type_code: crate::types::B_MIME_STRING_TYPE, data: c_string(m) });
        }
        let (_, v) = r.attrs.iter().find(|(k, _)| k == name)?;
        Some(haiku_attr(v))
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
}
