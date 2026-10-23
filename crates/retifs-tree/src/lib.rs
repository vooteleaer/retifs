//! The file-tree view of a namespace (ADR-0002): which record sits at which
//! path, and how attribute values read and write as text (xattrs). Shared by
//! the FUSE mount and the Windows Cloud Files provider; builds everywhere.
//!
//! - A record with a `path` attribute (`/a/b.txt`) is the file at that path;
//!   its content block is the file's content.
//! - A record with `type = directory` and a path is a directory (so empty
//!   directories exist); other directories are implied by paths below them.
//! - Records without a path (put there by an app, a phone, the CLI) are
//!   under `/Unfiled/<name>` (their ID if they have no name), except retifs' own
//!   (`type` `retifs.*` or `keep-rule`: shares, index settings, keep rules),
//!   which aren't files.
//! - Two records claiming one path: the later ID gets `~<first 8 of its ID>`.

use std::collections::BTreeMap;

use libretifs::{AttrValue, RecordView};

pub const RECORDS_DIR: &str = "/Unfiled";
pub const QUERY_DIR: &str = "/.query";

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// A directory record (`id`) or one implied by paths below it.
    Dir { id: Option<String> },
    File { id: String, cap: Option<String>, size: u64, mtime_ms: Option<i64> },
}

impl Node {
    pub fn id(&self) -> Option<&str> {
        match self {
            Node::Dir { id } => id.as_deref(),
            Node::File { id, .. } => Some(id),
        }
    }
}

#[derive(Debug, Default)]
pub struct Tree {
    pub nodes: BTreeMap<String, Node>,
}

/// `/a//b/` → `/a/b`. None for relative paths, `.` or `..` components, or
/// paths inside the virtual directories.
pub fn normalize(p: &str) -> Option<String> {
    if !p.starts_with('/') {
        return None;
    }
    let mut out = String::new();
    for c in p.split('/').filter(|c| !c.is_empty()) {
        if c == "." || c == ".." || c.contains('\0') {
            return None;
        }
        out.push('/');
        out.push_str(c);
    }
    if out.is_empty() {
        out.push('/');
    }
    (!is_virtual(&out) || out == RECORDS_DIR || out == QUERY_DIR).then_some(out)
}

/// Inside `/Unfiled` or `/.query`: not a place a record's path can point
/// (a file put in `/Unfiled` is one without a path).
pub fn is_virtual(p: &str) -> bool {
    [RECORDS_DIR, QUERY_DIR].iter().any(|v| p == *v || p.starts_with(&format!("{v}/")))
}

pub fn parent(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &p[..i],
    }
}

pub fn name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or("")
}

pub fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}

fn attr<'a>(r: &'a RecordView, key: &str) -> Option<&'a AttrValue> {
    r.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// A record's file name in `/Unfiled`: its `name`, made safe for a file
/// name, or its ID.
fn unfiled_name(r: &RecordView) -> String {
    let name = match attr(r, "name") {
        Some(AttrValue::Str(n)) => n.chars().map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c }).collect::<String>(),
        _ => String::new(),
    };
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." { r.id.clone() } else { name.to_string() }
}

fn unique(nodes: &BTreeMap<String, Node>, p: String, id: &str) -> String {
    if nodes.contains_key(&p) { format!("{p}~{}", &id[..8.min(id.len())]) } else { p }
}

impl Tree {
    pub fn build(records: &[RecordView]) -> Tree {
        let mut nodes = BTreeMap::new();
        // Unfiled only when something is in it (a directory implied below).
        for v in ["/", QUERY_DIR] {
            nodes.insert(v.to_string(), Node::Dir { id: None });
        }
        let mut sorted: Vec<&RecordView> = records.iter().collect();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        for r in sorted {
            let path = match attr(r, "path") {
                Some(AttrValue::Str(p)) => normalize(p).filter(|p| p != "/" && !is_virtual(p)),
                _ => None,
            };
            let dir = matches!(attr(r, "type"), Some(AttrValue::Str(t)) if t == "directory");
            let internal = matches!(attr(r, "type"), Some(AttrValue::Str(t)) if t.starts_with("retifs.") || t == "keep-rule");
            if path.is_none() && internal {
                continue;
            }
            match (path, dir) {
                (Some(p), true) => {
                    let p = unique(&nodes, p, &r.id);
                    nodes.insert(p, Node::Dir { id: Some(r.id.clone()) });
                }
                (path, _) => {
                    let p = path.unwrap_or_else(|| join(RECORDS_DIR, &unfiled_name(r)));
                    let p = unique(&nodes, p, &r.id);
                    let size = match attr(r, "size") {
                        Some(AttrValue::Int(n)) if *n >= 0 => *n as u64,
                        _ => 0,
                    };
                    let mtime_ms = match attr(r, "mtime") {
                        Some(AttrValue::Int(t)) => Some(*t),
                        _ => None,
                    };
                    nodes.insert(p, Node::File { id: r.id.clone(), cap: r.blocks.first().cloned(), size, mtime_ms });
                }
            }
        }
        // Directories implied by paths below them. A file in the way of one
        // moves aside, like any other clash.
        let paths: Vec<String> = nodes.keys().cloned().collect();
        for p in paths {
            let mut d = parent(&p).to_string();
            while d != "/" {
                match nodes.get(&d) {
                    Some(Node::Dir { .. }) => {}
                    Some(Node::File { id, .. }) => {
                        let aside = format!("{d}~{}", &id[..8.min(id.len())]);
                        let file = nodes.remove(&d).unwrap();
                        nodes.insert(aside, file);
                        nodes.insert(d.clone(), Node::Dir { id: None });
                    }
                    None => {
                        nodes.insert(d.clone(), Node::Dir { id: None });
                    }
                }
                d = parent(&d).to_string();
            }
        }
        Tree { nodes }
    }

    pub fn get(&self, p: &str) -> Option<&Node> {
        self.nodes.get(p)
    }

    /// Entries directly in `dir`: (name, full path).
    pub fn children(&self, dir: &str) -> Vec<(String, String)> {
        let prefix = if dir == "/" { "/".to_string() } else { format!("{dir}/") };
        self.nodes
            .range(prefix.clone()..)
            .take_while(|(p, _)| p.starts_with(&prefix))
            .filter(|(p, _)| p.len() > prefix.len() && !p[prefix.len()..].contains('/'))
            .map(|(p, _)| (p[prefix.len()..].to_string(), p.clone()))
            .collect()
    }

    /// Records at `dir` and below it: (path, id). For moving a directory.
    pub fn records_under(&self, dir: &str) -> Vec<(String, String)> {
        let prefix = format!("{dir}/");
        self.nodes
            .iter()
            .filter(|(p, _)| *p == dir || p.starts_with(&prefix))
            .filter_map(|(p, n)| n.id().map(|id| (p.clone(), id.to_string())))
            .collect()
    }
}

/// A query directory's name as terms: comma-separated, each percent-decoded
/// (`%2F` is `/`, which a name can't hold; `%2C` a comma inside a term).
pub fn query_terms(dir_name: &str) -> Vec<String> {
    dir_name.split(',').map(|t| percent_decode(t.trim())).filter(|t| !t.is_empty()).collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(x) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(x);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// An attribute value as xattr text: strings as they are (quoted if they'd
/// read back as something else), numbers, `true`/`false`, `null`, bytes as
/// `0x…`, lists as JSON.
pub fn format_value(v: &AttrValue) -> String {
    match v {
        AttrValue::Str(s) => {
            if matches!(parse_value(s), AttrValue::Str(ref back) if back == s) {
                s.clone()
            } else {
                json_string(s)
            }
        }
        other => format_item(other),
    }
}

fn format_item(v: &AttrValue) -> String {
    match v {
        AttrValue::Null => "null".into(),
        AttrValue::Bool(b) => b.to_string(),
        AttrValue::Int(i) => i.to_string(),
        AttrValue::Float(f) => format!("{f:?}"),
        AttrValue::Str(s) => json_string(s),
        AttrValue::Bytes(b) => format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
        AttrValue::List(items) => format!("[{}]", items.iter().map(format_item).collect::<Vec<_>>().join(", ")),
    }
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("strings serialize")
}

/// xattr text back to a value: the inverse of [`format_value`]. Anything
/// that isn't a number, `true`/`false`, `null`, `0x…`, a JSON string or list
/// is a string as written.
pub fn parse_value(s: &str) -> AttrValue {
    match s {
        "null" => return AttrValue::Null,
        "true" => return AttrValue::Bool(true),
        "false" => return AttrValue::Bool(false),
        _ => {}
    }
    if let Ok(i) = s.parse::<i64>() {
        return AttrValue::Int(i);
    }
    if let Ok(f) = s.parse::<f64>()
        && f.is_finite()
        && s.chars().all(|c| c.is_ascii_digit() || "+-.eE".contains(c))
    {
        return AttrValue::Float(f);
    }
    if let Some(hex) = s.strip_prefix("0x")
        && !hex.is_empty()
        && hex.len() % 2 == 0
        && let Some(bytes) = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect::<Option<Vec<u8>>>()
    {
        return AttrValue::Bytes(bytes);
    }
    if (s.starts_with('"') || s.starts_with('['))
        && let Ok(j) = serde_json::from_str::<serde_json::Value>(s)
        && let Some(v) = from_json(&j)
    {
        return v;
    }
    AttrValue::Str(s.to_string())
}

fn from_json(j: &serde_json::Value) -> Option<AttrValue> {
    use serde_json::Value as J;
    Some(match j {
        J::Null => AttrValue::Null,
        J::Bool(b) => AttrValue::Bool(*b),
        J::Number(n) => match n.as_i64() {
            Some(i) => AttrValue::Int(i),
            None => AttrValue::Float(n.as_f64()?),
        },
        J::String(s) => match parse_value(s) {
            AttrValue::Bytes(b) if s.starts_with("0x") => AttrValue::Bytes(b),
            _ => AttrValue::Str(s.clone()),
        },
        J::Array(items) => AttrValue::List(items.iter().map(from_json).collect::<Option<_>>()?),
        J::Object(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, attrs: &[(&str, AttrValue)], blocks: &[&str]) -> RecordView {
        RecordView {
            id: id.to_string(),
            attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
            blocks: blocks.iter().map(|b| b.to_string()).collect(),
        }
    }
    fn s(x: &str) -> AttrValue {
        AttrValue::Str(x.into())
    }

    #[test]
    fn unfiled_only_when_used() {
        let t = Tree::build(&[rec("aa01", &[("path", s("/a.txt"))], &[])]);
        assert!(t.get(RECORDS_DIR).is_none());
    }

    #[test]
    fn paths_become_a_tree() {
        let t = Tree::build(&[
            rec("aa01", &[("path", s("/docs/a.txt")), ("size", AttrValue::Int(5))], &["cap-a"]),
            rec("aa02", &[("path", s("//docs/sub/../b.txt"))], &[]),
            rec("aa03", &[("path", s("/photos")), ("type", s("directory"))], &[]),
            rec("aa04", &[("title", s("no path"))], &[]),
            rec("aa10", &[("name", s("IMG_1.jpg"))], &[]),
            rec("aa11", &[("name", s("IMG_1.jpg"))], &[]),
            rec("aa12", &[("name", s("a/b"))], &[]),
            rec("aa05", &[("path", s("/docs/a.txt"))], &[]),
            rec("aa06", &[("path", s("/docs"))], &[]),
            rec("aa07", &[("path", s("/.query/x"))], &[]),
            rec("aa08", &[("type", s("retifs.share")), ("name", s("prangli"))], &[]),
            rec("aa09", &[("type", s("keep-rule")), ("query", s("album=x"))], &[]),
        ]);
        let names = |d: &str| t.children(d).into_iter().map(|(n, _)| n).collect::<Vec<_>>();
        assert_eq!(names("/"), [".query", "Unfiled", "docs", "docs~aa06", "photos"]);
        assert_eq!(names("/docs"), ["a.txt", "a.txt~aa05"]);
        assert_eq!(t.get("/docs/a.txt"), Some(&Node::File { id: "aa01".into(), cap: Some("cap-a".into()), size: 5, mtime_ms: None }));
        assert_eq!(t.get("/photos"), Some(&Node::Dir { id: Some("aa03".into()) }));
        assert_eq!(names("/Unfiled"), ["IMG_1.jpg", "IMG_1.jpg~aa11", "a_b", "aa02", "aa04", "aa07"], "no path (or a bad one): by name, else ID");
        assert_eq!(names("/photos"), Vec::<String>::new());
        assert_eq!(t.records_under("/docs").len(), 2);
    }

    #[test]
    fn query_names_decode() {
        assert_eq!(query_terms("path^=%2Fphotos%2F, type=photo"), ["path^=/photos/", "type=photo"]);
        assert_eq!(query_terms("album=Prangli 2026"), ["album=Prangli 2026"]);
        assert_eq!(query_terms("note=a%2Cb,,"), ["note=a,b"]);
        assert_eq!(query_terms("x=100%"), ["x=100%"]);
    }

    #[test]
    fn values_round_trip_as_text() {
        let cases = [
            s("hello world"),
            s("42"),
            s("true"),
            s("0xzz"),
            s(""),
            s("\"quoted\""),
            AttrValue::Int(-7),
            AttrValue::Float(1.0),
            AttrValue::Float(2.5e-8),
            AttrValue::Bool(false),
            AttrValue::Null,
            AttrValue::Bytes(vec![0, 255]),
            AttrValue::List(vec![AttrValue::Int(1), s("a, b"), AttrValue::Bool(true)]),
        ];
        for v in cases {
            let text = format_value(&v);
            assert_eq!(parse_value(&text), v, "{text}");
        }
        assert_eq!(format_value(&s("plain")), "plain");
        assert_eq!(format_value(&s("42")), "\"42\"");
        assert_eq!(parse_value("Prangli 2026"), s("Prangli 2026"));
    }
}
