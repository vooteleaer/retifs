//! What the Windows folder shows of the tree (no Windows API here, so it's
//! tested everywhere): which tree paths can be Windows names, how names that
//! differ only in case are told apart, and the identity each placeholder
//! carries.

use std::collections::{BTreeMap, HashSet};

use libretifs::{AttrValue, RecordView};
use retifs_tree::{Node, Tree, QUERY_DIR};

/// What one placeholder should be.
#[derive(Debug, Clone, PartialEq)]
pub struct Want {
    /// Relative to the sync root, `\`-separated.
    pub rel: String,
    pub dir: bool,
    /// The placeholder's identity: [`identity`] of the record and content.
    pub blob: Vec<u8>,
    pub size: u64,
    pub mtime_ms: Option<i64>,
    /// Kept on this device (`keep` or `keep:<device>` is true): pinned,
    /// "Always keep on this device" in Explorer.
    pub keep: bool,
}

/// Every placeholder the folder should hold, parents before children, keyed
/// by the lowercased relative path (Windows names ignore case). Directories
/// differing only in case are one folder (the first spelling); paths that
/// can't be Windows names, and a file whose name another entry already has
/// in another case, are left out and returned as `skipped`.
pub struct Plan {
    pub wants: Vec<Want>,
    pub index: BTreeMap<String, usize>,
    pub skipped: Vec<String>,
}

pub fn plan(tree: &Tree, records: &[RecordView], device: &str) -> Plan {
    let kept: HashSet<&str> = records.iter().filter(|r| is_kept(r, device)).map(|r| r.id.as_str()).collect();
    let mut plan = Plan { wants: Vec::new(), index: BTreeMap::new(), skipped: Vec::new() };
    let mut bad_dirs: Vec<String> = Vec::new();
    for (path, node) in &tree.nodes {
        if path == "/" || path == QUERY_DIR || path.starts_with(&format!("{QUERY_DIR}/")) {
            continue; // queries stay in apps and the desktop utility (ADR-0002)
        }
        if bad_dirs.iter().any(|d| path.starts_with(&format!("{d}/"))) {
            continue;
        }
        let Some(rel) = windows_rel(path) else {
            plan.skipped.push(path.clone());
            if matches!(node, Node::Dir { .. }) {
                bad_dirs.push(path.clone());
            }
            continue;
        };
        // Under a directory already seen with other case: its spelling.
        let rel = match rel.rsplit_once('\\') {
            Some((parent, name)) => match plan.index.get(&parent.to_lowercase()) {
                Some(&i) => format!("{}\\{name}", plan.wants[i].rel),
                None => rel,
            },
            None => rel,
        };
        let key = rel.to_lowercase();
        if let Some(&i) = plan.index.get(&key) {
            // Two directories differing in case are one folder on Windows.
            if !(plan.wants[i].dir && matches!(node, Node::Dir { .. })) {
                plan.skipped.push(path.clone());
                if matches!(node, Node::Dir { .. }) {
                    bad_dirs.push(path.clone());
                }
            }
            continue;
        }
        let want = match node {
            Node::Dir { id } => Want { blob: identity(id.as_deref().unwrap_or(""), None), rel, dir: true, size: 0, mtime_ms: None, keep: false },
            Node::File { id, cap, size, mtime_ms } => {
                Want { blob: identity(id, cap.as_deref()), rel, dir: false, size: *size, mtime_ms: *mtime_ms, keep: kept.contains(id.as_str()) }
            }
        };
        plan.index.insert(key, plan.wants.len());
        plan.wants.push(want);
    }
    plan
}

fn is_kept(r: &RecordView, device: &str) -> bool {
    let own = format!("keep:{device}");
    r.attrs.iter().any(|(k, v)| (k == "keep" || *k == own) && *v == AttrValue::Bool(true))
}

/// A tree path (`/a/b.txt`) as a path relative to the sync root (`a\b.txt`),
/// or None if a component can't be a Windows name.
pub fn windows_rel(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    (!parts.is_empty() && parts.iter().all(|c| valid_name(c))).then(|| parts.join("\\"))
}

fn valid_name(c: &str) -> bool {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
        "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = c.split('.').next().unwrap_or("").trim_end();
    !c.is_empty()
        && c.len() <= 255
        && !c.ends_with('.')
        && !c.ends_with(' ')
        && !c.chars().any(|ch| ch < ' ' || "<>:\"/\\|?*".contains(ch))
        && !RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem))
}

/// A path relative to the sync root (`a\b.txt`) as a tree path (`/a/b.txt`).
pub fn tree_path(rel: &str) -> String {
    let parts: Vec<&str> = rel.split(['\\', '/']).filter(|c| !c.is_empty()).collect();
    format!("/{}", parts.join("/"))
}

/// Files applications keep beside documents for themselves (Office's lock
/// files, editors' temporary files, Explorer's folder settings): they stay
/// in the folder and aren't written to retifs.
pub fn is_scratch(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("~$") || lower.starts_with(".~lock.") || lower.ends_with(".tmp") || lower.ends_with('~') || lower == "desktop.ini" || lower == "thumbs.db"
}

/// A placeholder's identity (its file blob, at most 4 KiB): the record ID
/// and the content's read-cap. A new version has a new cap, so a changed
/// identity means the placeholder's content is stale.
pub fn identity(id: &str, cap: Option<&str>) -> Vec<u8> {
    format!("{id}\n{}", cap.unwrap_or("")).into_bytes()
}

/// The record ID and read-cap back out of an identity.
pub fn parse_identity(blob: &[u8]) -> Option<(&str, Option<&str>)> {
    let s = std::str::from_utf8(blob).ok()?;
    let (id, cap) = s.split_once('\n')?;
    Some((id, (!cap.is_empty()).then_some(cap)))
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
    fn local_paths() {
        assert_eq!(tree_path("docs\\a b.txt"), "/docs/a b.txt");
        assert_eq!(tree_path("x"), "/x");
        for scratch in ["~$Report.docx", "x.TMP", ".~lock.a.odt#", "notes.txt~", "Desktop.ini", "Thumbs.db"] {
            assert!(is_scratch(scratch), "{scratch}");
        }
        assert!(!is_scratch("Report.docx"));
    }

    #[test]
    fn windows_names() {
        assert_eq!(windows_rel("/docs/a.txt").as_deref(), Some("docs\\a.txt"));
        for bad in ["/a:b", "/x/what?", "/trail.", "/trail ", "/con", "/Con.txt", "/LPT1.tar.gz", "/tab\there", "/"] {
            assert_eq!(windows_rel(bad), None, "{bad}");
        }
        assert_eq!(windows_rel("/console").as_deref(), Some("console"));
        assert_eq!(windows_rel("/.records/ab12").as_deref(), Some(".records\\ab12"));
    }

    #[test]
    fn plan_skips_what_windows_cant_hold() {
        let records = [
            rec("aa01", &[("path", s("/Docs/a.txt")), ("size", AttrValue::Int(3)), ("keep:laptop", AttrValue::Bool(true))], &["cap-a"]),
            rec("aa02", &[("path", s("/docs/b.txt"))], &["cap-b"]),
            rec("aa03", &[("path", s("/bad:dir/c.txt"))], &[]),
            rec("aa04", &[("path", s("/A.TXT"))], &[]),
            rec("aa05", &[("path", s("/a.txt")), ("keep", AttrValue::Bool(true))], &[]),
            rec("aa06", &[("path", s("/e.txt")), ("keep:phone", AttrValue::Bool(true))], &[]),
        ];
        let p = plan(&Tree::build(&records), &records, "laptop");
        let rels: Vec<&str> = p.wants.iter().map(|w| w.rel.as_str()).collect();
        assert_eq!(rels, [".records", "A.TXT", "Docs", "Docs\\a.txt", "Docs\\b.txt", "e.txt"]);
        assert!(p.skipped.contains(&"/a.txt".to_string()), "case clash");
        assert!(!p.skipped.contains(&"/docs".to_string()), "merged into Docs");
        assert!(p.skipped.contains(&"/bad:dir".to_string()));
        assert!(!p.skipped.iter().any(|s| s.starts_with("/bad:dir/")), "only the directory is reported");
        let a = &p.wants[p.index["docs\\a.txt"]];
        assert!(a.keep && !a.dir && a.size == 3);
        assert_eq!(parse_identity(&a.blob), Some(("aa01", Some("cap-a"))));
        assert!(!p.wants[p.index["e.txt"]].keep, "kept on another device");
        assert!(!rels.iter().any(|r| r.starts_with(".query")));
    }
}
