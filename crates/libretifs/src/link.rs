//! `retifs:` links (ADR-0020): one envelope for what apps pass around as
//! text or QR codes.
//!
//! ```text
//! retifs:<kind>/<what>[?<key>=<value>&…]
//! ```
//!
//! Kinds: `node`, `ns`, `invite`, `ch`, `cap`. For `ns`, `<what>` is the
//! namespace address without its `retifs-ch:` prefix (`1:<writer>:<read key>`).
//! Parameters: `q` (a query, in the CLI's terms: what to open on), `view`
//! (which kind of app), `name` (a label), `from` (a node to fetch from, may
//! repeat). Values are percent-encoded. Unknown kinds and parameters are
//! kept, not refused, so printed codes keep working as kinds are added.

const SCHEME: &str = "retifs:";
const CHANNEL_PREFIX: &str = "retifs-ch:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub kind: String,
    pub what: String,
    pub params: Vec<(String, String)>,
}

impl Link {
    /// A read link to a namespace: its address (as `ns address` prints it),
    /// the nodes to fetch from, and a label.
    pub fn namespace(address: &str, from: &[String], name: Option<&str>) -> Link {
        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(n) = name {
            params.push(("name".into(), n.into()));
        }
        params.extend(from.iter().map(|f| ("from".to_string(), f.clone())));
        Link { kind: "ns".into(), what: address.strip_prefix(CHANNEL_PREFIX).unwrap_or(address).into(), params }
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn params_named<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.params.iter().filter(move |(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// For an `ns` link: the namespace address, as `ns join` takes it.
    pub fn ns_address(&self) -> Option<String> {
        (self.kind == "ns").then(|| format!("{CHANNEL_PREFIX}{}", self.what))
    }

    pub fn parse(s: &str) -> Result<Link, String> {
        let rest = s.trim().strip_prefix(SCHEME).ok_or("not a retifs: link")?;
        let (head, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (kind, what) = head.split_once('/').ok_or("a retifs: link needs a kind and what it points at")?;
        if kind.is_empty() || what.is_empty() {
            return Err("a retifs: link needs a kind and what it points at".into());
        }
        let params = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (decode(k), decode(v))
            })
            .collect();
        Ok(Link { kind: decode(kind), what: decode(what), params })
    }
}

impl std::fmt::Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SCHEME}{}/{}", encode(&self.kind), encode(&self.what))?;
        for (i, (k, v)) in self.params.iter().enumerate() {
            write!(f, "{}{}={}", if i == 0 { '?' } else { '&' }, encode(k), encode(v))?;
        }
        Ok(())
    }
}

/// A local namespace name from a label (a link's `name`, a folder's name):
/// lowercase letters, digits and dashes.
pub fn suggest_name(label: &str) -> String {
    let mut out = String::new();
    for c in label.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() { "shared".into() } else { out }
}

/// Percent-encodes all but unreserved characters and `:` (which addresses
/// use; it needs no encoding after the scheme).
fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = || s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
        match b[i] {
            b'%' if hex().is_some() => {
                out.push(hex().unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "retifs-ch:1:0f19bffab935b2aee3fd49313f700896a1be1925d9404f869eb1b5c332def4a4:847e7e2e0bde37d911ea1fd781f9c874041b8ebc1df6332a94f8a436f8f090ed";

    #[test]
    fn namespace_links_round_trip() {
        let mut l = Link::namespace(ADDR, &["1bb2eee04ab73ba0067b3431f4c5de79".into()], Some("Prangli 2026"));
        l.params.push(("q".into(), "album=Prangli 2026, type=photo".into()));
        let text = l.to_string();
        assert!(text.starts_with("retifs:ns/1:0f19bf"), "{text}");
        assert!(text.contains("name=Prangli%202026") && text.contains("q=album%3DPrangli%202026%2C%20type%3Dphoto"), "{text}");
        let back = Link::parse(&text).unwrap();
        assert_eq!(back, l);
        assert_eq!(back.ns_address().as_deref(), Some(ADDR));
        assert_eq!(back.params_named("from").collect::<Vec<_>>(), ["1bb2eee04ab73ba0067b3431f4c5de79"]);
        assert_eq!(back.param("q"), Some("album=Prangli 2026, type=photo"));
    }

    #[test]
    fn unknown_kinds_and_params_are_kept() {
        let l = Link::parse("retifs:future/thing?x=1&view=photos&flag").unwrap();
        assert_eq!((l.kind.as_str(), l.what.as_str()), ("future", "thing"));
        assert_eq!(l.param("x"), Some("1"));
        assert_eq!(l.param("flag"), Some(""));
        assert_eq!(l.ns_address(), None);
        assert_eq!(Link::parse("retifs:ns/1:ab?name=a+b%2").unwrap().param("name"), Some("a b%2"));
    }

    #[test]
    fn suggested_names() {
        assert_eq!(suggest_name("Prangli 2026"), "prangli-2026");
        assert_eq!(suggest_name("Boat (1).jpg"), "boat-1-jpg");
        assert_eq!(suggest_name("---"), "shared");
        assert_eq!(suggest_name("Õunad"), "õunad");
    }

    #[test]
    fn not_links() {
        for bad in ["", "https://x", "retifs:", "retifs:ns", "retifs:/x", "retifs:ns/"] {
            assert!(Link::parse(bad).is_err(), "{bad}");
        }
    }
}
