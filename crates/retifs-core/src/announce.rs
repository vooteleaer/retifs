//! What a `retifs.node` announce carries in its app data (ADR-0014): how
//! often the node announces, so others can tell a node that went quiet from
//! one that announces rarely, and, if its owner said, which site it's at, so
//! copies can be kept in more than one place. Canonical msgpack, a map so it
//! can grow (keys in order; `hold` only when false, `site` only when set):
//!
//! ```text
//! { "announce_s": uint, "hold": false, "site": bin 8, "v": 1 }
//! ```
//!
//! `hold: false`: the node holds nothing for others (`--hold-for-others 0`,
//! a phone, a test node), so offering it copies is pointless.
//!
//! The site is a tag, not the name: the first 8 bytes of
//! SHA-256("retifs.site" ‖ 0x00 ‖ the name, trimmed and lowercased). Nodes
//! with the same name are at the same site; a name others might also use
//! ("home") makes their nodes look like the same site too, which only costs
//! diversity, so a name of one's own is better ("prangli-home").
//!
//! Nodes before this sent `retifs/v0` (no interval known).

use sha2::{Digest, Sha256};

use crate::record::{write_array_len, write_bin, write_int, write_map_len, write_str, write_value, Reader, Value};

/// A site's tag in announces.
pub type SiteTag = [u8; 8];

/// The tag of site `name`.
pub fn site_tag(name: &str) -> SiteTag {
    let mut h = Sha256::new();
    h.update(b"retifs.site\0");
    h.update(name.trim().to_lowercase().as_bytes());
    h.finalize()[..8].try_into().expect("8 bytes")
}

/// What a node's announce says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeAnnounce {
    pub announce_s: Option<u32>,
    pub site: Option<SiteTag>,
    /// It said it holds nothing for others.
    pub holds_nothing: bool,
}

/// The interval assumed for a node that doesn't say (and the default).
pub const DEFAULT_ANNOUNCE_S: u32 = 600;

/// A node's announce app data, announcing every `announce_s` seconds, at
/// `site` if its owner named one; `holds`: whether it holds others' copies.
pub fn node_app_data(announce_s: u32, site: Option<SiteTag>, holds: bool) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_len(&mut out, 2 + site.is_some() as usize + !holds as usize);
    write_str(&mut out, "announce_s");
    write_int(&mut out, announce_s as i64);
    if !holds {
        write_str(&mut out, "hold");
        out.push(0xc2);
    }
    if let Some(site) = site {
        write_str(&mut out, "site");
        write_bin(&mut out, &site);
    }
    write_str(&mut out, "v");
    write_int(&mut out, 1);
    out
}

/// What a node's app data states. Anything unreadable (an older node's
/// `retifs/v0`, other versions) says nothing; unknown fields are skipped.
pub fn node_announce(app_data: &[u8]) -> NodeAnnounce {
    let mut out = NodeAnnounce::default();
    let mut r = Reader(app_data);
    let Ok(n) = r.map_len() else { return out };
    for _ in 0..n {
        let (Ok(key), Ok(v)) = (r.str(), r.value(1)) else { return NodeAnnounce::default() };
        match (key.as_str(), v) {
            ("announce_s", Value::Int(i)) => out.announce_s = u32::try_from(i).ok().filter(|s| *s > 0),
            ("site", Value::Bytes(b)) => out.site = b.try_into().ok(),
            ("hold", Value::Bool(false)) => out.holds_nothing = true,
            _ => {}
        }
    }
    out
}

/// The announce interval a node's app data states, if any.
pub fn node_announce_s(app_data: &[u8]) -> Option<u32> {
    node_announce(app_data).announce_s
}

// ------------------------------------------------- announced public libraries

/// A public library's announce (ADR-0029), sent from the node's
/// `retifs.library` destination, one library per announce. Canonical msgpack,
/// keys in order (`bounds` only when set):
///
/// ```text
/// { "about": str, "bounds": [w, s, e, n], "ch": bin 64 (writer ‖ read key),
///   "fmt": 1, "has": [[type, count], ...], "name": str, "node": bin 16,
///   "seq": uint, "v": 1 }
/// ```
///
/// `node`: the announcing node's `retifs.node` address, which serves the
/// library (the announce comes from its `retifs.library` destination, which
/// serves nothing).
/// ```text
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct LibraryAnnounce {
    pub name: String,
    pub about: String,
    /// The channel: writer key and read key (its address, `retifs-ch:1:…`).
    pub writer: [u8; 32],
    pub read_key: [u8; 32],
    /// The library format it's in (channels and records, decision 2).
    pub fmt: u32,
    /// What it holds: record types and how many of each, most first.
    pub has: Vec<(String, u64)>,
    /// west, south, east, north, for a library tied to an area.
    pub bounds: Option<[f64; 4]>,
    /// Its latest version.
    pub seq: u64,
    /// The node that serves it (its `retifs.node` address).
    pub node: Option<[u8; 16]>,
}

/// The library format this node reads and writes.
pub const LIBRARY_FMT: u32 = 1;
/// Limits that keep an announce inside one packet.
pub const NAME_MAX: usize = 32;
pub const ABOUT_MAX: usize = 80;
pub const HAS_MAX: usize = 6;
pub const TYPE_MAX: usize = 48;

fn cut(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The most app data a library announce carries: a Reticulum announce has
/// room for 316 bytes (an MTU of 500 less the header and the announce's
/// keys, name hash, random part and signature); this leaves a margin.
pub const APP_DATA_MAX: usize = 300;

/// How short the description may get before types are left out: what a
/// library holds tells apps whether it's for them, so it matters more.
pub const ABOUT_MIN: usize = 24;

/// The app data of a library's announce, cut to fit `APP_DATA_MAX`. retifs'
/// own records (`retifs.*`: placement, shares) aren't content and aren't
/// listed. Then the description gets shorter, down to `ABOUT_MIN`, then the
/// least common types go (a single map record is worth more than that, but
/// the order is the publisher's to choose: the most telling first).
pub fn library_app_data(l: &LibraryAnnounce) -> Vec<u8> {
    let mut l = l.clone();
    l.has.retain(|(t, _)| !t.starts_with("retifs."));
    l.has.truncate(HAS_MAX);
    loop {
        let out = encode_library(&l);
        if out.len() <= APP_DATA_MAX {
            return out;
        }
        if l.about.len() > ABOUT_MIN {
            let keep = l.about.len().saturating_sub(out.len() - APP_DATA_MAX).max(ABOUT_MIN);
            l.about = cut(&l.about, keep).to_string();
        } else if l.has.len() > 1 {
            l.has.pop();
        } else if !l.about.is_empty() {
            l.about.clear();
        } else {
            l.has.clear();
            l.bounds = None;
            return encode_library(&l);
        }
    }
}

fn encode_library(l: &LibraryAnnounce) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_len(&mut out, 7 + l.bounds.is_some() as usize + l.node.is_some() as usize);
    write_str(&mut out, "about");
    write_str(&mut out, cut(&l.about, ABOUT_MAX));
    if let Some(b) = l.bounds {
        write_str(&mut out, "bounds");
        write_value(&mut out, &Value::List(b.iter().map(|f| Value::Float(*f)).collect()));
    }
    write_str(&mut out, "ch");
    let mut ch = [0u8; 64];
    ch[..32].copy_from_slice(&l.writer);
    ch[32..].copy_from_slice(&l.read_key);
    write_bin(&mut out, &ch);
    write_str(&mut out, "fmt");
    write_int(&mut out, l.fmt as i64);
    write_str(&mut out, "has");
    let has: Vec<&(String, u64)> = l.has.iter().take(HAS_MAX).collect();
    write_array_len(&mut out, has.len());
    for (t, n) in has {
        write_array_len(&mut out, 2);
        write_str(&mut out, cut(t, TYPE_MAX));
        write_int(&mut out, *n as i64);
    }
    write_str(&mut out, "name");
    write_str(&mut out, cut(&l.name, NAME_MAX));
    if let Some(n) = l.node {
        write_str(&mut out, "node");
        write_bin(&mut out, &n);
    }
    write_str(&mut out, "seq");
    write_int(&mut out, l.seq as i64);
    write_str(&mut out, "v");
    write_int(&mut out, 1);
    out
}

/// What a heard library announce says. None when it isn't one (a node's
/// announce, anything else) or names no channel. Unknown keys are skipped; an
/// announce of another `v` is returned with `v` so a node can say it needs a
/// newer retifs (ADR-0030) without reading the rest.
pub fn library_announce(app_data: &[u8]) -> Option<(u32, Option<LibraryAnnounce>)> {
    let mut r = Reader(app_data);
    let n = r.map_len().ok()?;
    let (mut v, mut ch, mut l) = (None, None, LibraryAnnounce { name: String::new(), about: String::new(), writer: [0; 32], read_key: [0; 32], fmt: 0, has: Vec::new(), bounds: None, seq: 0, node: None });
    for _ in 0..n {
        let key = r.str().ok()?;
        let value = r.value(1).ok()?;
        match (key.as_str(), value) {
            ("v", Value::Int(i)) => v = u32::try_from(i).ok(),
            ("ch", Value::Bytes(b)) if b.len() == 64 => ch = Some(b),
            ("name", Value::Str(s)) => l.name = s,
            ("about", Value::Str(s)) => l.about = s,
            ("fmt", Value::Int(i)) => l.fmt = u32::try_from(i).unwrap_or(u32::MAX),
            ("seq", Value::Int(i)) => l.seq = u64::try_from(i).unwrap_or(0),
            ("node", Value::Bytes(b)) => l.node = b.try_into().ok(),
            ("bounds", Value::List(b)) => {
                let f: Vec<f64> = b.iter().filter_map(|x| if let Value::Float(f) = x { Some(*f) } else { None }).collect();
                l.bounds = (f.len() == 4).then(|| [f[0], f[1], f[2], f[3]]);
            }
            ("has", Value::List(items)) => {
                l.has = items
                    .into_iter()
                    .filter_map(|it| match it {
                        Value::List(pair) => match pair.as_slice() {
                            [Value::Str(t), Value::Int(c)] => Some((t.clone(), u64::try_from(*c).ok()?)),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect()
            }
            _ => {}
        }
    }
    let v = v?;
    if v != 1 {
        return Some((v, None));
    }
    let ch = ch?;
    l.writer.copy_from_slice(&ch[..32]);
    l.read_key.copy_from_slice(&ch[32..]);
    Some((v, Some(l)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ignores_old_or_odd_data() {
        assert_eq!(node_announce_s(&node_app_data(600, None, true)), Some(600));
        assert_eq!(node_announce_s(&node_app_data(86_400, None, true)), Some(86_400));
        // Without a site, as before sites.
        assert_eq!(node_app_data(600, None, true), [0x82, 0xaa, b'a', b'n', b'n', b'o', b'u', b'n', b'c', b'e', b'_', b's', 0xcd, 0x02, 0x58, 0xa1, b'v', 0x01]);
        assert_eq!(node_announce_s(b"retifs/v0"), None);
        assert_eq!(node_announce_s(&node_app_data(0, None, true)), None);
        assert_eq!(node_announce_s(&[]), None);
    }

    #[test]
    fn sites() {
        let home = site_tag("Prangli-Home");
        assert_eq!(home, site_tag("  prangli-home "), "trimmed, any case");
        assert_ne!(home, site_tag("prangli-cabin"));
        let a = node_announce(&node_app_data(600, Some(home), true));
        assert_eq!(a, NodeAnnounce { announce_s: Some(600), site: Some(home), holds_nothing: false });
        let data = node_app_data(600, Some([7; 8]), true);
        assert_eq!(&data[..1], &[0x83]);
        assert_eq!(&data[15..27], &[0xa4, b's', b'i', b't', b'e', 0xc4, 0x08, 7, 7, 7, 7, 7]);
        assert_eq!(node_announce(&node_app_data(600, None, true)).site, None);
        // A site of the wrong size is no site.
        let mut odd = Vec::new();
        write_map_len(&mut odd, 1);
        write_str(&mut odd, "site");
        write_bin(&mut odd, &[1, 2, 3]);
        assert_eq!(node_announce(&odd), NodeAnnounce::default());
    }

    #[test]
    fn libraries() {
        let l = LibraryAnnounce {
            name: "Eesti kaart".into(),
            about: "OpenStreetMap, 2026-10-27: tiles, places".into(),
            writer: [1; 32],
            read_key: [2; 32],
            fmt: LIBRARY_FMT,
            has: vec![("application/vnd.mapbox-vector-tile".into(), 95332), ("application/x-vnd.retifs.tileset".into(), 1)],
            bounds: Some([20.85, 57.49, 28.22, 60.0]),
            seq: 191,
            node: Some([9; 16]),
        };
        let data = library_app_data(&l);
        assert!(data.len() <= APP_DATA_MAX, "{} bytes", data.len());
        // The description got shorter to make room; every type is still there.
        let read = library_announce(&data).unwrap().1.unwrap();
        assert_eq!(read.has, l.has);
        assert!(read.about.len() >= ABOUT_MIN && l.about.starts_with(&read.about), "{}", read.about);
        // retifs' own records aren't listed.
        let own = LibraryAnnounce { has: vec![("application/x-vnd.retifs.place".into(), 5), ("retifs.placement".into(), 1)], ..l.clone() };
        assert_eq!(library_announce(&library_app_data(&own)).unwrap().1.unwrap().has, vec![("application/x-vnd.retifs.place".to_string(), 5)]);
        let small = LibraryAnnounce { has: l.has[..1].to_vec(), ..l.clone() };
        assert_eq!(library_announce(&library_app_data(&small)), Some((1, Some(small))));
        // Too long: cut, still read.
        let long = LibraryAnnounce { name: "ä".repeat(40), about: "x".repeat(200), has: (0..20).map(|i| (format!("t/{i}"), i)).collect(), bounds: None, ..l.clone() };
        let read = library_announce(&library_app_data(&long)).unwrap().1.unwrap();
        assert_eq!(read.name.len(), 32);
        assert!(!read.has.is_empty() && read.has.len() <= HAS_MAX && library_app_data(&long).len() <= APP_DATA_MAX);
        // A node's announce isn't a library's; a newer one says only its v.
        assert_eq!(library_announce(&node_app_data(600, None, true)), None);
        let mut newer = Vec::new();
        write_map_len(&mut newer, 2);
        write_str(&mut newer, "future");
        write_int(&mut newer, 7);
        write_str(&mut newer, "v");
        write_int(&mut newer, 2);
        assert_eq!(library_announce(&newer), Some((2, None)));
        assert_eq!(library_announce(b"retifs/v0"), None);
    }

    #[test]
    fn holding_nothing() {
        let data = node_app_data(600, Some([7; 8]), false);
        assert_eq!(&data[..1], &[0x84]);
        assert_eq!(&data[15..21], &[0xa4, b'h', b'o', b'l', b'd', 0xc2]);
        let a = node_announce(&data);
        assert!(a.holds_nothing && a.site == Some([7; 8]) && a.announce_s == Some(600));
        assert!(!node_announce(&node_app_data(600, None, true)).holds_nothing);
    }
}
