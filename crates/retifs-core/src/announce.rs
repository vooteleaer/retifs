//! What a `retifs.node` announce carries in its app data (ADR-0014): how
//! often the node announces, so others can tell a node that went quiet from
//! one that announces rarely, and, if its owner said, which site it's at, so
//! copies can be kept in more than one place. Canonical msgpack, a map so it
//! can grow (keys in order; `site` only when set):
//!
//! ```text
//! { "announce_s": uint, "site": bin 8, "v": 1 }
//! ```
//!
//! The site is a tag, not the name: the first 8 bytes of
//! SHA-256("retifs.site" ‖ 0x00 ‖ the name, trimmed and lowercased). Nodes
//! with the same name are at the same site; a name others might also use
//! ("home") makes their nodes look like the same site too, which only costs
//! diversity, so a name of one's own is better ("prangli-home").
//!
//! Nodes before this sent `retifs/v0` (no interval known).

use sha2::{Digest, Sha256};

use crate::record::{write_bin, write_int, write_map_len, write_str, Reader, Value};

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
}

/// The interval assumed for a node that doesn't say (and the default).
pub const DEFAULT_ANNOUNCE_S: u32 = 600;

/// A node's announce app data, announcing every `announce_s` seconds, at
/// `site` if its owner named one.
pub fn node_app_data(announce_s: u32, site: Option<SiteTag>) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_len(&mut out, if site.is_some() { 3 } else { 2 });
    write_str(&mut out, "announce_s");
    write_int(&mut out, announce_s as i64);
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
            _ => {}
        }
    }
    out
}

/// The announce interval a node's app data states, if any.
pub fn node_announce_s(app_data: &[u8]) -> Option<u32> {
    node_announce(app_data).announce_s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ignores_old_or_odd_data() {
        assert_eq!(node_announce_s(&node_app_data(600, None)), Some(600));
        assert_eq!(node_announce_s(&node_app_data(86_400, None)), Some(86_400));
        // Without a site, as before sites.
        assert_eq!(node_app_data(600, None), [0x82, 0xaa, b'a', b'n', b'n', b'o', b'u', b'n', b'c', b'e', b'_', b's', 0xcd, 0x02, 0x58, 0xa1, b'v', 0x01]);
        assert_eq!(node_announce_s(b"retifs/v0"), None);
        assert_eq!(node_announce_s(&node_app_data(0, None)), None);
        assert_eq!(node_announce_s(&[]), None);
    }

    #[test]
    fn sites() {
        let home = site_tag("Prangli-Home");
        assert_eq!(home, site_tag("  prangli-home "), "trimmed, any case");
        assert_ne!(home, site_tag("prangli-cabin"));
        let a = node_announce(&node_app_data(600, Some(home)));
        assert_eq!(a, NodeAnnounce { announce_s: Some(600), site: Some(home) });
        let data = node_app_data(600, Some([7; 8]));
        assert_eq!(&data[..1], &[0x83]);
        assert_eq!(&data[15..27], &[0xa4, b's', b'i', b't', b'e', 0xc4, 0x08, 7, 7, 7, 7, 7]);
        assert_eq!(node_announce(&node_app_data(600, None)).site, None);
        // A site of the wrong size is no site.
        let mut odd = Vec::new();
        write_map_len(&mut odd, 1);
        write_str(&mut odd, "site");
        write_bin(&mut odd, &[1, 2, 3]);
        assert_eq!(node_announce(&odd), NodeAnnounce::default());
    }
}
