//! What a `retifs.node` announce carries in its app data (ADR-0014): how
//! often the node announces, so others can tell a node that went quiet from
//! one that announces rarely. Canonical msgpack, a map so it can grow:
//!
//! ```text
//! { "announce_s": uint, "v": 1 }
//! ```
//!
//! Nodes before this sent `retifs/v0` (no interval known).

use crate::record::{write_int, write_map_len, write_str, Reader, Value};

/// The interval assumed for a node that doesn't say (and the default).
pub const DEFAULT_ANNOUNCE_S: u32 = 600;

/// A node's announce app data, announcing every `announce_s` seconds.
pub fn node_app_data(announce_s: u32) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_len(&mut out, 2);
    write_str(&mut out, "announce_s");
    write_int(&mut out, announce_s as i64);
    write_str(&mut out, "v");
    write_int(&mut out, 1);
    out
}

/// The announce interval a node's app data states, if any. Anything else
/// (an older node's `retifs/v0`, unknown fields, other versions) is None.
pub fn node_announce_s(app_data: &[u8]) -> Option<u32> {
    let mut r = Reader(app_data);
    let n = r.map_len().ok()?;
    let mut every = None;
    for _ in 0..n {
        let key = r.str().ok()?;
        let v = r.value(1).ok()?;
        if key == "announce_s"
            && let Value::Int(i) = v
        {
            every = u32::try_from(i).ok().filter(|s| *s > 0);
        }
    }
    every
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ignores_old_or_odd_data() {
        assert_eq!(node_announce_s(&node_app_data(600)), Some(600));
        assert_eq!(node_announce_s(&node_app_data(86_400)), Some(86_400));
        assert_eq!(node_app_data(600), [0x82, 0xaa, b'a', b'n', b'n', b'o', b'u', b'n', b'c', b'e', b'_', b's', 0xcd, 0x02, 0x58, 0xa1, b'v', 0x01]);
        assert_eq!(node_announce_s(b"retifs/v0"), None);
        assert_eq!(node_announce_s(&node_app_data(0)), None);
        assert_eq!(node_announce_s(&[]), None);
    }
}
