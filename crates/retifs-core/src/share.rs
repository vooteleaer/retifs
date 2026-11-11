//! Shares (ADR-0021): a selection of a source namespace's records, copied
//! into a namespace of its own and kept up to date by the owner's nodes.
//!
//! A copy's record ID is derived from the source record's ID and the share
//! namespace, so every owner node that keeps the share writes the same
//! records (equal writes merge to one state), and a member can't tell the
//! source ID from it:
//!
//! ```text
//! share_id = HKDF-SHA256(ikm = source record ID, salt = "retifs/v1/share-record",
//!                        info = the share namespace's ns_id)[0..16]
//! ```
//!
//! Two shares of one source have unrelated IDs for the same record.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::{channel::NsId, record::RecordId, record::Value};

const SHARE_RECORD_SALT: &[u8] = b"retifs/v1/share-record";
const WRITEBACK_SALT: &[u8] = b"retifs/v1/share-writeback";

/// The `type` of a share's definition record, kept in the source namespace.
pub const DEFINITION_TYPE: &str = "retifs.share";

/// The ID of `source`'s copy in the share namespace `share`.
pub fn record_id(source: &RecordId, share: &NsId) -> RecordId {
    let mut out = [0u8; 16];
    Hkdf::<Sha256>::new(Some(SHARE_RECORD_SALT), source).expand(share, &mut out).expect("16 bytes is a valid HKDF output length");
    out
}

/// The ID in the source namespace of a record a member added to the share
/// `share` (write-back, ADR-0021): derived, so every owner node that keeps
/// the share writes the addition as the same record (equal writes merge).
///
/// ```text
/// source_id = HKDF-SHA256(ikm = the member's record ID, salt = "retifs/v1/share-writeback",
///                         info = the share namespace's ns_id)[0..16]
/// ```
pub fn writeback_id(member_record: &RecordId, share: &NsId) -> RecordId {
    let mut out = [0u8; 16];
    Hkdf::<Sha256>::new(Some(WRITEBACK_SALT), member_record).expand(share, &mut out).expect("16 bytes is a valid HKDF output length");
    out
}

/// Attributes a share leaves out unless asked to keep them: where a photo
/// was taken says where someone lives (ADR-0021, default filters).
pub const DEFAULT_OMIT: &[&str] = &["geo"];

/// What a new share leaves out: `omit`, and the defaults not in `keep`.
pub fn with_default_omit(mut omit: Vec<String>, keep: &[String]) -> Vec<String> {
    for d in DEFAULT_OMIT {
        if !keep.iter().any(|k| k == d) && !omit.iter().any(|o| o == d) {
            omit.push(d.to_string());
        }
    }
    omit
}

/// Whether attribute `key` is left out by `omit`: an exact key, or a prefix
/// ending in `*` (`exif:gps*`).
pub fn omitted(key: &str, omit: &[String]) -> bool {
    omit.iter().any(|o| match o.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => key == o,
    })
}

/// A source record's attributes as copied into a share: without those
/// `omit` names, and never this owner's keep tags (`keep`, `keep:<device>`:
/// what the owner's devices hold says nothing about the members').
pub fn copy_attrs(attrs: &BTreeMap<String, Value>, omit: &[String]) -> BTreeMap<String, Value> {
    attrs.iter().filter(|(k, _)| *k != "keep" && !k.starts_with("keep:") && !omitted(k, omit)).map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_depend_on_both_and_differ_from_the_source() {
        let a = record_id(&[1; 16], &[7; 16]);
        assert_eq!(a, record_id(&[1; 16], &[7; 16]));
        assert_ne!(a, record_id(&[2; 16], &[7; 16]));
        assert_ne!(a, record_id(&[1; 16], &[8; 16]));
        assert_ne!(a, [1; 16]);
    }

    #[test]
    fn copies_leave_out_keep_tags_and_omitted_keys() {
        let attrs: BTreeMap<String, Value> = [
            ("path", Value::Str("/a.jpg".into())),
            ("keep", Value::Bool(true)),
            ("keep:laptop", Value::Bool(true)),
            ("keeper", Value::Str("not a tag".into())),
            ("geo", Value::Str("59.6,24.9".into())),
            ("exif:gps_lat", Value::Float(59.6)),
            ("exif:model", Value::Str("X".into())),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let copy = copy_attrs(&attrs, &["geo".into(), "exif:gps*".into()]);
        assert_eq!(copy.keys().map(String::as_str).collect::<Vec<_>>(), ["exif:model", "keeper", "path"]);
    }
}

#[cfg(test)]
mod default_omit_tests {
    use super::*;

    #[test]
    fn location_left_out_unless_kept() {
        assert_eq!(with_default_omit(vec![], &[]), vec!["geo".to_string()]);
        assert_eq!(with_default_omit(vec!["exif.*".into()], &[]), vec!["exif.*".to_string(), "geo".into()]);
        assert!(with_default_omit(vec![], &["geo".into()]).is_empty());
        assert_eq!(with_default_omit(vec!["geo".into()], &[]), vec!["geo".to_string()]);
    }
}
