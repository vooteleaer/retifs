//! Haiku's media attributes on any record (ADR-0023): Tracker's audio and
//! image columns and MediaPlayer read `Audio:Artist`, `Media:Width` and the
//! like; retifs keeps the keys every app reads (`audio.artist`, `width`, as
//! the extractor writes them). Each Haiku attribute is a view of its key,
//! read and written through it, and queries on it ask for the key.

use libretifs::AttrValue;

/// Haiku's attribute, the record key it shows, and whether Haiku types it
/// as a 32-bit integer (the others are strings).
const MEDIA: [(&str, &str, bool); 8] = [
    ("Audio:Artist", "audio.artist", false),
    ("Audio:Album", "audio.album", false),
    ("Media:Title", "audio.title", false),
    ("Audio:Genre", "audio.genre", false),
    ("Audio:Track", "audio.track", true),
    ("Audio:Year", "audio.year", true),
    ("Media:Width", "width", true),
    ("Media:Height", "height", true),
];

/// The record key Haiku attribute `attr` is a view of, if it's one of these.
pub fn key_for(attr: &str) -> Option<&'static str> {
    MEDIA.iter().find(|(a, _, _)| *a == attr).map(|(_, k, _)| *k)
}

/// The Haiku attributes a record with these keys shows: (attribute, key).
pub fn shown(has: impl Fn(&str) -> bool) -> Vec<(&'static str, &'static str)> {
    MEDIA.iter().filter(|(_, k, _)| has(k)).map(|(a, k, _)| (*a, *k)).collect()
}

/// A value as Haiku attribute `attr` expects it: an integer one as
/// `B_INT32_TYPE` when it fits, so Tracker sorts and shows it.
pub fn haiku_value(attr: &str, v: &AttrValue) -> crate::volume::Attr {
    let int32 = MEDIA.iter().any(|(a, _, i)| *a == attr && *i);
    match v {
        AttrValue::Int(i) if int32 && i32::try_from(*i).is_ok() => {
            crate::volume::Attr { type_code: crate::types::B_INT32_TYPE, data: (*i as i32).to_ne_bytes().to_vec() }
        }
        other => crate::volume::haiku_attr(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_attributes_are_views_of_keys() {
        assert_eq!(key_for("Audio:Artist"), Some("audio.artist"));
        assert_eq!(key_for("Media:Width"), Some("width"));
        assert_eq!(key_for("audio.artist"), None);
        let keys = ["width", "height", "camera"];
        assert_eq!(shown(|k| keys.contains(&k)), [("Media:Width", "width"), ("Media:Height", "height")]);
        let w = haiku_value("Media:Width", &AttrValue::Int(4032));
        assert_eq!((w.type_code, w.data), (crate::types::B_INT32_TYPE, 4032i32.to_ne_bytes().to_vec()));
        // Not an integer view, or too large for one: as retifs values go.
        assert_eq!(haiku_value("Audio:Artist", &AttrValue::Str("Arvo Pärt".into())).type_code, crate::types::B_STRING_TYPE);
        assert_eq!(haiku_value("Audio:Year", &AttrValue::Int(1 << 40)).type_code, crate::types::B_INT64_TYPE);
    }
}
