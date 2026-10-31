//! Haiku People's attributes on contacts (ADR-0025). A contact
//! (`application/x-person`) keeps the keys every retifs app reads (`name`,
//! `org`, `phone:work`, …); People and Tracker read and write `META:name`,
//! `META:company`, `META:wphone`. Each `META:` attribute is a view of the key
//! the record has: the first of its candidates present, else the first
//! (where a new value goes).

/// People's attributes and the record keys they show, most specific first.
const PEOPLE: [(&str, &[&str]); 15] = [
    ("META:name", &["name"]),
    ("META:nickname", &["nickname"]),
    ("META:company", &["org"]),
    ("META:address", &["address", "address:home"]),
    ("META:city", &["city"]),
    ("META:state", &["state"]),
    ("META:zip", &["zip"]),
    ("META:country", &["country"]),
    ("META:hphone", &["phone:home", "phone"]),
    ("META:wphone", &["phone:work"]),
    ("META:mphone", &["phone:mobile", "phone:cell"]),
    ("META:fax", &["phone:fax"]),
    ("META:email", &["email", "email:home"]),
    ("META:url", &["url"]),
    ("META:group", &["group"]),
];

/// The record key `attr` (a People attribute) reads and writes, given the
/// keys the record has; None if `attr` isn't one of People's.
pub fn key_for(attr: &str, has: impl Fn(&str) -> bool) -> Option<&'static str> {
    let (_, keys) = PEOPLE.iter().find(|(a, _)| *a == attr)?;
    Some(keys.iter().copied().find(|k| has(k)).unwrap_or(keys[0]))
}

/// The People attributes a record with these keys shows: (attribute, key).
/// A key goes to one attribute only (a lone `phone` is the home phone).
pub fn shown(has: impl Fn(&str) -> bool) -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&'static str, &'static str)> = Vec::new();
    for (attr, keys) in PEOPLE {
        if let Some(k) = keys.iter().copied().find(|k| has(k) && !out.iter().any(|(_, used)| used == k)) {
            out.push((attr, k));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn people_attributes_are_views_of_keys() {
        let keys = ["name", "phone", "phone:work", "email:home"];
        let has = |k: &str| keys.contains(&k);
        assert_eq!(key_for("META:hphone", has), Some("phone"));
        assert_eq!(key_for("META:wphone", has), Some("phone:work"));
        assert_eq!(key_for("META:email", has), Some("email:home"));
        // Not there yet: where People's value goes.
        assert_eq!(key_for("META:mphone", has), Some("phone:mobile"));
        assert_eq!(key_for("META:company", has), Some("org"));
        assert_eq!(key_for("name", has), None);
        let s = shown(has);
        assert_eq!(s, [("META:name", "name"), ("META:hphone", "phone"), ("META:wphone", "phone:work"), ("META:email", "email:home")]);
    }
}
