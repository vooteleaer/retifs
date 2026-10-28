//! The local record database (ADR-0016): records, attribute index, queries.

use std::collections::BTreeMap;

use retifs_core::record::{Record, Value};
use retifs_store::{SlabStore, Term};

fn store() -> (tempfile::TempDir, SlabStore) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = SlabStore::open(dir.path()).unwrap();
    st.set_sync(false);
    (dir, st)
}

fn rec(id: u8, attrs: &[(&str, Value)]) -> Record {
    Record { id: [id; 16], attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect::<BTreeMap<_, _>>(), blocks: vec![] }
}

fn ids(rs: Vec<Record>) -> Vec<u8> {
    rs.iter().map(|r| r.id[0]).collect()
}

fn q(st: &SlabStore, query: &str) -> Vec<u8> {
    let terms: Vec<Term> = query.split_whitespace().map(|t| Term::parse(t).unwrap()).collect();
    ids(st.query("photos", &terms).unwrap())
}

#[test]
fn queries_match_befs_style_terms() {
    let (_d, st) = store();
    let s = |v: &str| Value::Str(v.into());
    st.put_record("photos", &rec(1, &[("type", s("image")), ("album", s("Prangli 2026")), ("width", Value::Int(4000)), ("tags", Value::List(vec![s("sea"), s("boat")]))])).unwrap();
    st.put_record("photos", &rec(2, &[("type", s("image")), ("album", s("Tallinn")), ("width", Value::Int(1200)), ("rating", Value::Float(-1.5))])).unwrap();
    st.put_record("photos", &rec(3, &[("type", s("document")), ("name", s("notes")), ("width", Value::Int(-5))])).unwrap();
    st.put_record("other", &rec(9, &[("type", s("image"))])).unwrap();

    assert_eq!(q(&st, "type=image"), vec![1, 2], "per namespace");
    assert_eq!(q(&st, "type=image width>2000"), vec![1]);
    assert_eq!(q(&st, "width>=-5 width<1200"), vec![3], "negative ints order correctly");
    assert_eq!(q(&st, "width<=1200"), vec![2, 3]);
    assert_eq!(q(&st, "album^=Pran"), vec![1]);
    assert_eq!(q(&st, "tags=boat"), vec![1], "list values are indexed per element");
    assert_eq!(q(&st, "has:rating"), vec![2]);
    assert_eq!(q(&st, "rating<0"), Vec::<u8>::new(), "an int bound doesn't match a float value");
    assert_eq!(q(&st, "rating<0.0"), vec![2]);
    assert_eq!(q(&st, ""), vec![1, 2, 3], "no terms: everything");

    // Replacing a record reindexes it; deleting removes it from queries.
    st.put_record("photos", &rec(1, &[("type", s("document"))])).unwrap();
    assert_eq!(q(&st, "type=image"), vec![2]);
    assert_eq!(q(&st, "tags=boat"), Vec::<u8>::new());
    assert!(st.delete_record("photos", &[2; 16]).unwrap());
    assert_eq!(q(&st, "type=image"), Vec::<u8>::new());
    assert_eq!(q(&st, "type=document"), vec![1, 3]);

    // A snapshot replaces the namespace.
    st.replace_namespace("photos", &[rec(7, &[("type", s("image"))])]).unwrap();
    assert_eq!(q(&st, ""), vec![7]);
    assert_eq!(st.namespaces().unwrap(), vec!["other".to_string(), "photos".to_string()]);
}

#[test]
fn values_parse_like_typed_literals() {
    use retifs_store::parse_value;
    assert_eq!(parse_value("42"), Value::Int(42));
    assert_eq!(parse_value("-1.5"), Value::Float(-1.5));
    assert_eq!(parse_value("true"), Value::Bool(true));
    assert_eq!(parse_value("\"42\""), Value::Str("42".into()));
    assert_eq!(parse_value("hello world"), Value::Str("hello world".into()));
    assert_eq!(Term::parse("has:name").unwrap(), Term::Has("name".into()));
    assert!(Term::parse("=x").is_err());
}

#[test]
fn in_memory_matching_agrees_with_the_index() {
    let (_d, st) = store();
    let s = |v: &str| Value::Str(v.into());
    let recs = vec![
        rec(1, &[("type", s("image")), ("album", s("Prangli 2026")), ("width", Value::Int(4000)), ("tags", Value::List(vec![s("sea"), s("boat")]))]),
        rec(2, &[("type", s("image")), ("album", s("Tallinn")), ("width", Value::Int(1200)), ("rating", Value::Float(-1.5))]),
        rec(3, &[("type", s("document")), ("name", s("notes")), ("width", Value::Int(-5))]),
    ];
    for r in &recs {
        st.put_record("photos", r).unwrap();
    }
    for query in ["type=image", "type=image width>2000", "width>=-5 width<1200", "album^=Pran", "tags=boat", "has:rating", "rating<0", "rating<0.0", ""] {
        let terms: Vec<Term> = query.split_whitespace().map(|t| Term::parse(t).unwrap()).collect();
        let by_index = ids(st.query("photos", &terms).unwrap());
        let in_memory: Vec<u8> = recs.iter().filter(|r| terms.iter().all(|t| t.matches(r))).map(|r| r.id[0]).collect();
        assert_eq!(by_index, in_memory, "{query}");
    }
}

#[test]
fn namespace_info_member_channels_and_writer_heads() {
    use retifs_core::{Cid, Seed};
    use retifs_store::WriterHead;
    let (_d, st) = store();
    st.set_ns_info("shared", &[1; 32], &[2; 32]).unwrap();
    assert_eq!(st.ns_info("shared").unwrap(), Some(([1; 32], [2; 32])));
    assert_eq!(st.ns_info("other").unwrap(), None);
    st.set_member_channel("ns:shared", &[3; 16]).unwrap();
    assert_eq!(st.member_channel("ns:shared").unwrap(), Some([3; 16]));
    let h = |w: u8| WriterHead { writer: [w; 32], head: vec![w; 258], commit: (Cid::of(&[w]), Seed([w; 32])) };
    st.set_writer_head(&[3; 16], &h(5)).unwrap();
    st.set_writer_head(&[3; 16], &h(6)).unwrap();
    st.set_writer_head(&[4; 16], &h(7)).unwrap();
    assert_eq!(st.writer_heads(&[3; 16]).unwrap(), vec![h(5), h(6)]);
    assert_eq!(st.writer_head(&[3; 16], &[6; 32]).unwrap(), Some(h(6)));

    st.set_ns_identity("shared", &[8; 64]).unwrap();
    assert_eq!(st.ns_identity("shared").unwrap(), Some([8; 64]));
    assert_eq!(st.ns_keys("shared").unwrap(), vec![[2; 32]], "the first key comes from the address");
    assert!(st.add_ns_key("shared", &[9; 32]).unwrap());
    assert!(!st.add_ns_key("shared", &[9; 32]).unwrap(), "known keys aren't added twice");
    assert_eq!(st.ns_keys("shared").unwrap(), vec![[2; 32], [9; 32]]);
}


/// Found by the scale test: `album=a7` also returned `a74` and `a76`
/// (string values have no terminator in the index keys).
#[test]
fn string_terms_match_exactly_not_by_prefix() {
    let (_d, st) = store();
    let s = |v: &str| Value::Str(v.into());
    for (id, a) in [(1, "a7"), (2, "a74"), (3, "a70"), (4, "a8"), (5, "a6zz")] {
        st.put_record("photos", &rec(id, &[("album", s(a))])).unwrap();
    }
    assert_eq!(q(&st, "album=a7"), vec![1]);
    assert_eq!(q(&st, "album<=a7"), vec![1, 5]);
    assert_eq!(q(&st, "album<a7"), vec![5]);
    assert_eq!(q(&st, "album>a7"), vec![2, 3, 4]);
    assert_eq!(q(&st, "album>=a7"), vec![1, 2, 3, 4]);
    assert_eq!(q(&st, "album^=a7"), vec![1, 2, 3]);
}

#[test]
fn leaving_a_namespace_leaves_the_others() {
    let (_d, st) = store();
    let s = |v: &str| Value::Str(v.into());
    // "map" and "map2": one name a prefix of the other, nothing of map2 may go.
    st.put_record("map", &rec(1, &[("type", s("image"))])).unwrap();
    st.put_record("map", &rec(2, &[("type", s("place"))])).unwrap();
    st.put_record("map2", &rec(3, &[("type", s("image"))])).unwrap();
    st.set_ns_info("map", &[1; 32], &[2; 32]).unwrap();
    st.set_ns_info("map2", &[3; 32], &[4; 32]).unwrap();
    st.leave_namespace("map").unwrap();
    assert_eq!(st.namespaces().unwrap(), vec!["map2".to_string()]);
    assert!(st.records("map").unwrap().is_empty() && st.ns_info("map").unwrap().is_none());
    assert_eq!(ids(st.records("map2").unwrap()), vec![3]);
    assert_eq!(ids(st.query("map2", &[Term::parse("type=image").unwrap()]).unwrap()), vec![3]);
    assert!(st.query("map", &[Term::parse("type=image").unwrap()]).unwrap().is_empty(), "its index went too");
    // Joined again later: empty, as new.
    st.put_record("map", &rec(5, &[("type", s("image"))])).unwrap();
    assert_eq!(ids(st.records("map").unwrap()), vec![5]);
}

#[test]
fn a_joined_namespace_without_records_is_listed() {
    let (_d, st) = store();
    st.put_record("photos", &rec(1, &[])).unwrap();
    st.set_ns_info("map", &[1; 32], &[2; 32]).unwrap();
    assert_eq!(st.namespaces().unwrap(), vec!["map".to_string(), "photos".to_string()], "joined lazily, nothing fetched yet: still here");
    st.leave_namespace("map").unwrap();
    assert_eq!(st.namespaces().unwrap(), vec!["photos".to_string()]);
}
