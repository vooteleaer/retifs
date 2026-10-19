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

