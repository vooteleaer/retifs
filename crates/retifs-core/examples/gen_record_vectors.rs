//! Regenerates `test-vectors/record-v1.json` (irreversible decision 2: canonical serialization).
//!
//!     cargo run -p retifs-core --example gen_record_vectors > crates/retifs-core/test-vectors/record-v1.json

use std::collections::BTreeMap;

use retifs_core::{
    record::{encode_value, Record, Snapshot, Value},
    Cid, FileRef, Seed,
};
use serde_json::{json, Value as J};

/// Tagged JSON, so the checker can rebuild the exact msgpack types.
fn tagged(v: &Value) -> J {
    match v {
        Value::Null => json!({"t": "nil"}),
        Value::Bool(b) => json!({"t": "bool", "v": b}),
        Value::Int(i) => json!({"t": "int", "v": i}),
        Value::Float(f) => json!({"t": "float", "v": f}),
        Value::Str(s) => json!({"t": "str", "v": s}),
        Value::Bytes(b) => json!({"t": "bin", "v": hex::encode(b)}),
        Value::List(items) => json!({"t": "list", "v": items.iter().map(tagged).collect::<Vec<_>>()}),
    }
}

fn record(id: u8, attrs: Vec<(&str, Value)>, blocks: Vec<FileRef>) -> Record {
    Record { id: [id; 16], attrs: attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<BTreeMap<_, _>>(), blocks }
}

fn record_json(r: &Record) -> J {
    json!({
        "id": hex::encode(r.id),
        "attrs": r.attrs.iter().map(|(k, v)| (k.clone(), tagged(v))).collect::<serde_json::Map<_, _>>(),
        "blocks": r.blocks.iter().map(|b| json!([b.root.to_string(), hex::encode(b.seed.0), b.size])).collect::<Vec<_>>(),
        "encoded": hex::encode(r.encode()),
    })
}

fn main() {
    let values = vec![
        Value::Null,
        Value::Bool(true),
        Value::Int(0),
        Value::Int(127),
        Value::Int(128),
        Value::Int(65535),
        Value::Int(65536),
        Value::Int(1 << 40),
        Value::Int(-1),
        Value::Int(-32),
        Value::Int(-33),
        Value::Int(-129),
        Value::Int(i64::MIN),
        Value::Float(0.1),
        Value::Float(-2.0),
        Value::Str(String::new()),
        Value::Str("a".repeat(31)),
        Value::Str("b".repeat(32)),
        Value::Str("täpitähed".into()),
        Value::Bytes(vec![]),
        Value::Bytes(vec![7; 300]),
        Value::List(vec![Value::Int(1), Value::List(vec![Value::Str("x".into())])]),
    ];
    let page = FileRef { root: Cid::of(b"index.mu"), seed: Seed([0x42; 32]), size: 812 };
    let r1 = record(
        0x01,
        vec![
            ("path", Value::Str("/page/index.mu".into())),
            ("type", Value::Str("page".into())),
            ("mime", Value::Str("text/micron".into())),
            ("size", Value::Int(812)),
        ],
        vec![page],
    );
    let r2 = record(0x02, vec![("name", Value::Str("Prangli 2026".into())), ("tags", Value::List(vec![]))], vec![]);
    let snap = Snapshot::new(vec![r2.clone(), r1.clone()]).unwrap();

    let doc = json!({
        "construction": "retifs records v1 (ADR-0016, decision 2: canonical msgpack, proposed)",
        "values": values.iter().map(|v| json!({"value": tagged(v), "encoded": hex::encode(encode_value(v))})).collect::<Vec<_>>(),
        "records": [record_json(&r1), record_json(&r2)],
        "snapshot": hex::encode(snap.encode()),
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
