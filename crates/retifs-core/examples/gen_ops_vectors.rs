//! Regenerates `test-vectors/ops-v1.json` (ADR-0017: operations file and merge).
//!
//!     cargo run -p retifs-core --example gen_ops_vectors > crates/retifs-core/test-vectors/ops-v1.json

use std::collections::BTreeMap;

use retifs_core::{
    ops::{merge, Op, OpsFile, Right, WriterCommit},
    record::{Snapshot, Value},
    Cid, FileRef, Seed,
};
use serde_json::{json, Value as J};

fn v(x: &Value) -> J {
    match x {
        Value::Null => json!({"t": "nil"}),
        Value::Bool(b) => json!({"t": "bool", "v": b}),
        Value::Int(i) => json!({"t": "int", "v": i}),
        Value::Float(f) => json!({"t": "float", "v": f}),
        Value::Str(s) => json!({"t": "str", "v": s}),
        Value::Bytes(b) => json!({"t": "bin", "v": hex::encode(b)}),
        Value::List(items) => json!({"t": "list", "v": items.iter().map(v).collect::<Vec<_>>()}),
    }
}

fn op(o: &Op) -> J {
    match o {
        Op::Set(id, k, x) => json!(["set", hex::encode(id), k, v(x)]),
        Op::Unset(id, k) => json!(["unset", hex::encode(id), k]),
        Op::Blocks(id, bs) => json!([
            "blocks",
            hex::encode(id),
            bs.iter().map(|b| json!([b.root.to_string(), hex::encode(b.seed.0), b.size])).collect::<Vec<_>>()
        ]),
        Op::Delete(id) => json!(["delete", hex::encode(id)]),
        Op::Grant(w, rs) => json!([
            "grant",
            hex::encode(w),
            rs.iter().map(|r| if *r == Right::Grant { "grant" } else { "write" }).collect::<Vec<_>>()
        ]),
        Op::Revoke(w) => json!(["revoke", hex::encode(w)]),
    }
}

fn main() {
    let (alice, bob, eve) = ([0xa1u8; 32], [0xb0u8; 32], [0xe5u8; 32]);
    let (page, photo) = ([0x01u8; 16], [0x02u8; 16]);
    let block = FileRef { root: Cid::of(b"index.mu"), seed: Seed([0x42; 32]), size: 812 };
    let s = |x: &str| Value::Str(x.into());
    let mut chains: BTreeMap<[u8; 32], Vec<WriterCommit>> = BTreeMap::new();
    chains.insert(
        alice,
        vec![
            WriterCommit {
                time_ms: 1000,
                ops: vec![
                    Op::Grant(bob, vec![Right::Write]),
                    Op::Set(page, "path".into(), s("/index.mu")),
                    Op::Blocks(page, vec![block]),
                    Op::Set(page, "title".into(), s("Home")),
                ],
            },
            WriterCommit { time_ms: 3000, ops: vec![Op::Set(page, "title".into(), s("Front page")), Op::Revoke(bob)] },
        ],
    );
    chains.insert(
        bob,
        vec![
            WriterCommit {
                time_ms: 2000,
                ops: vec![
                    Op::Set(page, "title".into(), s("A title by Bob")),
                    Op::Set(page, "tags".into(), Value::List(vec![s("home")])),
                    Op::Set(photo, "type".into(), s("image")),
                    Op::Grant(eve, vec![Right::Write]),
                ],
            },
            WriterCommit { time_ms: 4000, ops: vec![Op::Delete(page)] },
        ],
    );
    chains.insert(eve, vec![WriterCommit { time_ms: 2500, ops: vec![Op::Set(photo, "spam".into(), Value::Bool(true))] }]);
    let merged = merge(&alice, &chains, 10_000);
    let snapshot = Snapshot::new(merged.records.clone()).unwrap();

    let doc = json!({
        "construction": "retifs operations v1 (ADR-0017, proposed): ops file canonical msgpack; merge in stamp order (time, writer, index)",
        "creator": hex::encode(alice),
        "now_ms": 10_000,
        "chains": chains.iter().map(|(w, cs)| json!({
            "writer": hex::encode(w),
            "commits": cs.iter().map(|c| json!({
                "time_ms": c.time_ms,
                "ops": c.ops.iter().map(op).collect::<Vec<_>>(),
                "encoded": hex::encode(OpsFile { ops: c.ops.clone() }.encode()),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "merged_snapshot": hex::encode(snapshot.encode()),
        "ignored_ops": merged.ignored_ops,
        "writers_after": merged.writers.keys().map(hex::encode).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
