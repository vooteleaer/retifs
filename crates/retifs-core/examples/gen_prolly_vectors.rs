//! Regenerates `test-vectors/prolly-v1.json` (ADR-0018: stamped records and Prolly trees).
//!
//!     cargo run -p retifs-core --example gen_prolly_vectors > crates/retifs-core/test-vectors/prolly-v1.json

use std::collections::HashMap;

use retifs_core::{
    ops::{Stamp, StampedRecord},
    prolly,
    record::{RecordId, Value},
    Cid, ConvergenceSecret, FileRef, Seed, Store,
};
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct Mem(HashMap<Cid, Vec<u8>>);
impl Store for Mem {
    type Error = std::convert::Infallible;
    fn put(&mut self, cid: Cid, ct: Vec<u8>) -> Result<(), Self::Error> {
        self.0.insert(cid, ct);
        Ok(())
    }
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.get(cid).cloned())
    }
}

/// Key i: SHA-256(u32_be(i) ‖ 12 zero bytes)[..16].
fn key(i: u32) -> RecordId {
    let mut k = [0u8; 16];
    k[..4].copy_from_slice(&i.to_be_bytes());
    Sha256::digest(k)[..16].try_into().unwrap()
}

/// msgpack str "value <i>" (always under 32 bytes: fixstr).
fn small(i: u32) -> Vec<u8> {
    let s = format!("value {i}");
    [vec![0xa0 | s.len() as u8], s.into_bytes()].concat()
}

/// msgpack bin 16 of `n` bytes all equal to (i mod 256).
fn large(i: u32, n: usize) -> Vec<u8> {
    [vec![0xc5], (n as u16).to_be_bytes().to_vec(), vec![i as u8; n]].concat()
}

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

fn stamp(s: &Stamp) -> J {
    json!([s.0, hex::encode(s.1), s.2, s.3])
}

fn tree(secret: &ConvergenceSecret, entries: Vec<(RecordId, Vec<u8>)>) -> J {
    let mut store = Mem::default();
    let (cid, seed) = prolly::build(&mut store, secret, entries).unwrap().unwrap();
    let mut nodes: Vec<String> = store.0.keys().map(|c| c.to_string()).collect();
    nodes.sort();
    json!({"root_cid": cid.to_string(), "root_seed": hex::encode(seed.0), "nodes": nodes})
}

fn main() {
    let secret_bytes = [0x7au8; 32];
    let secret = ConvergenceSecret::personal(secret_bytes);
    let (a, b) = ([0xa1u8; 32], [0xb0u8; 32]);

    // Stamped records: empty-ish, full, and a tombstone with an unset field.
    let mut full = StampedRecord { live: Some((1000, a, 1, 0)), ..Default::default() };
    full.fields.insert("path".into(), ((1000, a, 1, 1), Some(Value::Str("/index.mu".into()))));
    full.fields.insert("size".into(), ((2500, b, 3, 0), Some(Value::Int(-70000))));
    full.fields.insert("tags".into(), ((2500, b, 3, 1), Some(Value::List(vec![Value::Bool(true), Value::Float(0.5), Value::Null]))));
    full.blocks = Some(((1000, a, 1, 2), vec![FileRef { root: Cid::of(b"index.mu"), seed: Seed([0x42; 32]), size: 812 }]));
    let mut gone = StampedRecord { live: Some((1000, a, 1, 0)), deleted: Some((u64::from(u32::MAX) + 5, b, 300, 7)), ..Default::default() };
    gone.fields.insert("title".into(), ((4000, a, 2, 0), None));
    let only_live = StampedRecord { live: Some((5, b, 1, 0)), ..Default::default() };
    let srecs: Vec<(RecordId, StampedRecord)> = vec![([0x01; 16], full), ([0x02; 16], gone), ([0x03; 16], only_live)];
    for (_, r) in &srecs {
        assert_eq!(&StampedRecord::decode(&r.encode()).unwrap(), r);
    }
    let srec_json: Vec<J> = srecs
        .iter()
        .map(|(id, r)| {
            json!({
                "id": hex::encode(id),
                "live": r.live.as_ref().map(stamp),
                "deleted": r.deleted.as_ref().map(stamp),
                "fields": r.fields.iter().map(|(k, (s, x))| json!([k, stamp(s), x.as_ref().map(v)])).collect::<Vec<_>>(),
                "blocks": r.blocks.as_ref().map(|(s, refs)| json!([stamp(s), refs.iter().map(|b| json!([b.root.to_string(), hex::encode(b.seed.0), b.size])).collect::<Vec<_>>()])),
                "encoded": hex::encode(r.encode()),
            })
        })
        .collect();

    // Tree 1: 2000 small entries plus the stamped records (three levels).
    let mut small_entries: Vec<(RecordId, Vec<u8>)> = (0..2000).map(|i| (key(i), small(i))).collect();
    small_entries.extend(srecs.iter().map(|(id, r)| (*id, r.encode())));
    small_entries.sort_by_key(|(k, _)| *k);
    // Tree 2: the same with entry 1234 changed (shares all but one leaf's path).
    let mut changed = small_entries.clone();
    let pos = changed.iter().position(|(k, _)| *k == key(1234)).unwrap();
    changed[pos].1 = vec![0x07];
    // Tree 3: 60 entries of 4000 bytes, so the size cut closes leaves.
    let mut large_entries: Vec<(RecordId, Vec<u8>)> = (0..60).map(|i| (key(i), large(i, 4000))).collect();
    large_entries.sort_by_key(|(k, _)| *k);

    let doc = json!({
        "description": "retifs Prolly trees v1 (ADR-0018). Stamped records are canonical msgpack; a tree's nodes are sealed (ADR-0008) under `secret` with the personal scheme. Entry keys: SHA-256(u32_be(i) ‖ 12 zero bytes)[..16]; small values: msgpack str \"value <i>\"; large values: msgpack bin 16 of 4000 bytes equal to i mod 256.",
        "fanout": prolly::FANOUT,
        "max_node": prolly::MAX_NODE,
        "secret": hex::encode(secret_bytes),
        "stamped_records": srec_json,
        "trees": [
            {"name": "small", "count": 2000, "kind": "small", "with_stamped": true, "changed": null, "result": tree(&secret, small_entries)},
            {"name": "small, entry 1234 = msgpack 7", "count": 2000, "kind": "small", "with_stamped": true, "changed": [1234, "07"], "result": tree(&secret, changed)},
            {"name": "large", "count": 60, "kind": "large", "with_stamped": false, "changed": null, "result": tree(&secret, large_entries)},
        ],
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
