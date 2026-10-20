//! Regenerates `test-vectors/index-v1.json` (ADR-0019: blind index keys,
//! tokens, entries, and the index tree).
//!
//!     cargo run -p retifs-core --example gen_index_vectors > crates/retifs-core/test-vectors/index-v1.json

use std::collections::HashMap;

use retifs_core::{
    index::{self, IndexKeys},
    prolly,
    record::{RecordId, Value},
    Cid, Store,
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

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

/// Record i: SHA-256("record" ‖ u32_be(i))[..16].
fn id(i: u32) -> RecordId {
    Sha256::digest([b"record".as_slice(), &i.to_be_bytes()].concat())[..16].try_into().unwrap()
}

fn main() {
    let read_key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let keys = IndexKeys::derive(&read_key);
    let search = index::search_secret(&read_key);

    // Tokens over every value type, and an entry for each.
    let cases = [
        ("album", s("Prangli 2026")),
        ("type", s("image")),
        ("n", Value::Int(5)),
        ("n", s("5")),
        ("n", Value::Int(-300)),
        ("n", Value::Int(70000)),
        ("tags:urgent", Value::Bool(true)),
        ("ratio", Value::Float(0.5)),
        ("raw", Value::Bytes(vec![1, 2, 3])),
        ("nimi", s("Pärnu õhtu")),
    ];
    let tokens: Vec<J> = cases
        .iter()
        .enumerate()
        .map(|(i, (k, x))| {
            let t = keys.token(k, x);
            let e = keys.entry(&t, &id(i as u32));
            assert_eq!(keys.open_entry(&t, &e), id(i as u32));
            json!({"key": k, "value": v(x), "token": hex::encode(t), "record": hex::encode(id(i as u32)), "entry": hex::encode(e)})
        })
        .collect();

    // A namespace: settings, 400 records, an index of the declared keys.
    let settings = vec![("type".to_string(), s(index::SETTINGS_TYPE)), ("keys".to_string(), Value::List(vec![s("album"), s("type"), s("tags:*")]))];
    let mut records: Vec<(RecordId, Vec<(String, Value)>)> = vec![(id(1_000_000), settings)];
    for i in 0..400u32 {
        let mut attrs = vec![("type".to_string(), s(if i % 3 == 0 { "image" } else { "note" })), ("title".to_string(), s(&format!("title {i}")))];
        if i % 40 == 1 {
            attrs.push(("album".to_string(), s("Prangli 2026")));
        }
        if i % 97 == 0 {
            attrs.push(("tags".to_string(), Value::List(vec![s("a"), s("b")])));
            attrs.push(("tags:urgent".to_string(), Value::Bool(true)));
        }
        records.push((id(i), attrs));
    }
    let declared = index::declared_keys(records.iter().map(|(_, a)| a.as_slice()));
    let tree_keys = index::index_keys(&keys, records.iter().map(|(i, a)| (*i, a.as_slice())), &declared);
    let mut store = Mem::default();
    let (cid, seed) = index::build(&mut store, &search, tree_keys.clone()).unwrap().unwrap();
    let mut nodes: Vec<String> = store.0.keys().map(|c| c.to_string()).collect();
    nodes.sort();
    let lookups: Vec<J> = [("album", s("Prangli 2026")), ("tags:urgent", Value::Bool(true)), ("title", s("title 3"))]
        .iter()
        .map(|(k, x)| {
            let t = keys.token(k, x);
            let entries = index::lookup(&store, &(cid, seed), &t).unwrap();
            let mut ids: Vec<String> = entries.iter().map(|e| hex::encode(keys.open_entry(&t, e))).collect();
            ids.sort();
            json!({"key": k, "value": v(x), "token": hex::encode(t), "entries": entries.iter().map(hex::encode).collect::<Vec<_>>(), "records": ids})
        })
        .collect();

    // The index channel, a descriptor (fixed IV) and a query proof.
    let ch = index::channel_key(&read_key);
    let checkpoint = retifs_core::FileRef { root: Cid::of(b"checkpoint"), seed: retifs_core::Seed([0x44; 32]), size: 4321 };
    let desc = index::Descriptor { index: Some((cid, seed)), state: keys.seal_state(&checkpoint, [0x66; 16]), time_ms: 1_760_000_000_000 };
    let link_id = [0x77u8; 16];

    let doc = json!({
        "version": 1,
        "fanout": prolly::FANOUT,
        "max_node": prolly::MAX_NODE,
        "read_key": hex::encode(read_key),
        "search_secret": hex::encode(search.as_bytes()),
        "tokens": tokens,
        "namespace": {
            "records": records.iter().map(|(i, attrs)| json!([hex::encode(i), attrs.iter().map(|(k, x)| json!([k, v(x)])).collect::<Vec<_>>()])).collect::<Vec<_>>(),
            "declared": declared,
            "tree_keys": tree_keys.len(),
            "tree_keys_sha256": hex::encode(Sha256::digest(tree_keys.concat())),
            "root_cid": cid.to_string(),
            "root_seed": hex::encode(seed.0),
            "nodes": nodes,
        },
        "lookups": lookups,
        "channel": {
            "address": ch.addr().to_string(),
            "writer": hex::encode(ch.writer()),
            "ns_id": hex::encode(ch.ns_id()),
        },
        "descriptor": {
            "checkpoint": [checkpoint.root.to_string(), hex::encode(checkpoint.seed.0), checkpoint.size],
            "iv": hex::encode([0x66u8; 16]),
            "time_ms": desc.time_ms,
            "encoded": hex::encode(desc.encode()),
        },
        "query_proof": {"link_id": hex::encode(link_id), "proof": hex::encode(index::query_proof(&search, &link_id))},
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
