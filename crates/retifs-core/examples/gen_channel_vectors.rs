//! Regenerates `test-vectors/channel-v1.json` (irreversible decisions 5 and 8).
//!
//!     cargo run -p retifs-core --example gen_channel_vectors > crates/retifs-core/test-vectors/channel-v1.json

use retifs_core::{
    channel::{ChannelKey, Commit, Head},
    Cid, FileRef, Seed,
};
use serde_json::json;

fn main() {
    let key = ChannelKey::from_secrets(std::array::from_fn(|i| 0x30 + i as u8), std::array::from_fn(|i| 0x60 + i as u8));
    let addr = key.addr();
    let root1 = FileRef { root: Cid::of(b"tree v1"), seed: Seed([0x11; 32]), size: 1000 };
    let root2 = FileRef { root: Cid::of(b"tree v2"), seed: Seed([0x22; 32]), size: 2000 };
    let (c1, s1) = Commit::create(&key, 1, 1_790_000_000_000, None, root1);
    let (c2, s2) = Commit::create(&key, 2, 1_790_000_060_000, Some((s1.cid, s1.seed)), root2);
    let iv = [0x77u8; 16];
    let head = Head::sign(&key, 2, 1_790_000_060, s2.cid, &s2.seed, iv);

    let commit = |c: &Commit, s: &retifs_core::Sealed| {
        json!({
            "seq": c.seq,
            "time_ms": c.time_ms,
            "body_and_sig": hex::encode(c.encode()),
            "chunk_cid": s.cid.to_string(),
            "chunk_seed": hex::encode(s.seed.0),
            "chunk": hex::encode(&s.ciphertext),
            "root_cid": c.root.root.to_string(),
            "root_seed": hex::encode(c.root.seed.0),
            "root_size": c.root.size,
        })
    };
    let doc = json!({
        "construction": "retifs channels v1 (ADR-0015, decisions 5 and 8, proposed)",
        "writer_seed": hex::encode(key.signing_seed()),
        "read_key": hex::encode(addr.read_key),
        "writer": hex::encode(addr.writer),
        "ns_id": hex::encode(addr.ns_id()),
        "address": addr.to_string(),
        "commits": [commit(&c1, &s1), commit(&c2, &s2)],
        "head_iv": hex::encode(iv),
        "head": hex::encode(head.encode()),
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
