//! Regenerates `test-vectors/share-v1.json` (ADR-0021: the record IDs of
//! share copies).
//!
//!     cargo run -p retifs-core --example gen_share_vectors > crates/retifs-core/test-vectors/share-v1.json

use retifs_core::{channel, share};
use serde_json::json;
use sha2::{Digest, Sha256};

/// Test input i: SHA-256(label ‖ u32_be(i)), cut to `n` bytes.
fn input<const N: usize>(label: &str, i: u32) -> [u8; N] {
    Sha256::digest([label.as_bytes(), &i.to_be_bytes()].concat())[..N].try_into().unwrap()
}

fn main() {
    let mut cases = Vec::new();
    for i in 0..4u32 {
        let writer: [u8; 32] = input("writer", i / 2);
        let source: [u8; 16] = input("record", i);
        let ns_id = channel::ns_id(&writer);
        cases.push(json!({
            "share_writer": hex::encode(writer),
            "share_ns_id": hex::encode(ns_id),
            "source_record": hex::encode(source),
            "share_record": hex::encode(share::record_id(&source, &ns_id)),
        }));
    }
    let out = json!({
        "about": "ADR-0021: a share copy's record ID = HKDF-SHA256(ikm = source record ID, salt = \"retifs/v1/share-record\", info = ns_id of the share)[0..16]; ns_id = SHA-256(\"retifs/v1/ns\" || share writer)[0..16]",
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
