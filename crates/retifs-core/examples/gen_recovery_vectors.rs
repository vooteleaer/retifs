//! Regenerates `test-vectors/recovery-v1.json` (ADR-0033: the recovery kit's
//! words and everything derived from its seed).
//!
//!     cargo run -p retifs-core --example gen_recovery_vectors > crates/retifs-core/test-vectors/recovery-v1.json

use retifs_core::recovery::RecoverySeed;
use serde_json::json;
use sha2::{Digest, Sha256};

fn main() {
    let mut seeds: Vec<[u8; 32]> = vec![[0; 32], [0xff; 32]];
    for i in 0..4u32 {
        seeds.push(Sha256::digest([b"recovery".as_slice(), &i.to_be_bytes()].concat()).into());
    }
    let node: [u8; 16] = Sha256::digest(b"a retifs.node")[..16].try_into().unwrap();
    let cases: Vec<_> = seeds
        .iter()
        .map(|s| {
            let seed = RecoverySeed::from_bytes(*s);
            json!({
                "seed": hex::encode(s),
                "words": seed.words().join(" "),
                "identity_secret": hex::encode(seed.identity_secret()),
                "identity_public": hex::encode(seed.identity_public()),
                "identity_hash": hex::encode(seed.identity_hash()),
                "keyring_ns_id": hex::encode(seed.keyring_ns_id()),
                "keyring_read_key": hex::encode(seed.keyring_read_key()),
                "locator": hex::encode(seed.locator().0),
                "node": hex::encode(node),
                "node_tag": hex::encode(seed.locator().tag(&node)),
            })
        })
        .collect();
    let out = json!({
        "about": "ADR-0033: words = BIP-39 English over seed || SHA-256(seed)[0], 24 words; k(info) = HKDF-SHA256(ikm = seed, salt = \"retifs/v1/recovery\", info)[0..32]; identity secret = k(\"x25519\") || k(\"ed25519\") (RNS layout); keyring ns_id = SHA-256(\"retifs/v1/ns\" || Ed25519 public)[0..16]; keyring read key = k(\"keyring-read\"); locator = k(\"keyring-locator\"); node_tag = HMAC-SHA256(locator, node)[0..16]",
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
