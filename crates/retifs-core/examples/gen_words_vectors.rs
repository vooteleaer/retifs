//! Regenerates `test-vectors/words-v1.json` (ADR-0020: fingerprint words).
//!
//!     cargo run -p retifs-core --example gen_words_vectors > crates/retifs-core/test-vectors/words-v1.json

use retifs_core::words;
use serde_json::json;
use sha2::{Digest, Sha256};

fn main() {
    let cases: Vec<_> = (0..4u32)
        .map(|i| {
            let len = if i % 2 == 0 { 32 } else { 16 };
            let key = &Sha256::digest([b"key".as_slice(), &i.to_be_bytes()].concat())[..len];
            json!({ "key": hex::encode(key), "words": words::fingerprint(key, words::DEFAULT_WORDS) })
        })
        .collect();
    let doc = json!({
        "about": "ADR-0020: fingerprint words = BIP-39 English words for consecutive 11-bit groups of SHA-256(key), most significant bit first; 6 words by default",
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
