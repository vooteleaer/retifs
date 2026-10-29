//! Regenerates `test-vectors/manifest-v1.json`: manifests (ADR-0009,
//! irreversible decision 11), checked by `verify_manifest_rns.py`.
//!
//!     cargo run -p retifs-core --example gen_manifest_vectors > crates/retifs-core/test-vectors/manifest-v1.json
//!
//! Each case gives the file's data (inline, or as a pattern to regenerate),
//! its read-cap and every manifest node's ciphertext. Data and padding chunks
//! aren't listed: a verifier seals them again from the data and the leaf
//! spans, and from the padding rule, and compares CIDs.

use std::collections::HashMap;

use retifs_core::{
    manifest::{self, WriteOpts},
    open, Cid, ConvergenceSecret, FileRef, Seed,
};
use serde_json::{json, Value};

#[derive(Default)]
struct Mem(HashMap<Cid, Vec<u8>>);

impl retifs_core::Store for Mem {
    type Error = std::convert::Infallible;
    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), Self::Error> {
        self.0.insert(cid, ciphertext);
        Ok(())
    }
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.get(cid).cloned())
    }
}

/// The same pattern the chunk vectors use: byte i = (i·31 + salt) mod 251.
fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + salt as usize) % 251) as u8).collect()
}

/// The first length from `start` (in 4 KiB steps) whose pattern splits into a
/// chunk count PADMÉ rounds up: a case that really has padding chunks.
fn padded_len(start: usize, salt: u8) -> usize {
    let mut len = start;
    loop {
        let n = retifs_core::chunker::split(&pattern(len, salt)).count() as u64;
        if manifest::padme(n) > n {
            return len;
        }
        len += 4096;
    }
}

/// Every manifest node of `file`, root first, depth first.
fn nodes(store: &Mem, file: &FileRef) -> Vec<Value> {
    let mut out = Vec::new();
    let mut stack: Vec<(Cid, Seed, u64, bool)> = vec![(file.root, file.seed, file.size, true)];
    while let Some((cid, seed, span, root)) = stack.pop() {
        let ct = store.0.get(&cid).expect("written");
        let pt = open(&cid, &seed, ct).expect("opens");
        out.push(json!({ "cid": cid.to_string(), "ciphertext": hex::encode(ct) }));
        let node = if root { manifest::decode_root(&pt, span) } else { manifest::decode_node(&pt, span) }.expect("decodes");
        if !node.leaf {
            for e in node.entries.iter().rev() {
                stack.push((e.cid, e.seed, e.span, false));
            }
        }
    }
    out
}

fn case(name: &str, scheme: Value, secret: &ConvergenceSecret, data: Value, bytes: &[u8], opts: WriteOpts) -> Value {
    let mut store = Mem::default();
    let file = manifest::write_opts(&mut store, secret, bytes, opts).expect("writes");
    json!({
        "name": name,
        "scheme": scheme,
        "convergence_secret": hex::encode(secret.as_bytes()),
        "data": data,
        "pad": opts.pad,
        "stable_padding": opts.stable_padding,
        "file": { "root": file.root.to_string(), "seed": hex::encode(file.seed.0), "size": file.size },
        "nodes": nodes(&store, &file),
    })
}

fn main() {
    let public = ConvergenceSecret::public();
    let record = ConvergenceSecret::for_record(&[0x42; 32], &[0x07; 16]);
    let pub_scheme = json!({ "type": "public" });
    let rec_scheme = json!({ "type": "record", "namespace_key": hex::encode([0x42u8; 32]), "record_id": hex::encode([0x07u8; 16]) });
    let pat = |len: usize, salt: u8| (json!({ "pattern": { "len": len, "salt": salt } }), pattern(len, salt));
    let raw = |b: &[u8]| (json!({ "hex": hex::encode(b) }), b.to_vec());
    let padded = WriteOpts::default();
    let stable = WriteOpts { stable_padding: true, ..WriteOpts::default() };

    let mut cases = Vec::new();
    for (name, scheme, secret, (data, bytes), opts) in [
        ("inline-empty", &pub_scheme, &public, raw(b""), padded),
        ("inline-short", &pub_scheme, &public, raw(b"hello retifs"), padded),
        ("inline-max", &pub_scheme, &public, pat(manifest::INLINE_MAX, 5), padded),
        ("one-chunk", &pub_scheme, &public, pat(manifest::INLINE_MAX + 1, 5), padded),
        ("padded-leaf", &pub_scheme, &public, pat(padded_len(110_000, 6), 6), padded),
        ("record-stable-padding", &rec_scheme, &record, pat(padded_len(110_000, 6), 6), stable),
        ("two-levels", &pub_scheme, &public, pat(1_200_000, 7), padded),
    ] {
        cases.push(case(name, scheme.clone(), secret, data, &bytes, opts));
    }
    let doc = json!({
        "construction": "retifs manifest v1 (ADR-0009, proposed): nodes sealed like chunks (ADR-0008); node = 0x01 || kind || u16_be n || body; leaf entry = cid(33) || seed(32) || u32_be len; internal entry = cid(33) || seed(32) || u64_be span; inline = n bytes of data (root only, n <= inline_max)",
        "padding": "data chunks padded to PADME(count) with pieces HMAC-SHA256 counter mode under HMAC-SHA256(secret, 'retifs/v1/pad' || digest || u64_be index), digest = SHA-256(data chunk CIDs in order), or 32 zero bytes with stable padding; piece length = max_piece",
        "inline_max": manifest::INLINE_MAX,
        "max_piece": retifs_core::chunker::MAX_SIZE,
        "writer_policy": { "fanout": manifest::FANOUT, "chunker": "FastCDC 2020, 8 KiB min, 12 KiB avg, max_piece max (not part of the format)" },
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
