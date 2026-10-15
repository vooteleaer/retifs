//! Regenerates `test-vectors/lease-v1.json` (irreversible decision 6).
//!
//!     cargo run -p retifs-core --example gen_lease_vectors > crates/retifs-core/test-vectors/lease-v1.json

use retifs_core::{
    lease::{node_destination, prove, Lease, LeaseKey, Receipt, Renewal},
    ChunkToken, Cid, Seed,
};
use serde_json::json;

fn main() {
    let namespace_key: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let lease_id: [u8; 16] = std::array::from_fn(|i| 0xA0 + i as u8);
    let seeds: Vec<Seed> = (0..3u8).map(|i| Seed([0x10 + i; 32])).collect();
    let ciphertexts: Vec<Vec<u8>> = (0..3u8).map(|i| vec![0x40 + i; 1024]).collect();
    let entries: Vec<(Cid, ChunkToken)> =
        ciphertexts.iter().zip(&seeds).map(|(ct, s)| (Cid::of(ct), ChunkToken::for_seed(s))).collect();

    let key = LeaseKey::derive(&namespace_key, &lease_id);
    let lease = Lease::sign(&key, lease_id, 1_800_000_000, 3, entries);
    let renewal = Renewal::sign(&key, lease_id, 1_900_000_000);
    let holder_identity: [u8; 64] = std::array::from_fn(|i| 0x55 ^ i as u8);
    let receipt = Receipt::sign(&holder_identity, &lease, 1_800_000_000);
    let nonce = [0x77u8; 16];

    let doc = json!({
        "construction": "retifs leases v1 (ADR-0010/0011, decision 6, proposed)",
        "namespace_key": hex::encode(namespace_key),
        "lease_id": hex::encode(lease_id),
        "lease_signer": hex::encode(key.public()),
        "chunks": seeds.iter().zip(&ciphertexts).map(|(s, ct)| json!({
            "seed": hex::encode(s.0),
            "ciphertext": hex::encode(ct),
            "cid": Cid::of(ct).to_string(),
            "chunk_token": hex::encode(ChunkToken::for_seed(s).0),
            "prove_nonce": hex::encode(nonce),
            "prove": hex::encode(prove(&nonce, ct)),
        })).collect::<Vec<_>>(),
        "expires": lease.expires,
        "generations": lease.generations,
        "lease": hex::encode(lease.encode()),
        "lease_digest": hex::encode(lease.digest()),
        "renewal_expires": renewal.expires,
        "renewal": hex::encode(renewal.encode()),
        "holder_identity_secret": hex::encode(holder_identity),
        "holder_node_destination": hex::encode(node_destination(&receipt.holder)),
        "receipt": hex::encode(receipt.encode()),
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
