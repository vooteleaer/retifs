//! Regenerates `test-vectors/chunk-v1.json`.
//!
//!     cargo run -p retifs-core --example gen_vectors > crates/retifs-core/test-vectors/chunk-v1.json

use retifs_core::{seal_with, Compression, ConvergenceSecret};
use serde_json::{json, Value};

fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + salt as usize) % 251) as u8).collect()
}

fn case(name: &str, scheme: Value, secret: &ConvergenceSecret, data: &[u8]) -> Value {
    case_with(name, scheme, secret, data, Compression::Off)
}

fn case_with(name: &str, scheme: Value, secret: &ConvergenceSecret, data: &[u8], compression: Compression) -> Value {
    let sealed = seal_with(secret, data, compression).expect("vector data fits");
    json!({
        "name": name,
        "scheme": scheme,
        "convergence_secret": hex::encode(secret.as_bytes()),
        "compression": if compression == Compression::Zstd { "zstd" } else { "off" },
        "data": hex::encode(data),
        "class": sealed.ciphertext.len(),
        "seed": hex::encode(sealed.seed.0),
        "cid": sealed.cid.to_string(),
        "ciphertext": hex::encode(&sealed.ciphertext),
    })
}

fn text(len: usize) -> Vec<u8> {
    b"retifs keeps your data encrypted, redundant and yours. ".iter().cycle().take(len).copied().collect()
}

fn main() {
    let publisher: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let public = ConvergenceSecret::public();
    let stable = ConvergenceSecret::restricted(&publisher, b"alpine-main", b"stable");
    let edge = ConvergenceSecret::restricted(&publisher, b"alpine-main", b"edge");
    let personal = ConvergenceSecret::personal([0xA5; 32]);
    let restricted = |channel: &str| {
        json!({ "type": "restricted", "publisher_secret": hex::encode(publisher),
                "name": hex::encode("alpine-main"), "channel": hex::encode(channel) })
    };

    let cases = vec![
        case("public-empty", json!({"type": "public"}), &public, b""),
        case("public-short", json!({"type": "public"}), &public, b"hello retifs"),
        case("public-class-1k-full", json!({"type": "public"}), &public, &pattern(955, 1)),
        case("public-class-2k-first", json!({"type": "public"}), &public, &pattern(956, 1)),
        case("public-20000", json!({"type": "public"}), &public, &pattern(20_000, 2)),
        case("restricted-stable", restricted("stable"), &stable, &pattern(1000, 3)),
        case("restricted-edge-same-data", restricted("edge"), &edge, &pattern(1000, 3)),
        case("personal", json!({"type": "personal"}), &personal, &pattern(1000, 3)),
        case_with("public-zstd-text", json!({"type": "public"}), &public, &text(6000), Compression::Zstd),
    ];

    let doc = json!({
        "construction": "retifs chunk encryption v1 (ADR-0008, proposed); frame = encoding u8 || u32_be len || payload || zero fill",
        "cid": "0x01 || SHA-256(ciphertext)",
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
