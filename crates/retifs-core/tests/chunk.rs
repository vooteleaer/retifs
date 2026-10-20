use std::collections::HashSet;

use retifs_core::{
    chunk::{class_for, CLASSES, MAX_DATA},
    chunker, open, seal, seal_with, Cid, ChunkError, Compression, ConvergenceSecret, Seed,
};

fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + salt as usize) % 251) as u8).collect()
}

/// xorshift: deterministic pseudo-random bytes that FastCDC can find boundaries in.
fn noise(len: usize, mut s: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

#[test]
fn roundtrip_at_every_class_boundary() {
    let secret = ConvergenceSecret::public();
    for &class in &CLASSES {
        let max = class - 64 - 5;
        for len in [max.saturating_sub(1), max] {
            let data = pattern(len, 7);
            let s = seal(&secret, &data).unwrap();
            assert_eq!(s.ciphertext.len(), class, "len {len}");
            assert_eq!(open(&s.cid, &s.seed, &s.ciphertext).unwrap(), data);
        }
    }
    assert_eq!(class_for(MAX_DATA), Some(CLASSES[9]));
    assert_eq!(class_for(0), Some(512));
    assert_eq!(class_for(512 - 64 - 5), Some(512));
    assert_eq!(class_for(512 - 64 - 4), Some(1024));
    assert_eq!(seal(&secret, &vec![0; MAX_DATA + 1]).unwrap_err(), ChunkError::TooLarge);
}

#[test]
fn ciphertext_size_hides_exact_length() {
    let secret = ConvergenceSecret::public();
    let len = |n| seal(&secret, &pattern(n, 0)).unwrap().ciphertext.len();
    assert_eq!(len(10), len(400));
    assert_eq!(len(500), len(900));
}

#[test]
fn convergent_within_a_secret_and_separate_across_secrets() {
    let data = pattern(5000, 9);
    let public = ConvergenceSecret::public();
    let p1 = ConvergenceSecret::personal([1; 32]);
    let p2 = ConvergenceSecret::personal([2; 32]);

    assert_eq!(seal(&public, &data).unwrap().cid, seal(&public, &data).unwrap().cid);
    let cids: HashSet<Cid> = [&public, &p1, &p2].iter().map(|s| seal(s, &data).unwrap().cid).collect();
    assert_eq!(cids.len(), 3);

    let pubk = [7u8; 32];
    let stable = ConvergenceSecret::restricted(&pubk, b"line", b"stable");
    let edge = ConvergenceSecret::restricted(&pubk, b"line", b"edge");
    assert_ne!(seal(&stable, &data).unwrap().cid, seal(&edge, &data).unwrap().cid);
    // length-prefixed fields: ("ab","c") and ("a","bc") must differ
    assert!(ConvergenceSecret::restricted(&pubk, b"ab", b"c") != ConvergenceSecret::restricted(&pubk, b"a", b"bc"));
}

#[test]
fn different_data_never_shares_iv() {
    let secret = ConvergenceSecret::restricted(&[3; 32], b"line", b"ch");
    let ivs: HashSet<[u8; 16]> = (0..200u32)
        .map(|i| seal(&secret, &i.to_be_bytes()).unwrap().ciphertext[..16].try_into().unwrap())
        .collect();
    assert_eq!(ivs.len(), 200);
}

#[test]
fn tampering_is_detected() {
    let s = seal(&ConvergenceSecret::public(), &pattern(3000, 4)).unwrap();

    let mut flipped = s.ciphertext.clone();
    flipped[100] ^= 1;
    assert_eq!(open(&s.cid, &s.seed, &flipped).unwrap_err(), ChunkError::CidMismatch);
    // A forger who also recomputes the CID still fails the HMAC.
    assert_eq!(open(&Cid::of(&flipped), &s.seed, &flipped).unwrap_err(), ChunkError::BadMac);
    // Wrong seed (wrong read key) fails the HMAC.
    assert_eq!(open(&s.cid, &Seed([0; 32]), &s.ciphertext).unwrap_err(), ChunkError::BadMac);
    // Truncation is caught before anything else.
    assert_eq!(open(&s.cid, &s.seed, &s.ciphertext[..1000]).unwrap_err(), ChunkError::NotAClassSize);
}

#[test]
fn chunk_seal_open_and_dedup_after_edit() {
    let secret = ConvergenceSecret::personal([9; 32]);
    let original = noise(1 << 20, 0x9E37_79B9_7F4A_7C15);
    let mut edited = original.clone();
    edited.splice(500_000..500_000, b"inserted in the middle".iter().copied());

    let seal_all = |data: &[u8]| -> Vec<_> { chunker::split(data).map(|c| seal(&secret, c).unwrap()).collect() };
    let a = seal_all(&original);
    let b = seal_all(&edited);

    let restored: Vec<u8> = a.iter().flat_map(|s| open(&s.cid, &s.seed, &s.ciphertext).unwrap()).collect();
    assert_eq!(restored, original);

    let a_cids: HashSet<Cid> = a.iter().map(|s| s.cid).collect();
    let shared = b.iter().filter(|s| a_cids.contains(&s.cid)).count();
    assert!(shared + 3 >= b.len(), "an insert should change only a couple of chunks: {shared}/{}", b.len());
}

#[test]
fn matches_committed_test_vectors() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/chunk-v1.json")).unwrap();
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let hexf = |k: &str| hex::decode(case[k].as_str().unwrap()).unwrap();
        let secret = ConvergenceSecret::personal(hexf("convergence_secret").try_into().unwrap());
        let compression = if case["compression"] == "zstd" { Compression::Zstd } else { Compression::Off };
        let s = seal_with(&secret, &hexf("data"), compression).unwrap();
        assert_eq!(s.seed.0.to_vec(), hexf("seed"), "{name}: seed");
        assert_eq!(s.cid.to_string(), case["cid"].as_str().unwrap(), "{name}: cid");
        assert_eq!(s.ciphertext, hexf("ciphertext"), "{name}: ciphertext");
    }
}

#[test]
fn compression_shrinks_compressible_data_and_roundtrips() {
    let secret = ConvergenceSecret::public();
    let text: Vec<u8> = b"retifs keeps your data encrypted, redundant and yours. ".iter().cycle().take(16_000).copied().collect();
    let raw = seal(&secret, &text).unwrap();
    let z = seal_with(&secret, &text, Compression::Zstd).unwrap();
    assert_eq!(raw.ciphertext.len(), 16_384);
    assert!(z.ciphertext.len() <= 2048, "compressed into a small class: {}", z.ciphertext.len());
    assert_ne!(raw.cid, z.cid);
    assert_eq!(open(&z.cid, &z.seed, &z.ciphertext).unwrap(), text);
}

#[test]
fn incompressible_data_stays_raw() {
    let secret = ConvergenceSecret::public();
    let data = noise(12_000, 99);
    let raw = seal(&secret, &data).unwrap();
    let z = seal_with(&secret, &data, Compression::Zstd).unwrap();
    assert_eq!(raw.cid, z.cid, "no gain, so the writer keeps it raw (same chunk)");
}
