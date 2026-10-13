use std::collections::HashMap;

use retifs_core::{
    manifest::{read_all, read_range, write},
    Cid, ConvergenceSecret, ManifestError, Store,
};

#[derive(Default)]
struct MemStore(HashMap<Cid, Vec<u8>>);

impl Store for MemStore {
    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) {
        self.0.insert(cid, ciphertext);
    }
    fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.0.get(cid).cloned()
    }
}

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
fn roundtrip_sizes() {
    let secret = ConvergenceSecret::personal([5; 32]);
    for len in [0, 1, 4095, 16_384, 200_000, 3_000_000] {
        let data = noise(len, len as u64 + 1);
        let mut store = MemStore::default();
        let f = write(&mut store, &secret, &data);
        assert_eq!(f.size, len as u64);
        assert_eq!(read_all(&store, &f).unwrap(), data, "len {len}");
    }
}

#[test]
fn random_access_ranges() {
    let data = noise(3_000_000, 11);
    let mut store = MemStore::default();
    let f = write(&mut store, &ConvergenceSecret::public(), &data);
    let mut s = 99u64;
    for _ in 0..50 {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        let a = (s >> 33) % 3_000_000;
        let b = (a + (s >> 13) % 70_000).min(3_000_000);
        assert_eq!(read_range(&store, &f, a..b).unwrap(), &data[a as usize..b as usize]);
    }
    assert_eq!(read_range(&store, &f, 0..3_000_001).unwrap_err(), ManifestError::OutOfRange);
}

#[test]
fn public_files_converge_personal_files_dont() {
    let data = noise(500_000, 21);
    let (mut s1, mut s2) = (MemStore::default(), MemStore::default());
    let a = write(&mut s1, &ConvergenceSecret::public(), &data);
    let b = write(&mut s2, &ConvergenceSecret::public(), &data);
    assert_eq!(a, b, "same public file, same read-cap, from independent writers");

    let c = write(&mut s1, &ConvergenceSecret::personal([1; 32]), &data);
    assert_ne!(a.root, c.root);
}

#[test]
fn missing_and_tampered_chunks_are_reported() {
    let data = noise(300_000, 8);
    let mut store = MemStore::default();
    let f = write(&mut store, &ConvergenceSecret::public(), &data);

    let victim = *store.0.keys().find(|c| **c != f.root).unwrap();
    let mut tampered = MemStore(store.0.clone());
    tampered.0.get_mut(&victim).unwrap()[50] ^= 1;
    assert!(matches!(read_all(&tampered, &f), Err(ManifestError::Chunk(c, _)) if c == victim));

    store.0.remove(&victim);
    assert_eq!(read_all(&store, &f).unwrap_err(), ManifestError::Missing(victim));
}

#[test]
fn storage_sees_only_class_sized_blobs() {
    let data = noise(1_000_000, 13);
    let mut store = MemStore::default();
    write(&mut store, &ConvergenceSecret::public(), &data);
    for ct in store.0.values() {
        assert!(ct.len().is_power_of_two() && (1024..=262_144).contains(&ct.len()));
    }
}
