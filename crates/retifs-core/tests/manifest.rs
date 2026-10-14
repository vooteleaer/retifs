use std::collections::HashMap;

use retifs_core::{
    manifest::{read_all, read_range, write},
    Cid, ConvergenceSecret, ManifestError, Store,
};

#[derive(Default)]
struct MemStore(HashMap<Cid, Vec<u8>>);

impl Store for MemStore {
    type Error = std::convert::Infallible;
    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), Self::Error> {
        self.0.insert(cid, ciphertext);
        Ok(())
    }
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.get(cid).cloned())
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
        let f = write(&mut store, &secret, &data).unwrap();
        assert_eq!(f.size, len as u64);
        assert_eq!(read_all(&store, &f).unwrap(), data, "len {len}");
    }
}

#[test]
fn random_access_ranges() {
    let data = noise(3_000_000, 11);
    let mut store = MemStore::default();
    let f = write(&mut store, &ConvergenceSecret::public(), &data).unwrap();
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
    let a = write(&mut s1, &ConvergenceSecret::public(), &data).unwrap();
    let b = write(&mut s2, &ConvergenceSecret::public(), &data).unwrap();
    assert_eq!(a, b, "same public file, same read-cap, from independent writers");

    let c = write(&mut s1, &ConvergenceSecret::personal([1; 32]), &data).unwrap();
    assert_ne!(a.root, c.root);
}

#[test]
fn missing_and_tampered_chunks_are_reported() {
    let data = noise(300_000, 8);
    let mut store = MemStore::default();
    let f = write(&mut store, &ConvergenceSecret::public(), &data).unwrap();

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
    write(&mut store, &ConvergenceSecret::public(), &data).unwrap();
    for ct in store.0.values() {
        assert!(ct.len().is_power_of_two() && (1024..=262_144).contains(&ct.len()));
    }
}

#[test]
fn read_cap_text_roundtrip() {
    let mut store = MemStore::default();
    let f = write(&mut store, &ConvergenceSecret::public(), &noise(50_000, 1)).unwrap();
    let text = f.to_string();
    assert!(text.starts_with("retifs:1:01"));
    assert_eq!(text.parse::<retifs_core::FileRef>().unwrap(), f);
    assert!("retifs:2:00:00:1".parse::<retifs_core::FileRef>().is_err());
}

#[test]
fn tiny_files_are_inline_in_one_blob() {
    use retifs_core::manifest::INLINE_MAX;
    let secret = ConvergenceSecret::personal([3; 32]);
    for len in [0, 1, 400, INLINE_MAX] {
        let data = noise(len, len as u64 + 9);
        let mut store = MemStore::default();
        let f = write(&mut store, &secret, &data).unwrap();
        assert_eq!(store.0.len(), 1, "len {len}: exactly one blob");
        assert_eq!(store.0[&f.root].len(), 1024, "len {len}: 1 KiB class");
        assert_eq!(read_all(&store, &f).unwrap(), data);
        if len > 10 {
            assert_eq!(read_range(&store, &f, 3..10).unwrap(), &data[3..10]);
        }
    }
    let mut store = MemStore::default();
    let f = write(&mut store, &secret, &noise(INLINE_MAX + 1, 1)).unwrap();
    assert_eq!(store.0.len(), 2, "one byte more: root node + chunk");
    assert_eq!(read_all(&store, &f).unwrap(), noise(INLINE_MAX + 1, 1));
}

#[test]
fn compressed_files_roundtrip_and_take_less_space() {
    use retifs_core::{manifest::{write_opts, WriteOpts}, Compression};
    let text: Vec<u8> = b"line of a log file: sensor 7 reports 21.5 C at 12:00\n".iter().cycle().take(500_000).copied().collect();
    let secret = ConvergenceSecret::personal([4; 32]);
    let (mut raw, mut z) = (MemStore::default(), MemStore::default());
    let f_raw = write(&mut raw, &secret, &text).unwrap();
    let f_z = write_opts(&mut z, &secret, &text, WriteOpts { compression: Compression::Zstd }).unwrap();
    assert_eq!(read_all(&z, &f_z).unwrap(), text);
    assert_eq!(read_range(&z, &f_z, 123_456..200_000).unwrap(), &text[123_456..200_000]);
    let bytes = |s: &MemStore| s.0.values().map(Vec::len).sum::<usize>();
    assert!(bytes(&z) * 4 < bytes(&raw), "compressed {} vs raw {}", bytes(&z), bytes(&raw));
    assert_eq!(read_all(&raw, &f_raw).unwrap(), text);
}
