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

    // The first data chunk: a random blob might be padding, which a local read never touches.
    let root = retifs_core::open(&f.root, &f.seed, &store.0[&f.root]).unwrap();
    let victim = retifs_core::manifest::decode_root(&root, f.size).unwrap().entries[0].cid;
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
        assert!(ct.len().is_power_of_two() && (512..=262_144).contains(&ct.len()));
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
        assert!(store.0[&f.root].len() <= 1024, "len {len}: a 512 B or 1 KiB chunk");
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
    let f_z = write_opts(&mut z, &secret, &text, WriteOpts { compression: Compression::Zstd, ..Default::default() }).unwrap();
    assert_eq!(read_all(&z, &f_z).unwrap(), text);
    assert_eq!(read_range(&z, &f_z, 123_456..200_000).unwrap(), &text[123_456..200_000]);
    let bytes = |s: &MemStore| s.0.values().map(Vec::len).sum::<usize>();
    assert!(bytes(&z) * 4 < bytes(&raw), "compressed {} vs raw {}", bytes(&z), bytes(&raw));
    assert_eq!(read_all(&raw, &f_raw).unwrap(), text);
}

#[test]
fn padme_values() {
    use retifs_core::manifest::padme;
    for (n, p) in [(0, 0), (1, 1), (2, 2), (3, 3), (7, 7), (9, 10), (100, 104), (1000, 1024), (65_000, 65_536)] {
        assert_eq!(padme(n), p, "padme({n})");
    }
    for n in 1..100_000u64 {
        let p = padme(n);
        assert!(p >= n && (p - n) * 100 <= n * 12 + 100, "overhead for {n}: {p}");
    }
}

#[test]
fn padded_files_hide_their_chunk_count_and_read_back_exactly() {
    use retifs_core::manifest::{padme, write_tracked, WriteOpts};
    let secret = ConvergenceSecret::personal([6; 32]);
    let data = noise(1_100_000, 77); // ~76 real chunks
    let mut padded = MemStore::default();
    let (f, blobs) = write_tracked(&mut padded, &secret, &data, WriteOpts::default()).unwrap();
    let mut plain = MemStore::default();
    write_tracked(&mut plain, &secret, &data, WriteOpts { pad: false, ..Default::default() }).unwrap();

    let data_chunks = |s: &MemStore| s.0.values().filter(|c| c.len() == 16_384).count() as u64;
    let real = data_chunks(&plain);
    assert_eq!(data_chunks(&padded), padme(real), "chunk count padded up to the PADMÉ bucket");
    assert!(padme(real) > real, "this size actually needed padding ({real} chunks)");
    assert_eq!(blobs.len(), padded.0.len(), "every blob is reported with its seed");

    assert_eq!(f.size, data.len() as u64, "the read-cap keeps the true size");
    assert_eq!(read_all(&padded, &f).unwrap(), data);
    assert_eq!(read_range(&padded, &f, 1_099_000..1_100_000).unwrap(), &data[1_099_000..]);
    assert_eq!(read_range(&padded, &f, 0..1_100_001).unwrap_err(), ManifestError::OutOfRange);

    let mut again = MemStore::default();
    let (g, _) = write_tracked(&mut again, &ConvergenceSecret::public(), &data, WriteOpts::default()).unwrap();
    let mut other = MemStore::default();
    let (h, _) = write_tracked(&mut other, &ConvergenceSecret::public(), &data, WriteOpts::default()).unwrap();
    assert_eq!(g, h, "padding is deterministic: equal public files still converge");
}

#[test]
fn records_dedup_across_versions_but_not_across_records() {
    let ns = [9u8; 32];
    let v1 = noise(400_000, 3);
    let mut v2 = v1.clone();
    v2[200_000] ^= 0xff; // a one-byte edit
    let rec = ConvergenceSecret::for_record(&ns, b"/home/me/notes.txt");
    let other = ConvergenceSecret::for_record(&ns, b"/home/me/other.txt");

    let mut s1 = MemStore::default();
    write(&mut s1, &rec, &v1).unwrap();
    let before = s1.0.len();
    write(&mut s1, &rec, &v2).unwrap();
    let new_blobs = s1.0.len() - before;
    assert!(new_blobs <= 4, "an edit costs a chunk or two plus nodes, got {new_blobs}");

    let mut s2 = MemStore::default();
    write(&mut s2, &other, &v1).unwrap();
    assert!(s2.0.keys().all(|c| !s1.0.contains_key(c)), "another record shares no CIDs, even with equal content");
}

#[test]
fn stable_padding_keeps_versions_cheap() {
    use retifs_core::manifest::{padme, WriteOpts};
    let rec = ConvergenceSecret::for_record(&[9u8; 32], b"big.bin");
    let v1 = noise(1_100_000, 8); // needs padding (~76 real chunks)
    let mut v2 = v1.clone();
    v2[600_000] ^= 0xff;
    let stable = WriteOpts { stable_padding: true, ..Default::default() };

    let mut s = MemStore::default();
    retifs_core::manifest::write_opts(&mut s, &rec, &v1, stable).unwrap();
    let before = s.0.len();
    let f2 = retifs_core::manifest::write_opts(&mut s, &rec, &v2, stable).unwrap();
    let added = s.0.len() - before;
    assert!(added <= 4, "an edit costs a chunk or two plus nodes, not new padding: {added}");
    assert_eq!(read_all(&s, &f2).unwrap(), v2);
    assert!(padme(76) > 76);
}

