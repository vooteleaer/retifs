use std::fs;

use retifs_core::{manifest, seal, Cid, ConvergenceSecret};
use retifs_store::{tier, SlabStore, StoreError};

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

fn sealed(n: u64, len: usize) -> retifs_core::Sealed {
    seal(&ConvergenceSecret::public(), &noise(len, n + 1)).unwrap()
}

fn segment_files(root: &std::path::Path) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for class in fs::read_dir(root.join("slabs")).unwrap() {
        let class = class.unwrap();
        for seg in fs::read_dir(class.path()).unwrap() {
            let seg = seg.unwrap();
            out.push((format!("{}/{}", class.file_name().to_string_lossy(), seg.file_name().to_string_lossy()),
                      seg.metadata().unwrap().len()));
        }
    }
    out.sort();
    out
}

#[test]
fn persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let a = sealed(1, 3000);
    {
        let st = SlabStore::open(dir.path()).unwrap();
        assert!(st.insert(&a.cid, &a.ciphertext, tier::CACHE).unwrap());
    }
    let st = SlabStore::open(dir.path()).unwrap();
    assert_eq!(st.fetch(&a.cid).unwrap().unwrap(), a.ciphertext);
    assert_eq!(st.fetch(&sealed(2, 10).cid).unwrap(), None);
}

#[test]
fn dedup_merges_tiers_without_new_slot() {
    let dir = tempfile::tempdir().unwrap();
    let st = SlabStore::open(dir.path()).unwrap();
    let a = sealed(1, 3000);
    assert!(st.insert(&a.cid, &a.ciphertext, tier::CACHE).unwrap());
    assert!(!st.insert(&a.cid, &a.ciphertext, tier::PINNED).unwrap());
    assert_eq!(st.tier(&a.cid).unwrap(), Some(tier::CACHE | tier::PINNED));
    assert_eq!(st.len().unwrap(), 1);
    assert_eq!(segment_files(dir.path()), vec![("c4k/seg-000000".into(), 4096)]);
}

#[test]
fn freed_slots_are_reused() {
    let dir = tempfile::tempdir().unwrap();
    let st = SlabStore::open(dir.path()).unwrap();
    let (a, b, c) = (sealed(1, 3000), sealed(2, 3000), sealed(3, 3000));
    st.insert(&a.cid, &a.ciphertext, tier::CACHE).unwrap();
    st.insert(&b.cid, &b.ciphertext, tier::CACHE).unwrap();
    assert!(st.remove(&a.cid).unwrap());
    st.insert(&c.cid, &c.ciphertext, tier::CACHE).unwrap();
    // c took a's slot: the segment didn't grow past two slots
    assert_eq!(segment_files(dir.path()), vec![("c4k/seg-000000".into(), 2 * 4096)]);
    assert_eq!(st.fetch(&a.cid).unwrap(), None);
    assert_eq!(st.fetch(&b.cid).unwrap().unwrap(), b.ciphertext);
    assert_eq!(st.fetch(&c.cid).unwrap().unwrap(), c.ciphertext);
}

#[test]
fn corruption_on_disk_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let a = sealed(1, 3000);
    {
        let st = SlabStore::open(dir.path()).unwrap();
        st.insert(&a.cid, &a.ciphertext, tier::CACHE).unwrap();
    }
    let seg = dir.path().join("slabs/c4k/seg-000000");
    let mut bytes = fs::read(&seg).unwrap();
    bytes[123] ^= 0x40;
    fs::write(&seg, bytes).unwrap();
    let st = SlabStore::open(dir.path()).unwrap();
    assert!(matches!(st.fetch(&a.cid), Err(StoreError::Corrupt(c)) if c == a.cid));
}

#[test]
fn refuses_bad_input() {
    let dir = tempfile::tempdir().unwrap();
    let st = SlabStore::open(dir.path()).unwrap();
    let a = sealed(1, 3000);
    let wrong = Cid::of(b"something else");
    assert!(matches!(st.insert(&wrong, &a.ciphertext, tier::CACHE), Err(StoreError::Corrupt(_))));
    assert!(matches!(st.insert(&a.cid, &a.ciphertext[..1000], tier::CACHE), Err(StoreError::NotAClassSize(1000))));
    assert!(st.is_empty().unwrap());
}

#[test]
fn files_roundtrip_through_the_slab_store() {
    let dir = tempfile::tempdir().unwrap();
    let data = noise(3_000_000, 77);
    let file = {
        let mut st = SlabStore::open(dir.path()).unwrap();
        st.set_sync(false);
        manifest::write(&mut st, &ConvergenceSecret::personal([4; 32]), &data).unwrap()
    };
    let st = SlabStore::open(dir.path()).unwrap();
    assert_eq!(manifest::read_all(&st, &file).unwrap(), data);
    assert_eq!(manifest::read_range(&st, &file, 1_234_567..1_300_000).unwrap(), &data[1_234_567..1_300_000]);

    // own writes are pinned
    assert_eq!(st.tier(&file.root).unwrap(), Some(tier::PINNED));
    // one segment per size class in use, not one file per chunk
    let segs = segment_files(dir.path());
    assert!(segs.len() <= retifs_core::chunk::CLASSES.len(), "{segs:?}");
    assert!(segs.iter().all(|(name, _)| name.ends_with("seg-000000")), "{segs:?}");
    assert!(st.len().unwrap() > 100);
    let on_disk: u64 = segs.iter().map(|(_, n)| n).sum();
    eprintln!("{} chunks, {} data bytes, {} on disk ({:.0}% overhead)",
              st.len().unwrap(), data.len(), on_disk, (on_disk as f64 / data.len() as f64 - 1.0) * 100.0);
}

#[test]
fn serving_index_is_per_token_and_publish_is_separate() {
    use retifs_core::{access::PUBLIC_ID, ServeToken};
    let dir = tempfile::tempdir().unwrap();
    let st = SlabStore::open(dir.path()).unwrap();
    let file = manifest::write(&mut retifs_store::PinnedTier(&st), &ConvergenceSecret::personal([1; 32]), &noise(50_000, 5)).unwrap();
    let token = ServeToken::for_file(&file);
    let other = ServeToken::for_file(&retifs_core::FileRef { seed: retifs_core::Seed([9; 32]), ..file });

    assert!(!st.is_served(&token.id(), &file.root).unwrap(), "nothing is served until registered");
    st.register_serving(&token, &[file.root]).unwrap();
    assert!(st.is_served(&token.id(), &file.root).unwrap());
    assert!(!st.is_served(&other.id(), &file.root).unwrap(), "another token doesn't open it");
    assert!(!st.is_served(&PUBLIC_ID, &file.root).unwrap(), "not public unless published");
    assert_eq!(st.serve_token(&token.id()).unwrap(), Some(token.clone()));

    st.publish(&[file.root]).unwrap();
    assert!(st.is_served(&PUBLIC_ID, &file.root).unwrap());
}
