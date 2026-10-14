//! Disk budget (ADR-0012): usage per tier, limits, eviction order, holes.

use retifs_core::{seal, ConvergenceSecret, Sealed};
use retifs_store::{tier, Budget, SlabStore, StoreError, Tier};

const K4: u64 = 4096;

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

/// A distinct 4 KiB-class chunk.
fn chunk(n: u64) -> Sealed {
    seal(&ConvergenceSecret::public(), &noise(3000, n + 1)).unwrap()
}

fn store(budget: Budget) -> (tempfile::TempDir, SlabStore) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = SlabStore::open(dir.path()).unwrap();
    st.set_sync(false);
    st.set_budget(budget);
    (dir, st)
}

#[test]
fn usage_follows_inserts_tier_changes_and_removals() {
    let (_d, st) = store(Budget::default());
    let (a, b) = (chunk(1), chunk(2));
    st.insert(&a.cid, &a.ciphertext, tier::PINNED).unwrap();
    st.insert(&b.cid, &b.ciphertext, tier::CACHE).unwrap();
    let u = st.usage().unwrap();
    assert_eq!((u.pinned, u.cache, u.spare), (K4, K4, 0));

    // Reading something you already cache-hold and then pinning it moves its bytes.
    st.insert(&b.cid, &b.ciphertext, tier::PINNED).unwrap();
    let u = st.usage().unwrap();
    assert_eq!((u.pinned, u.cache), (2 * K4, 0));

    st.set_tier(&a.cid, tier::SPARE).unwrap();
    assert_eq!(st.usage().unwrap().spare, K4);
    st.remove(&a.cid).unwrap();
    st.remove(&b.cid).unwrap();
    assert_eq!(st.usage().unwrap().total(), 0);
}

#[test]
fn cache_cap_evicts_least_recently_used() {
    let (_d, st) = store(Budget { cache_max: Some(3 * K4), ..Default::default() });
    let c: Vec<Sealed> = (0..5).map(chunk).collect();
    for s in &c[..3] {
        st.insert(&s.cid, &s.ciphertext, tier::CACHE).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    st.fetch(&c[0].cid).unwrap(); // c0 is now the most recently used
    std::thread::sleep(std::time::Duration::from_millis(5));
    st.insert(&c[3].cid, &c[3].ciphertext, tier::CACHE).unwrap();

    assert_eq!(st.usage().unwrap().cache, 3 * K4, "cache stays at its cap");
    assert!(st.tier(&c[1].cid).unwrap().is_none(), "c1 was the least recently used and was evicted");
    assert!(st.tier(&c[0].cid).unwrap().is_some(), "c0 was read recently and stays");
}

#[test]
fn disk_pressure_evicts_spare_then_cache_but_never_pinned() {
    // A "volume" with room for 4 chunks above a 1-chunk reserve.
    let (_d, st) = store(Budget { simulate_free: Some(5 * K4), min_free: Some(K4), max_store: Some(u64::MAX), ..Default::default() });
    let c: Vec<Sealed> = (0..8).map(chunk).collect();
    st.insert(&c[0].cid, &c[0].ciphertext, tier::SPARE).unwrap();
    st.insert(&c[1].cid, &c[1].ciphertext, tier::CACHE).unwrap();
    st.insert(&c[2].cid, &c[2].ciphertext, tier::PINNED).unwrap();
    st.insert(&c[3].cid, &c[3].ciphertext, tier::PINNED).unwrap();

    st.insert(&c[4].cid, &c[4].ciphertext, tier::PINNED).unwrap();
    assert!(st.tier(&c[0].cid).unwrap().is_none(), "spare went first");
    assert!(st.tier(&c[1].cid).unwrap().is_some(), "cache still there");

    st.insert(&c[5].cid, &c[5].ciphertext, tier::PINNED).unwrap();
    assert!(st.tier(&c[1].cid).unwrap().is_none(), "then cache");

    let err = st.insert(&c[6].cid, &c[6].ciphertext, tier::PINNED).unwrap_err();
    assert!(matches!(err, StoreError::Full(_)), "own data is refused, nothing pinned was dropped: {err}");
    for s in &c[2..6] {
        assert_eq!(st.tier(&s.cid).unwrap(), Some(tier::PINNED));
    }

    let err = st.insert(&c[7].cid, &c[7].ciphertext, tier::SPARE).unwrap_err();
    assert!(matches!(err, StoreError::Full(_)), "spare can't displace anything but spare");
}

#[test]
fn store_limit_caps_hard_tiers_only() {
    let (_d, st) = store(Budget { max_store: Some(2 * K4), ..Default::default() });
    let c: Vec<Sealed> = (0..4).map(chunk).collect();
    st.insert(&c[0].cid, &c[0].ciphertext, tier::PINNED).unwrap();
    st.insert(&c[1].cid, &c[1].ciphertext, tier::SERVING).unwrap();
    assert!(matches!(st.insert(&c[2].cid, &c[2].ciphertext, tier::PINNED), Err(StoreError::Full(_))));
    st.insert(&c[3].cid, &c[3].ciphertext, tier::CACHE).unwrap();
    let u = st.usage().unwrap();
    assert_eq!((u.hard(), u.of(Tier::Cache)), (2 * K4, K4));
}

#[test]
fn enforce_gives_space_back_when_others_fill_the_disk() {
    let (_d, st) = store(Budget { simulate_free: Some(10 * K4), min_free: Some(K4), ..Default::default() });
    let c: Vec<Sealed> = (0..4).map(chunk).collect();
    for s in &c[..3] {
        st.insert(&s.cid, &s.ciphertext, tier::CACHE).unwrap();
    }
    st.insert(&c[3].cid, &c[3].ciphertext, tier::PINNED).unwrap();
    assert_eq!(st.enforce().unwrap(), 0, "within budget");

    // Another program takes most of the disk: only 4.5 chunks' worth was ever free.
    st.set_budget(Budget { simulate_free: Some(4 * K4 + K4 / 2), min_free: Some(K4), ..Default::default() });
    let freed = st.enforce().unwrap();
    assert!(freed >= K4, "cache evicted to restore the reserve, freed {freed}");
    assert!(st.limits().unwrap().disk_available >= K4);
    assert_eq!(st.tier(&c[3].cid).unwrap(), Some(tier::PINNED));
}

#[test]
fn removed_slots_read_as_holes_and_neighbours_survive() {
    let (dir, st) = store(Budget::default());
    let (a, b) = (chunk(1), chunk(2));
    st.insert(&a.cid, &a.ciphertext, tier::CACHE).unwrap();
    st.insert(&b.cid, &b.ciphertext, tier::PINNED).unwrap();
    st.remove(&a.cid).unwrap();

    let seg = std::fs::read(dir.path().join("slabs/c4k/seg-000000")).unwrap();
    assert!(seg[..4096].iter().all(|&x| x == 0), "the freed slot was punched out (zeroed)");
    assert_eq!(st.fetch(&b.cid).unwrap().unwrap(), b.ciphertext);
}
