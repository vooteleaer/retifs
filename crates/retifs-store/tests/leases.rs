//! Leases on the holder and owner side (ADR-0010/0011).

use retifs_core::{
    lease::{Lease, LeaseKey, Receipt, Renewal},
    seal, ChunkToken, ConvergenceSecret, Sealed,
};
use retifs_store::{tier, Accept, ProofState, SlabStore, LEASE_CHUNK_ESTIMATE};

fn chunk(n: u8) -> Sealed {
    seal(&ConvergenceSecret::public(), &[n; 3000]).unwrap()
}

fn store() -> (tempfile::TempDir, SlabStore) {
    let dir = tempfile::tempdir().unwrap();
    let mut st = SlabStore::open(dir.path()).unwrap();
    st.set_sync(false);
    (dir, st)
}

fn lease(id: u8, chunks: &[Sealed], expires: u64) -> (LeaseKey, Lease) {
    let key = LeaseKey::derive(&[9; 32], &[id; 16]);
    let entries = chunks.iter().map(|c| (c.cid, ChunkToken::for_seed(&c.seed))).collect();
    let l = Lease::sign(&key, [id; 16], expires, 1, entries);
    (key, l)
}

#[test]
fn holder_accepts_pulls_serves_and_expires() {
    let (_d, st) = store();
    let chunks: Vec<Sealed> = (0..3).map(chunk).collect();
    let (key, l) = lease(1, &chunks, 1000);

    assert_eq!(st.accept_lease(&l, &[[7; 16]], 0).unwrap(), Accept::NoRoom, "holding for others is off");
    assert_eq!(st.accept_lease(&l, &[[7; 16]], 3 * LEASE_CHUNK_ESTIMATE).unwrap(), Accept::Accepted);
    assert_eq!(st.accept_lease(&l, &[], 3 * LEASE_CHUNK_ESTIMATE).unwrap(), Accept::Accepted, "idempotent");
    let (_, other) = lease(1, &chunks[..1], 1000);
    assert_eq!(st.accept_lease(&other, &[], u64::MAX).unwrap(), Accept::Conflict, "same id, other content");

    let wants = st.lease_wants().unwrap();
    assert_eq!(wants.len(), 1);
    assert_eq!(wants[0].1.len(), 3);
    assert_eq!(wants[0].0.sources, vec![[7; 16]]);
    // Served under the chunk's token even before it arrives (answers "don't have" until then).
    assert_eq!(st.serving_token(&chunks[0].cid).unwrap(), Some(ChunkToken::for_seed(&chunks[0].seed)));

    for c in &chunks[..2] {
        assert!(st.lease_arrived(&c.cid, &c.ciphertext).unwrap());
    }
    assert!(!st.lease_arrived(&chunk(9).cid, &chunk(9).ciphertext).unwrap(), "not leased: refused");
    let h = st.held_lease(&l.id).unwrap().unwrap();
    assert_eq!((h.held, h.lease.entries.len()), (2, 3));
    assert_eq!(st.usage().unwrap().leased, 2 * 4096);
    assert_eq!(st.lease_chunk(&l.id, 1).unwrap().unwrap(), chunks[1].ciphertext);

    // Renewal: only the lease key, only later.
    assert!(!st.renew_lease(&Renewal::sign(&LeaseKey::derive(&[8; 32], &[1; 16]), [1; 16], 2000)).unwrap());
    assert!(!st.renew_lease(&Renewal::sign(&key, [1; 16], 900)).unwrap());
    assert!(st.renew_lease(&Renewal::sign(&key, [1; 16], 2000)).unwrap());
    assert_eq!(st.expire_leases(1500).unwrap(), 0, "renewed");

    assert_eq!(st.expire_leases(2500).unwrap(), 1);
    assert!(st.fetch(&chunks[0].cid).unwrap().is_none(), "leased-only chunk removed");
    assert_eq!(st.serving_token(&chunks[0].cid).unwrap(), None, "no longer served");
    assert_eq!(st.usage().unwrap().leased, 0);
    assert!(st.lease_wants().unwrap().is_empty());
}

#[test]
fn shared_chunks_survive_until_the_last_lease_and_own_data_stays() {
    let (_d, st) = store();
    let (a, b, own) = (chunk(1), chunk(2), chunk(3));
    st.insert(&own.cid, &own.ciphertext, tier::PINNED).unwrap();
    st.register_serving(&[(own.cid, ChunkToken::for_seed(&own.seed))]).unwrap();
    let (_, l1) = lease(1, &[a.clone(), own.clone()], 100);
    let (_, l2) = lease(2, &[a.clone(), b.clone()], 200);
    st.accept_lease(&l1, &[], u64::MAX).unwrap();
    st.accept_lease(&l2, &[], u64::MAX).unwrap();
    for c in [&a, &b] {
        st.lease_arrived(&c.cid, &c.ciphertext).unwrap();
    }
    assert_eq!(st.tier(&own.cid).unwrap(), Some(tier::PINNED | tier::SERVING), "already local: kept at once");

    assert_eq!(st.expire_leases(150).unwrap(), 1);
    assert!(st.fetch(&a.cid).unwrap().is_some(), "still kept by lease 2");
    assert_eq!(st.tier(&own.cid).unwrap(), Some(tier::PINNED));
    assert!(st.serving_token(&own.cid).unwrap().is_some(), "own data still served");

    assert_eq!(st.expire_leases(250).unwrap(), 1);
    assert!(st.fetch(&a.cid).unwrap().is_none() && st.fetch(&b.cid).unwrap().is_none());
}

#[test]
fn owner_counts_holders_with_valid_receipts() {
    let (_d, st) = store();
    let chunks: Vec<Sealed> = (0..2).map(chunk).collect();
    let root = chunks[0].cid;
    let (_, l1) = lease(1, &chunks, 1000);
    let (_, l2) = lease(2, &chunks, 1000);
    st.record_own_lease(&l1, &[1; 16], &[root]).unwrap();
    st.record_own_lease(&l2, &[2; 16], &[root]).unwrap();
    assert!(st.confirmed_holders(&root, 10).unwrap().is_empty(), "no receipts yet");

    let mut own = st.own_leases().unwrap();
    for o in &mut own {
        let r = Receipt::sign(&[5; 64], &o.lease, 1000);
        assert_eq!(r.lease_digest, o.lease.digest());
        o.receipt_until = r.holds_until;
    }
    own[1].proof = ProofState::Failed;
    for o in &own {
        st.update_own_lease(o).unwrap();
    }
    let holder_ok = own.iter().find(|o| o.proof != ProofState::Failed).unwrap().holder;
    assert_eq!(st.confirmed_holders(&root, 10).unwrap(), vec![holder_ok]);
    assert!(st.confirmed_holders(&root, 1001).unwrap().is_empty(), "receipts ran out");
}

#[test]
fn placement_state_ranks_nodes_and_learns_reliability() {
    let (_d, st) = store();
    st.heard_storage_node(&[1; 16], 3, None, None, 100).unwrap();
    st.heard_storage_node(&[2; 16], 1, None, None, 50).unwrap();
    st.heard_storage_node(&[3; 16], 1, None, None, 90).unwrap();
    st.avoid_storage_node(&[3; 16], 500).unwrap();
    st.heard_storage_node(&[3; 16], 1, None, None, 95).unwrap();
    let nodes = st.storage_nodes().unwrap();
    assert_eq!(nodes.iter().map(|n| n.peer[0]).collect::<Vec<_>>(), vec![3, 2, 1], "nearest, then freshest");
    assert_eq!(nodes[0].avoid_until_ms, 500, "hearing a node again keeps its back-off");

    let fresh = st.holder_stats(&[9; 16]).unwrap();
    assert!((fresh.loss() - 0.1).abs() < 1e-9, "a new holder counts as 10 %");
    for _ in 0..100 {
        st.holder_result(&[9; 16], true, 1).unwrap();
    }
    assert!(st.holder_stats(&[9; 16]).unwrap().loss() < 0.01, "a reliable record lowers it");
    let flaky = st.holder_result(&[8; 16], false, 1).unwrap();
    assert!(flaky.loss() > 0.1);

    let file = retifs_core::FileRef { root: chunk(1).cid, seed: chunk(1).seed, size: 3000 };
    st.need_file(&file).unwrap();
    assert_eq!(st.needed_files().unwrap(), vec![file]);
}

#[test]
fn link_quality_from_rtt_then_measurements() {
    use retifs_store::LinkQuality;
    let (_d, st) = store();
    let fast = [1u8; 16];
    let lora = [2u8; 16];
    st.record_rtt(&fast, 40).unwrap();
    st.record_rtt(&lora, 2500).unwrap();
    assert!(!st.link_quality(&fast).unwrap().slow());
    let q = st.link_quality(&lora).unwrap();
    assert!(q.slow(), "a slow round trip means LoRa-class until measured");
    assert!(q.transfer_secs(1 << 30) > 80.0 * 86_400.0, "1 GiB over LoRa: months");
    assert!(q.transfer_secs(900) < 10.0, "a tiny file still crosses quickly");

    // A slow round trip but a fast measured transfer (a busy long path, not LoRa).
    st.record_transfer(&lora, 256 * 1024, 2000).unwrap();
    assert!(!st.link_quality(&lora).unwrap().slow());
    // Tiny transfers don't count.
    st.record_transfer(&fast, 100, 10_000).unwrap();
    assert_eq!(st.link_quality(&fast).unwrap().samples, 0);
    assert!(!LinkQuality::default().slow(), "never linked: no reason to call it slow");
}

#[test]
fn forgetting_drops_leases_and_releases_only_unshared_own_chunks() {
    let (_d, st) = store();
    let (only_v1, shared, held_for_other) = (chunk(1), chunk(2), chunk(3));
    for c in [&only_v1, &shared] {
        st.insert(&c.cid, &c.ciphertext, tier::PINNED).unwrap();
        st.register_serving(&[(c.cid, ChunkToken::for_seed(&c.seed))]).unwrap();
    }
    // Also pinned here, and kept for someone else under their lease.
    st.insert(&held_for_other.cid, &held_for_other.ciphertext, tier::PINNED).unwrap();
    let (_, theirs) = lease(9, std::slice::from_ref(&held_for_other), 1000);
    st.accept_lease(&theirs, &[], u64::MAX).unwrap();

    let v1 = retifs_core::FileRef { root: only_v1.cid, seed: only_v1.seed, size: 3000 };
    st.need_file(&v1).unwrap();
    let (_, mine) = lease(1, &[only_v1.clone(), shared.clone()], 1000);
    st.record_own_lease(&mine, &[5; 16], &[v1.root]).unwrap();

    assert_eq!(st.forget_file(&v1.root).unwrap(), 1, "its lease is no longer renewed");
    assert!(st.needed_files().unwrap().is_empty());
    assert!(st.own_leases().unwrap().is_empty());

    // `shared` is still used by another needed version: the caller leaves it out.
    assert_eq!(st.release_chunks(&[only_v1.cid, held_for_other.cid]).unwrap(), 1);
    assert_eq!(st.tier(&only_v1.cid).unwrap(), Some(tier::CACHE), "evictable now");
    assert!(st.serving_token(&only_v1.cid).unwrap().is_none(), "no longer served");
    assert_eq!(st.tier(&shared.cid).unwrap(), Some(tier::PINNED));
    assert_eq!(st.tier(&held_for_other.cid).unwrap(), Some(tier::CACHE | tier::SERVING), "still kept for them");
    assert!(st.serving_token(&held_for_other.cid).unwrap().is_some());
}

#[test]
fn surplus_copies_are_trimmed_with_hysteresis() {
    use retifs_store::{surplus_holder, HolderView};
    let h = |n: u8, loss: f64, hops: u8, confirmed: bool| HolderView { peer: [n; 16], loss, hops, confirmed };
    let target = 1e-3;
    // Exactly at the target with two holders: nothing to trim.
    assert_eq!(surplus_holder(0.1, &[h(1, 0.1, 1, true), h(2, 0.1, 1, true)], target), None);
    // A third copy after a repair, and the flaky one recovered a little: 0.1 × 0.02 × 0.02
    // without the flaky holder is 4e-5, well under half the target. The worst record goes.
    let after_repair = [h(1, 0.02, 1, true), h(2, 0.15, 1, true), h(3, 0.02, 4, true)];
    assert_eq!(surplus_holder(0.1, &after_repair, target), Some([2; 16]));
    // Never while a placement is in progress (a holder without a receipt yet).
    let pending = [h(1, 0.02, 1, true), h(2, 0.15, 1, true), h(3, 0.02, 4, false)];
    assert_eq!(surplus_holder(0.1, &pending, target), None);
    // Equal records: the farthest goes.
    let equal = [h(1, 0.01, 1, true), h(2, 0.01, 5, true), h(3, 0.01, 2, true)];
    assert_eq!(surplus_holder(0.1, &equal, target), Some([2; 16]));
    // Just under the target but not under half of it: keep (hysteresis).
    assert_eq!(surplus_holder(0.1, &[h(1, 0.09, 1, true), h(2, 0.5, 1, true)], target * 1.0), None);
}

#[test]
fn mixed_leases_turn_stale_when_one_file_goes() {
    let (_d, st) = store();
    let (a, b) = (chunk(1).cid, chunk(2).cid);
    let (_, mixed) = lease(1, &[chunk(1), chunk(2), chunk(3)], 1000);
    let (_, only_a) = lease(2, &[chunk(1)], 1000);
    st.record_own_lease(&mixed, &[7; 16], &[a, b]).unwrap();
    st.record_own_lease(&only_a, &[8; 16], &[a]).unwrap();
    assert_eq!(st.own_leases_for(&a).unwrap().len(), 2);

    // Trim `a` at holder 7: the mixed lease still serves `b`, so it turns stale.
    assert_eq!(st.drop_holder(&a, &[7; 16]).unwrap(), 1);
    let m = st.own_leases_for(&b).unwrap();
    assert_eq!((m.len(), m[0].roots.clone(), m[0].stale), (1, vec![b], true));
    assert_eq!(st.own_leases_for(&a).unwrap().len(), 1, "a is still kept at holder 8");

    // Forget `a` entirely: its single-file lease goes; the stale one is untouched.
    st.need_file(&retifs_core::FileRef { root: a, seed: chunk(1).seed, size: 3000 }).unwrap();
    assert_eq!(st.forget_file(&a).unwrap(), 1);
    assert!(st.own_leases_for(&a).unwrap().is_empty());
    assert_eq!(st.own_leases().unwrap().len(), 1);
    // And forgetting `b` drops the last one.
    assert_eq!(st.forget_file(&b).unwrap(), 1);
    assert!(st.own_leases().unwrap().is_empty());
}


#[test]
fn channels_and_follows_roundtrip() {
    use retifs_core::channel::ChannelKey;
    let (_d, st) = store();
    assert!(st.create_channel("news", [1; 32], [2; 32]).unwrap());
    assert!(!st.create_channel("news", [3; 32], [4; 32]).unwrap(), "names are unique");
    let mut c = st.own_channel("news").unwrap().unwrap();
    assert_eq!((c.seq, c.last, c.head.len()), (0, None, 0));
    c.seq = 3;
    c.last = Some((chunk(1).cid, chunk(1).seed));
    c.head = vec![7; 258];
    st.update_own_channel(&c).unwrap();
    let back = st.own_channel("news").unwrap().unwrap();
    assert_eq!((back.seq, back.last, back.head.clone()), (3, c.last, vec![7; 258]));
    let addr = ChannelKey::from_secrets([1; 32], [2; 32]).addr();
    assert_eq!(st.head_for(&addr.ns_id()).unwrap(), Some(vec![7; 258]), "own heads are served");

    let other = ChannelKey::from_secrets([5; 32], [6; 32]).addr();
    st.follow(&other, &[[9; 16]]).unwrap();
    let mut f = st.follow(&other, &[[9; 16], [8; 16]]).unwrap();
    assert_eq!(f.hints, vec![[9; 16], [8; 16]]);
    f.seq = 2;
    f.current = Some(retifs_core::FileRef { root: chunk(2).cid, seed: chunk(2).seed, size: 5 });
    f.head = vec![1; 258];
    st.update_follow(&f).unwrap();
    let g = st.followed(&other.ns_id()).unwrap().unwrap();
    assert_eq!((g.seq, g.current, g.previous, g.hints.len()), (2, f.current, None, 2));
    assert_eq!(st.head_for(&other.ns_id()).unwrap(), Some(vec![1; 258]));
    assert_eq!(st.follows().unwrap().len(), 1);
}

#[test]
fn storage_nodes_keep_their_announce_interval_and_are_forgotten_when_silent() {
    let (_d, st) = store();
    st.heard_storage_node(&[1; 16], 1, Some(60), None, 1_000).unwrap();
    st.heard_storage_node(&[2; 16], 1, None, None, 1_000).unwrap();
    let every: Vec<(u8, u32)> = st.storage_nodes().unwrap().iter().map(|n| (n.peer[0], n.announce_s)).collect();
    assert!(every.contains(&(1, 60)) && every.contains(&(2, 600)), "{every:?}: unsaid means the default");
    // Silent for ten of its own intervals: node 1 (60 s) goes, node 2 (600 s) stays.
    let n = st.forget_silent_storage_nodes(1_000 + 700_000, |s| 10 * s.announce_s as u64 * 1000).unwrap();
    assert_eq!(n, 1);
    assert_eq!(st.storage_nodes().unwrap().iter().map(|n| n.peer[0]).collect::<Vec<_>>(), vec![2]);
    st.heard_storage_node(&[1; 16], 1, Some(60), None, 800_000).unwrap();
    assert_eq!(st.storage_nodes().unwrap().len(), 2, "its next announce brings it back");
}

#[test]
fn placement_carries_over_to_a_fresh_store_with_attached_chunks() {
    let (_d, st) = store();
    let (file_chunk, commit) = (chunk(1), chunk(2));
    let file = retifs_core::FileRef { root: file_chunk.cid, seed: file_chunk.seed, size: 3000 };
    st.need_file_with(&file, &[(commit.cid, commit.seed)]).unwrap();
    st.need_file_with(&file, &[(commit.cid, commit.seed)]).unwrap();
    st.need_file(&file).unwrap();
    assert_eq!(st.attached(&file.root).unwrap(), vec![(commit.cid, commit.seed)], "kept once, and kept by a later need");
    let (_, l) = lease(3, &[file_chunk.clone(), commit.clone()], 5000);
    st.record_own_lease(&l, &[4; 16], &[file.root]).unwrap();

    // A storage-less node's store after a restart: only what was carried.
    let dir = tempfile::tempdir().unwrap();
    let fresh = SlabStore::open_in_memory(dir.path(), 1 << 20).unwrap();
    let rows = fresh.import_placement(&st.export_placement().unwrap()).unwrap();
    assert_eq!(rows, 2);
    assert_eq!(fresh.needed_files().unwrap(), vec![file]);
    assert_eq!(fresh.attached(&file.root).unwrap(), vec![(commit.cid, commit.seed)]);
    let own = fresh.own_leases().unwrap();
    assert_eq!((own.len(), own[0].holder, own[0].lease.id), (1, [4; 16], l.id));
    assert_eq!(fresh.import_placement(&[9, 9, 9]).unwrap(), 0, "unknown version: nothing");
}
