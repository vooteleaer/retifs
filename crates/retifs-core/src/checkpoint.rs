//! Namespace checkpoints (ADR-0018): the merged state at given points of
//! every writer's chain, so a node resumes from it instead of replaying.
//!
//! ```text
//! checkpoint = { "control":  [ [ stamp, op ], … ],                     every control operation, by stamp
//!                "frontier": [ [ writer (bin 32), seq, time_ms, commit cid (bin 33) ], … ],   by writer
//!                "high":     nil | stamp,                              the highest data stamp seen
//!                "retifs":   "ns-checkpoint/1",
//!                "state":    nil | [ root cid (bin 33), root seed (bin 32) ] }   Prolly tree of stamped records
//! ```
//! A checkpoint is a cache of a deterministic function: the state after each
//! writer's commits up to its frontier, without the tombstones that frontier
//! makes unneeded ([`State::prunable`]). Commits after it apply as usual; a
//! control operation older than `high` needs the history (rebuild).

use std::collections::BTreeMap;

use crate::{
    chunk::Seed,
    cid::Cid,
    manifest::Store,
    ops::{read_op, read_opt_stamp, read_stamp, write_op, write_stamp, Op, Stamp, StampedRecord, State, WriterCommit, WriterKey},
    prolly::{self, Root, TreeError},
    record::{canonical, write_array_len, write_bin, write_int, write_map_len, write_str, Reader, RecordError, Value},
    secret::ConvergenceSecret,
};

pub const CHECKPOINT_TAG: &str = "ns-checkpoint/1";
const STATE_LABEL: &[u8] = b"retifs/v1/state";

/// How far a checkpoint covers one writer's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frontier {
    pub writer: WriterKey,
    pub seq: u64,
    pub time_ms: u64,
    /// The commit at `seq`: a reader resuming from the checkpoint checks that
    /// the chain it walks reaches this commit.
    pub commit: Cid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub control: Vec<(Stamp, Op)>,
    pub frontier: Vec<Frontier>,
    pub high: Option<Stamp>,
    pub state: Option<Root>,
}

/// The convergence secret of a namespace's state trees: every member with
/// the read key builds the same tree from the same state.
pub fn state_secret(read_key: &[u8; 32]) -> ConvergenceSecret {
    ConvergenceSecret::for_record(read_key, STATE_LABEL)
}

impl Checkpoint {
    /// Stores `state`'s records as a Prolly tree and returns the checkpoint.
    pub fn save<S: Store>(
        store: &mut S,
        secret: &ConvergenceSecret,
        state: &State,
        mut frontier: Vec<Frontier>,
    ) -> Result<Checkpoint, TreeError<S::Error>> {
        frontier.sort_by_key(|f| f.writer);
        let mut state = state.clone();
        state.prune(&state.prunable(&Self::reach(&frontier)));
        let entries = state.stamped().into_iter().map(|(id, r)| (id, r.encode())).collect();
        let root = prolly::build(store, secret, entries)?;
        Ok(Checkpoint { control: state.control().to_vec(), frontier, high: state.high(), state: root })
    }

    fn reach(frontier: &[Frontier]) -> Vec<(WriterKey, u64, u64)> {
        frontier.iter().map(|f| (f.writer, f.seq, f.time_ms)).collect()
    }

    /// The state it describes (reads the whole tree).
    pub fn load<S: Store>(&self, store: &S, creator: &WriterKey) -> Result<State, TreeError<S::Error>> {
        let entries = match &self.state {
            Some(root) => prolly::read_all(store, root)?,
            None => Vec::new(),
        };
        let mut stamped = Vec::with_capacity(entries.len());
        for (id, bytes) in entries {
            stamped.push((id, StampedRecord::decode(&bytes).map_err(|_| TreeError::Corrupt("stamped record"))?));
        }
        Ok(State::restore(creator, self.control.clone(), self.high, stamped))
    }

    /// Checks the checkpoint against the history it claims to summarize:
    /// `chains` holds each frontier writer's commits from the first up to its
    /// frontier. Returns how the replayed state differs, if it does.
    pub fn check<S: Store>(
        &self,
        store: &S,
        creator: &WriterKey,
        chains: &BTreeMap<WriterKey, Vec<WriterCommit>>,
        now_ms: u64,
    ) -> Result<Option<&'static str>, TreeError<S::Error>> {
        let claimed = self.load(store, creator)?;
        for f in &self.frontier {
            let chain = chains.get(&f.writer).map(Vec::as_slice).unwrap_or_default();
            if chain.first().map(|c| c.seq) != Some(1) || chain.last().map(|c| (c.seq, c.time_ms)) != Some((f.seq, f.time_ms)) {
                return Ok(Some("the history given doesn't match its frontier"));
            }
        }
        if chains.keys().any(|w| !self.frontier.iter().any(|f| f.writer == *w)) {
            return Ok(Some("the history given has writers it doesn't name"));
        }
        let mut replayed = State::build(creator, chains, now_ms);
        replayed.prune(&replayed.prunable(&Self::reach(&self.frontier)));
        Ok(if replayed.control() != claimed.control() {
            Some("its grants, revokes or keys differ from the history")
        } else if replayed.high() != claimed.high() || replayed.stamped() != claimed.stamped() {
            Some("its records differ from the history")
        } else {
            None
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_map_len(&mut out, 5);
        write_str(&mut out, "control");
        write_array_len(&mut out, self.control.len());
        for (s, op) in &self.control {
            write_array_len(&mut out, 2);
            write_stamp(&mut out, s);
            write_op(&mut out, op);
        }
        write_str(&mut out, "frontier");
        write_array_len(&mut out, self.frontier.len());
        for f in &self.frontier {
            write_array_len(&mut out, 4);
            write_bin(&mut out, &f.writer);
            write_int(&mut out, f.seq as i64);
            write_int(&mut out, f.time_ms as i64);
            write_bin(&mut out, f.commit.as_bytes());
        }
        write_str(&mut out, "high");
        match &self.high {
            None => out.push(0xc0),
            Some(s) => write_stamp(&mut out, s),
        }
        write_str(&mut out, "retifs");
        write_str(&mut out, CHECKPOINT_TAG);
        write_str(&mut out, "state");
        match &self.state {
            None => out.push(0xc0),
            Some((cid, seed)) => {
                write_array_len(&mut out, 2);
                write_bin(&mut out, cid.as_bytes());
                write_bin(&mut out, &seed.0);
            }
        }
        out
    }

    pub fn is_checkpoint(bytes: &[u8]) -> bool {
        Checkpoint::decode(bytes).is_ok()
    }

    pub fn decode(bytes: &[u8]) -> Result<Checkpoint, RecordError> {
        let bad = RecordError::Malformed;
        let mut r = Reader(bytes);
        if r.map_len()? != 5 || r.str()? != "control" {
            return Err(bad("checkpoint fields"));
        }
        let n = r.array_len()?;
        let mut control = Vec::with_capacity(n.min(1 << 12));
        for _ in 0..n {
            if r.array_len()? != 2 {
                return Err(bad("control entry"));
            }
            control.push((read_stamp(&mut r)?, read_op(&mut r)?));
        }
        if r.str()? != "frontier" {
            return Err(bad("checkpoint fields"));
        }
        let n = r.array_len()?;
        let mut frontier = Vec::with_capacity(n.min(1 << 12));
        for _ in 0..n {
            if r.array_len()? != 4 {
                return Err(bad("frontier entry"));
            }
            let writer: WriterKey = r.bin()?.try_into().map_err(|_| bad("frontier writer"))?;
            let seq = uint(&mut r)?;
            let time_ms = uint(&mut r)?;
            let commit = Cid::from_bytes(r.bin()?.try_into().map_err(|_| bad("frontier commit"))?).ok_or(bad("CID version"))?;
            frontier.push(Frontier { writer, seq, time_ms, commit });
        }
        if r.str()? != "high" {
            return Err(bad("checkpoint fields"));
        }
        let high = read_opt_stamp(&mut r)?;
        if r.str()? != "retifs" || r.str()? != CHECKPOINT_TAG {
            return Err(bad("not a checkpoint"));
        }
        if r.str()? != "state" {
            return Err(bad("checkpoint fields"));
        }
        let state = if r.0.first() == Some(&0xc0) {
            r.byte()?;
            None
        } else {
            if r.array_len()? != 2 {
                return Err(bad("state root"));
            }
            let cid = Cid::from_bytes(r.bin()?.try_into().map_err(|_| bad("root cid"))?).ok_or(bad("CID version"))?;
            let seed = Seed(r.bin()?.try_into().map_err(|_| bad("root seed"))?);
            Some((cid, seed))
        };
        if !r.0.is_empty() {
            return Err(bad("trailing bytes"));
        }
        if !control.windows(2).all(|w| w[0].0 < w[1].0) || !frontier.windows(2).all(|w| w[0].writer < w[1].writer) {
            return Err(bad("checkpoint order"));
        }
        let cp = Checkpoint { control, frontier, high, state };
        canonical(bytes, cp.encode())?;
        Ok(cp)
    }
}

fn uint(r: &mut Reader) -> Result<u64, RecordError> {
    match r.value(0)? {
        Value::Int(i) if i >= 0 => Ok(i as u64),
        _ => Err(RecordError::Malformed("number")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{merge, Right};
    use std::collections::HashMap;

    #[derive(Default)]
    struct Mem(HashMap<Cid, Vec<u8>>);
    impl Store for Mem {
        type Error = std::convert::Infallible;
        fn put(&mut self, cid: Cid, ct: Vec<u8>) -> Result<(), Self::Error> {
            self.0.insert(cid, ct);
            Ok(())
        }
        fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(cid).cloned())
        }
    }

    const ALICE: WriterKey = [0xa1; 32];
    const BOB: WriterKey = [0xb0; 32];
    const EVE: WriterKey = [0xe5; 32];

    type Chains = BTreeMap<WriterKey, Vec<WriterCommit>>;

    fn rng(mut seed: u64) -> impl FnMut(u64) -> u64 {
        move |n| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        }
    }

    /// Random chains of three writers with grants, revokes, deletes and
    /// same-millisecond commits; each writer's times increase.
    fn history(rnd: &mut impl FnMut(u64) -> u64) -> Chains {
        let writers = [ALICE, BOB, EVE];
        let ids: Vec<[u8; 16]> = (0..4u8).map(|i| [i; 16]).collect();
        let mut chains = Chains::new();
        for w in writers {
            let mut t = 0;
            for _ in 0..rnd(6) {
                t += rnd(30);
                let ops = (0..1 + rnd(4))
                    .map(|_| {
                        let id = ids[rnd(4) as usize];
                        let k = ["a", "b"][rnd(2) as usize].to_string();
                        match rnd(10) {
                            0..=3 => Op::Set(id, k, Value::Int(rnd(5) as i64)),
                            4 => Op::Unset(id, k),
                            5 => Op::Blocks(id, vec![]),
                            6 => Op::Delete(id),
                            7 => {
                                    let w = writers[rnd(3) as usize];
                                    let rights = if rnd(2) == 0 { vec![Right::Write] } else { vec![Right::Write, Right::Grant] };
                                    if rnd(2) == 0 {
                                        Op::Grant(w, rights)
                                    } else {
                                        // Limited: some of the keys, maybe an expiry.
                                        let keys = (rnd(3) != 0).then(|| {
                                            ["a", "b", "c", crate::ops::CONTENT_KEY, crate::ops::DELETE_KEY]
                                                .iter()
                                                .filter(|_| rnd(2) == 0)
                                                .map(|k| k.to_string())
                                                .collect()
                                        });
                                        let until = (keys.is_none() || rnd(2) == 0).then(|| rnd(250));
                                        Op::GrantLimited(w, rights, crate::ops::Limits { keys, until })
                                    }
                                }
                            8 => Op::Revoke(writers[rnd(3) as usize]),
                            _ => Op::Set(id, k, Value::Bool(true)),
                        }
                    })
                    .collect();
                let list = chains.entry(w).or_default();
                let seq = list.len() as u64 + 1;
                list.push(WriterCommit { seq, time_ms: t, ops });
            }
        }
        chains
    }

    /// A node receiving commits in random order (each writer's in sequence),
    /// applying them incrementally, rebuilding only when told to, and once
    /// restarting from a checkpoint: always the same as replaying everything.
    #[test]
    fn incremental_with_checkpoint_matches_replay() {
        let mut rnd = rng(0x2545_f491_4f6c_dd1d);
        let secret = state_secret(&[1; 32]);
        let mut store = Mem::default();
        let (mut rebuilds, mut in_place) = (0, 0);
        for _ in 0..1500 {
            let all = history(&mut rnd);
            // Arrival order: interleave writers at random, keeping each chain's order.
            let mut next: BTreeMap<WriterKey, usize> = all.keys().map(|w| (*w, 0)).collect();
            let mut held = Chains::new();
            let mut state = State::with_control(&ALICE, Vec::new());
            let total: usize = all.values().map(Vec::len).sum();
            let restart_at = rnd(total as u64 + 1) as usize;
            for step in 0..total {
                let open: Vec<WriterKey> = next.iter().filter(|(w, i)| **i < all[*w].len()).map(|(w, _)| *w).collect();
                let w = open[rnd(open.len() as u64) as usize];
                let c = &all[&w][next[&w]];
                *next.get_mut(&w).unwrap() += 1;
                held.entry(w).or_default().push(c.clone());
                if state.apply_commit(&w, c) {
                    in_place += 1;
                } else {
                    rebuilds += 1;
                    state = State::build(&ALICE, &held, 10_000);
                }
                assert_eq!(state.records(), merge(&ALICE, &held, 10_000).records, "after {} commits", step + 1);
                if step + 1 == restart_at {
                    let frontier = held
                        .iter()
                        .map(|(w, c)| Frontier { writer: *w, seq: c.len() as u64, time_ms: c.last().unwrap().time_ms, commit: Cid::of(&c.len().to_be_bytes()) })
                        .collect();
                    let cp = Checkpoint::save(&mut store, &secret, &state, frontier).unwrap();
                    let cp = Checkpoint::decode(&cp.encode()).unwrap();
                    state = cp.load(&store, &ALICE).unwrap();
                    assert_eq!(state.records(), merge(&ALICE, &held, 10_000).records, "restored");
                }
            }
            let expect = merge(&ALICE, &all, 10_000);
            assert_eq!(state.merged().writers, expect.writers);
        }
        // Most control operations arrive after the data they could affect is
        // older than them: they apply in place.
        assert!(in_place > rebuilds * 4, "in place {in_place}, rebuilds {rebuilds}");
    }

    /// An honest checkpoint checks out; one that leaves out a write, a
    /// delete or a revoke, or adds a record, doesn't.
    #[test]
    fn check_finds_forged_checkpoints() {
        fn id(i: u8) -> [u8; 16] {
            [i; 16]
        }
        let c = |seq, time_ms, ops| WriterCommit { seq, time_ms, ops };
        let mut chains = Chains::new();
        chains.insert(
            ALICE,
            vec![
                c(1, 10, vec![Op::Grant(BOB, vec![Right::Write, Right::Grant]), Op::Set(id(1), "a".into(), Value::Int(1))]),
                c(2, 30, vec![Op::Revoke(BOB), Op::Delete(id(2))]),
            ],
        );
        chains.insert(BOB, vec![c(1, 20, vec![Op::Set(id(2), "b".into(), Value::Int(2)), Op::Set(id(3), "c".into(), Value::Int(3))])]);
        let frontier = |ch: &Chains| -> Vec<Frontier> {
            ch.iter()
                .map(|(w, c)| Frontier { writer: *w, seq: c.len() as u64, time_ms: c.last().unwrap().time_ms, commit: Cid::of(w) })
                .collect()
        };
        let secret = state_secret(&[3; 32]);
        let mut store = Mem::default();
        let honest = Checkpoint::save(&mut store, &secret, &State::build(&ALICE, &chains, 1_000), frontier(&chains)).unwrap();
        assert_eq!(honest.check(&store, &ALICE, &chains, 1_000).unwrap(), None);

        // Each forgery: a state from an altered history, claiming the real frontier.
        let forge = |store: &mut Mem, alter: &dyn Fn(&mut Chains)| {
            let mut fake = chains.clone();
            alter(&mut fake);
            Checkpoint::save(store, &secret, &State::build(&ALICE, &fake, 1_000), frontier(&chains)).unwrap()
        };
        type Alter = dyn Fn(&mut Chains);
        let cases: [(&str, &Alter); 4] = [
            ("without Bob's write", &|ch| ch.get_mut(&BOB).unwrap()[0].ops.pop().map(|_| ()).unwrap()),
            ("without the delete", &|ch| ch.get_mut(&ALICE).unwrap()[1].ops.truncate(1)),
            ("without the revoke", &|ch| {
                ch.get_mut(&ALICE).unwrap()[1].ops.remove(0);
            }),
            ("with an extra record", &|ch| ch.get_mut(&ALICE).unwrap()[0].ops.push(Op::Set(id(9), "x".into(), Value::Bool(true)))),
        ];
        for (name, alter) in cases {
            let forged = forge(&mut store, alter);
            assert!(forged.check(&store, &ALICE, &chains, 1_000).unwrap().is_some(), "{name}");
        }
        // The history given must be the whole history up to the frontier.
        let mut short = chains.clone();
        short.get_mut(&ALICE).unwrap().pop();
        assert!(honest.check(&store, &ALICE, &short, 1_000).unwrap().is_some());
    }

    #[test]
    fn decode_rejects_unsorted_and_noncanonical() {
        let f = |w: u8| Frontier { writer: [w; 32], seq: 1, time_ms: 5, commit: Cid::of(&[w]) };
        let cp = Checkpoint { control: vec![((1, ALICE, 1, 0), Op::Grant(BOB, vec![Right::Write]))], frontier: vec![f(1), f(2)], high: Some((3, BOB, 1, 0)), state: None };
        assert_eq!(Checkpoint::decode(&cp.encode()).unwrap(), cp);
        let swapped = Checkpoint { frontier: vec![f(2), f(1)], ..cp.clone() };
        assert!(Checkpoint::decode(&swapped.encode()).is_err());
        let mut bytes = cp.encode();
        bytes.push(0xc0);
        assert!(Checkpoint::decode(&bytes).is_err());
    }
}
