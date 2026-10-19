//! Operation chains and their merge (ADR-0017; decisions 4 and 8). Draft v1.
//!
//! A namespace commit's tree is an operations file:
//! ```text
//! ops file = { "ops": [ op, … ], "retifs": "ns-ops/1" }        canonical msgpack (ADR-0016)
//! op       = [ "set", id, key, value ] | [ "unset", id, key ] | [ "blocks", id, [ ref, … ] ]
//!          | [ "delete", id ] | [ "grant", writer (bin 32), [ right, … ] ] | [ "revoke", writer ]
//!          | [ "identity", public (bin 64) ]                     the signer's RNS identity (X25519 ‖ Ed25519)
//!          | [ "rekey", epoch, [ [ writer (bin 32), wrapped (bin) ], … sorted by writer ] ]
//! right    = "grant" | "write"                                   sorted, unique
//! ```
//! Every reader replays all writers' operations in stamp order —
//! `(commit time, writer key, index in commit)` — and so reaches the same
//! state from the same operations, whatever order they arrived in. Writes
//! count only if their writer held `write` at that stamp; grants and revokes
//! only if it held `grant`. The creator holds both, always.

use std::collections::BTreeMap;

use crate::{
    manifest::FileRef,
    record::{
        canonical, read_block, write_array_len, write_bin, write_block, write_map_len, write_str, write_value, Reader,
        Record, RecordError, RecordId, Value,
    },
};

pub const OPS_TAG: &str = "ns-ops/1";
/// Commits dated further ahead of the reader's clock are ignored.
pub const MAX_CLOCK_AHEAD_MS: u64 = 24 * 3600 * 1000;

pub type WriterKey = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Right {
    Grant,
    Write,
}

impl Right {
    fn name(self) -> &'static str {
        match self {
            Right::Grant => "grant",
            Right::Write => "write",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Set(RecordId, String, Value),
    Unset(RecordId, String),
    Blocks(RecordId, Vec<FileRef>),
    Delete(RecordId),
    /// Sets the writer's rights (replacing earlier ones).
    Grant(WriterKey, Vec<Right>),
    Revoke(WriterKey),
    /// The signer's public identity (X25519 ‖ Ed25519), so others can wrap keys to it.
    /// Counts only if its Ed25519 half is the signer's own key.
    Identity([u8; 64]),
    /// A new read key for epoch `epoch`, wrapped to each remaining writer
    /// (keywrap: RNS `Identity.encrypt`). Counts only from a writer holding `grant`.
    Rekey(u64, Vec<(WriterKey, Vec<u8>)>),
}

/// One commit's operations.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OpsFile {
    pub ops: Vec<Op>,
}

impl OpsFile {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_map_len(&mut out, 2);
        write_str(&mut out, "ops");
        write_array_len(&mut out, self.ops.len());
        for op in &self.ops {
            write_op(&mut out, op);
        }
        write_str(&mut out, "retifs");
        write_str(&mut out, OPS_TAG);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<OpsFile, RecordError> {
        let mut r = Reader(bytes);
        if r.map_len()? != 2 || r.str()? != "ops" {
            return Err(RecordError::Malformed("ops file fields"));
        }
        let n = r.array_len()?;
        let mut ops = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            ops.push(read_op(&mut r)?);
        }
        if r.str()? != "retifs" || r.str()? != OPS_TAG || !r.0.is_empty() {
            return Err(RecordError::Malformed("not an ops file"));
        }
        let f = OpsFile { ops };
        canonical(bytes, f.encode())?;
        Ok(f)
    }

    pub fn is_ops(bytes: &[u8]) -> bool {
        bytes.ends_with(OPS_TAG.as_bytes())
    }
}

fn write_op(out: &mut Vec<u8>, op: &Op) {
    match op {
        Op::Set(id, k, v) => {
            write_array_len(out, 4);
            write_str(out, "set");
            write_bin(out, id);
            write_str(out, k);
            write_value(out, v);
        }
        Op::Unset(id, k) => {
            write_array_len(out, 3);
            write_str(out, "unset");
            write_bin(out, id);
            write_str(out, k);
        }
        Op::Blocks(id, blocks) => {
            write_array_len(out, 3);
            write_str(out, "blocks");
            write_bin(out, id);
            write_array_len(out, blocks.len());
            for b in blocks {
                write_block(out, b);
            }
        }
        Op::Delete(id) => {
            write_array_len(out, 2);
            write_str(out, "delete");
            write_bin(out, id);
        }
        Op::Grant(w, rights) => {
            let mut rights = rights.clone();
            rights.sort();
            rights.dedup();
            write_array_len(out, 3);
            write_str(out, "grant");
            write_bin(out, w);
            write_array_len(out, rights.len());
            for r in rights {
                write_str(out, r.name());
            }
        }
        Op::Revoke(w) => {
            write_array_len(out, 2);
            write_str(out, "revoke");
            write_bin(out, w);
        }
        Op::Identity(p) => {
            write_array_len(out, 2);
            write_str(out, "identity");
            write_bin(out, p);
        }
        Op::Rekey(epoch, entries) => {
            let mut entries = entries.clone();
            entries.sort_by_key(|(w, _)| *w);
            write_array_len(out, 3);
            write_str(out, "rekey");
            crate::record::write_int(out, *epoch as i64);
            write_array_len(out, entries.len());
            for (w, wrapped) in entries {
                write_array_len(out, 2);
                write_bin(out, &w);
                write_bin(out, &wrapped);
            }
        }
    }
}

fn read_op(r: &mut Reader) -> Result<Op, RecordError> {
    let n = r.array_len()?;
    let tag = r.str()?;
    let id = |r: &mut Reader| -> Result<RecordId, RecordError> {
        r.bin()?.try_into().map_err(|_| RecordError::Malformed("record id"))
    };
    let writer = |r: &mut Reader| -> Result<WriterKey, RecordError> {
        r.bin()?.try_into().map_err(|_| RecordError::Malformed("writer key"))
    };
    let op = match (tag.as_str(), n) {
        ("set", 4) => {
            let i = id(r)?;
            let k = r.str()?;
            Op::Set(i, k, r.value(0)?)
        }
        ("unset", 3) => {
            let i = id(r)?;
            Op::Unset(i, r.str()?)
        }
        ("blocks", 3) => {
            let i = id(r)?;
            let m = r.array_len()?;
            let mut blocks = Vec::with_capacity(m.min(1 << 12));
            for _ in 0..m {
                blocks.push(read_block(r)?);
            }
            Op::Blocks(i, blocks)
        }
        ("delete", 2) => Op::Delete(id(r)?),
        ("grant", 3) => {
            let w = writer(r)?;
            let m = r.array_len()?;
            let mut rights = Vec::new();
            for _ in 0..m {
                rights.push(match r.str()?.as_str() {
                    "grant" => Right::Grant,
                    "write" => Right::Write,
                    _ => return Err(RecordError::Malformed("unknown right")),
                });
            }
            Op::Grant(w, rights)
        }
        ("revoke", 2) => Op::Revoke(writer(r)?),
        ("identity", 2) => Op::Identity(r.bin()?.try_into().map_err(|_| RecordError::Malformed("identity"))?),
        ("rekey", 3) => {
            let epoch = match r.value(0)? {
                Value::Int(e) if e >= 0 => e as u64,
                _ => return Err(RecordError::Malformed("rekey epoch")),
            };
            let m = r.array_len()?;
            let mut entries = Vec::with_capacity(m.min(1 << 10));
            for _ in 0..m {
                if r.array_len()? != 2 {
                    return Err(RecordError::Malformed("rekey entry"));
                }
                let w = writer(r)?;
                entries.push((w, r.bin()?));
            }
            Op::Rekey(epoch, entries)
        }
        _ => return Err(RecordError::Malformed("unknown operation")),
    };
    Ok(op)
}

/// One commit of one writer, as the merge sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct WriterCommit {
    pub time_ms: u64,
    pub ops: Vec<Op>,
}

/// A valid rekey: who issued it, when, and the wrapped keys.
#[derive(Debug, Clone, PartialEq)]
pub struct RekeyEvent {
    pub epoch: u64,
    pub time_ms: u64,
    pub by: WriterKey,
    pub entries: Vec<(WriterKey, Vec<u8>)>,
}

/// The merged state of a namespace.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Merged {
    /// Writers' public identities, as they announced them.
    pub identities: BTreeMap<WriterKey, [u8; 64]>,
    /// Valid rekeys, in stamp order.
    pub rekeys: Vec<RekeyEvent>,
    /// Visible records, by ID.
    pub records: Vec<Record>,
    /// Writers and their rights at the end.
    pub writers: BTreeMap<WriterKey, Vec<Right>>,
    /// Operations that didn't count (no right at their stamp), and commits
    /// ignored for their dates.
    pub ignored_ops: usize,
    pub ignored_commits: usize,
}

/// Replays every writer's chain (each in sequence order) in stamp order.
pub fn merge(creator: &WriterKey, chains: &BTreeMap<WriterKey, Vec<WriterCommit>>, now_ms: u64) -> Merged {
    let mut m = Merged::default();
    // Stamp every operation; drop commits dated before their predecessor or too far ahead.
    let mut events: Vec<(u64, WriterKey, usize, &Op)> = Vec::new();
    for (writer, chain) in chains {
        let mut last = 0u64;
        for c in chain {
            if c.time_ms < last || c.time_ms > now_ms.saturating_add(MAX_CLOCK_AHEAD_MS) {
                m.ignored_commits += 1;
                continue;
            }
            last = c.time_ms;
            for (i, op) in c.ops.iter().enumerate() {
                events.push((c.time_ms, *writer, i, op));
            }
        }
    }
    events.sort_by_key(|a| (a.0, a.1, a.2));

    let mut rights: BTreeMap<WriterKey, Vec<Right>> = BTreeMap::new();
    rights.insert(*creator, vec![Right::Grant, Right::Write]);
    let mut records: BTreeMap<RecordId, Record> = BTreeMap::new();
    let has = |rights: &BTreeMap<WriterKey, Vec<Right>>, w: &WriterKey, r: Right| rights.get(w).is_some_and(|v| v.contains(&r));
    for (time_ms, writer, _, op) in events {
        match op {
            Op::Identity(p) => {
                if p[32..] == writer {
                    m.identities.insert(writer, *p);
                } else {
                    m.ignored_ops += 1;
                }
            }
            Op::Rekey(epoch, entries) if has(&rights, &writer, Right::Grant) => {
                m.rekeys.push(RekeyEvent { epoch: *epoch, time_ms, by: writer, entries: entries.clone() });
            }
            Op::Rekey(..) => m.ignored_ops += 1,
            Op::Grant(w, granted) if has(&rights, &writer, Right::Grant) => {
                if w != creator {
                    let mut g = granted.clone();
                    g.sort();
                    g.dedup();
                    rights.insert(*w, g);
                }
            }
            Op::Revoke(w) if has(&rights, &writer, Right::Grant) => {
                if w != creator {
                    rights.remove(w);
                }
            }
            Op::Grant(..) | Op::Revoke(_) => m.ignored_ops += 1,
            _ if !has(&rights, &writer, Right::Write) => m.ignored_ops += 1,
            Op::Set(id, k, v) => {
                let rec = records.entry(*id).or_insert_with(|| Record { id: *id, attrs: BTreeMap::new(), blocks: Vec::new() });
                rec.attrs.insert(k.clone(), v.clone());
            }
            Op::Unset(id, k) => {
                if let Some(rec) = records.get_mut(id) {
                    rec.attrs.remove(k);
                }
            }
            Op::Blocks(id, blocks) => {
                let rec = records.entry(*id).or_insert_with(|| Record { id: *id, attrs: BTreeMap::new(), blocks: Vec::new() });
                rec.blocks = blocks.clone();
            }
            Op::Delete(id) => {
                records.remove(id);
            }
        }
    }
    m.records = records.into_values().collect();
    m.writers = rights;
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: WriterKey = [1; 32];
    const BOB: WriterKey = [2; 32];
    const EVE: WriterKey = [3; 32];
    const R: RecordId = [7; 16];

    fn c(time_ms: u64, ops: Vec<Op>) -> WriterCommit {
        WriterCommit { time_ms, ops }
    }

    fn s(v: &str) -> Value {
        Value::Str(v.into())
    }

    fn chains(list: Vec<(WriterKey, Vec<WriterCommit>)>) -> BTreeMap<WriterKey, Vec<WriterCommit>> {
        list.into_iter().collect()
    }

    #[test]
    fn ops_files_roundtrip_canonically() {
        let f = OpsFile {
            ops: vec![
                Op::Set(R, "title".into(), s("Hello")),
                Op::Unset(R, "draft".into()),
                Op::Blocks(R, vec![]),
                Op::Delete(R),
                Op::Grant(BOB, vec![Right::Write, Right::Grant, Right::Write]),
                Op::Revoke(EVE),
            ],
        };
        let bytes = f.encode();
        assert!(OpsFile::is_ops(&bytes));
        let back = OpsFile::decode(&bytes).unwrap();
        assert_eq!(back.ops[4], Op::Grant(BOB, vec![Right::Grant, Right::Write]), "rights sorted, unique");
        assert_eq!(back.encode(), bytes);
    }

    #[test]
    fn last_writer_wins_per_field_and_order_of_arrival_does_not_matter() {
        let a = vec![c(100, vec![Op::Grant(BOB, vec![Right::Write]), Op::Set(R, "title".into(), s("A")), Op::Set(R, "x".into(), Value::Int(1))]), c(300, vec![Op::Set(R, "title".into(), s("A2"))])];
        let b = vec![c(200, vec![Op::Set(R, "title".into(), s("B")), Op::Set(R, "y".into(), Value::Int(2))])];
        let m1 = merge(&ALICE, &chains(vec![(ALICE, a.clone()), (BOB, b.clone())]), 1000);
        let m2 = merge(&ALICE, &chains(vec![(BOB, b), (ALICE, a)]), 1000);
        assert_eq!(m1, m2);
        let r = &m1.records[0];
        assert_eq!(r.attrs["title"], s("A2"), "newest stamp wins");
        assert_eq!((r.attrs["x"].clone(), r.attrs["y"].clone()), (Value::Int(1), Value::Int(2)), "different fields both survive");
    }

    #[test]
    fn writes_count_only_with_rights_at_their_stamp() {
        let alice = vec![
            c(100, vec![Op::Grant(BOB, vec![Right::Write])]),
            c(400, vec![Op::Revoke(BOB)]),
        ];
        let bob = vec![
            c(50, vec![Op::Set(R, "early".into(), Value::Bool(true))]), // before the grant
            c(200, vec![Op::Set(R, "ok".into(), Value::Bool(true)), Op::Grant(EVE, vec![Right::Write])]), // can't grant
            c(500, vec![Op::Set(R, "late".into(), Value::Bool(true))]), // after the revoke
        ];
        let eve = vec![c(300, vec![Op::Set(R, "eve".into(), Value::Bool(true))])];
        let m = merge(&ALICE, &chains(vec![(ALICE, alice), (BOB, bob), (EVE, eve)]), 1000);
        let keys: Vec<&str> = m.records[0].attrs.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["ok"]);
        assert_eq!(m.ignored_ops, 4);
        assert_eq!(m.writers.keys().copied().collect::<Vec<_>>(), vec![ALICE], "bob revoked, eve never admitted");
    }

    #[test]
    fn identities_and_rekeys_count_only_where_allowed() {
        let mut alice_id = [0u8; 64];
        alice_id[32..].copy_from_slice(&ALICE);
        let alice = vec![
            c(100, vec![Op::Identity(alice_id), Op::Grant(BOB, vec![Right::Write])]),
            c(300, vec![Op::Revoke(BOB), Op::Rekey(1, vec![(ALICE, vec![1, 2, 3])])]),
        ];
        let bob = vec![c(200, vec![Op::Identity(alice_id), Op::Rekey(1, vec![(BOB, vec![9])])])];
        let m = merge(&ALICE, &chains(vec![(ALICE, alice), (BOB, bob)]), 1000);
        assert_eq!(m.identities.keys().copied().collect::<Vec<_>>(), vec![ALICE], "bob can't claim alice's identity");
        assert_eq!(m.rekeys.len(), 1, "bob holds no grant right: his rekey doesn't count");
        assert_eq!((m.rekeys[0].epoch, m.rekeys[0].by, m.rekeys[0].time_ms), (1, ALICE, 300));
        let f = OpsFile { ops: vec![Op::Rekey(2, vec![(BOB, vec![5]), (ALICE, vec![6])])] };
        let back = OpsFile::decode(&f.encode()).unwrap();
        assert_eq!(back.ops[0], Op::Rekey(2, vec![(ALICE, vec![6]), (BOB, vec![5])]), "entries sorted by writer");
    }

    #[test]
    fn deletes_and_dates() {
        let alice = vec![
            c(100, vec![Op::Set(R, "a".into(), Value::Int(1))]),
            c(200, vec![Op::Delete(R)]),
            c(150, vec![Op::Set(R, "b".into(), Value::Int(2))]), // dated before its predecessor: ignored
        ];
        let m = merge(&ALICE, &chains(vec![(ALICE, alice)]), 1000);
        assert!(m.records.is_empty());
        assert_eq!(m.ignored_commits, 1);
        let ahead = vec![c(1000 + MAX_CLOCK_AHEAD_MS + 1, vec![Op::Set(R, "a".into(), Value::Int(1))])];
        assert_eq!(merge(&ALICE, &chains(vec![(ALICE, ahead)]), 1000).ignored_commits, 1, "too far in the future");
        let revived = vec![c(100, vec![Op::Delete(R)]), c(200, vec![Op::Set(R, "a".into(), Value::Int(3))])];
        assert_eq!(merge(&ALICE, &chains(vec![(ALICE, revived)]), 1000).records.len(), 1, "a later write revives it");
    }
}
