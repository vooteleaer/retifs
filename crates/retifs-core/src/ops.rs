//! Operation chains and their merge (ADR-0017; decisions 4 and 8). Draft v1.
//!
//! A namespace commit's tree is an operations file:
//! ```text
//! ops file = { "ops": [ op, … ], "retifs": "ns-ops/1" }        canonical msgpack (ADR-0016)
//! op       = [ "set", id, key, value ] | [ "unset", id, key ] | [ "blocks", id, [ ref, … ] ]
//!          | [ "delete", id ] | [ "grant", writer (bin 32), [ right, … ] ] | [ "revoke", writer ]
//!          | [ "identity", public (bin 64) ]                     the signer's RNS identity (X25519 ‖ Ed25519)
//!          | [ "rekey", epoch, [ [ writer (bin 32), wrapped (bin) ], … sorted by writer ] ]
//!          | [ "checkpoint", [ cid, seed, size ] ]               a checkpoint file (ADR-0018); changes nothing
//! right    = "grant" | "write"                                   sorted, unique
//! ```
//! Every reader replays all writers' operations in stamp order —
//! `(commit time, writer key, commit sequence number, index in commit)` — and so reaches the same
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
    /// The writer's checkpoint of the namespace (ADR-0018): a file a new
    /// member may start from instead of the history. It changes no state.
    Checkpoint(FileRef),
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

pub(crate) fn write_op(out: &mut Vec<u8>, op: &Op) {
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
        Op::Checkpoint(f) => {
            write_array_len(out, 2);
            write_str(out, "checkpoint");
            write_block(out, f);
        }
    }
}

pub(crate) fn read_op(r: &mut Reader) -> Result<Op, RecordError> {
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
        ("checkpoint", 2) => Op::Checkpoint(read_block(r)?),
        _ => return Err(RecordError::Malformed("unknown operation")),
    };
    Ok(op)
}

/// One commit of one writer, as the merge sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct WriterCommit {
    /// The commit's sequence number in its writer's chain: orders commits
    /// made in the same millisecond.
    pub seq: u64,
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
    let mut events: Vec<(u64, WriterKey, u64, usize, &Op)> = Vec::new();
    for (writer, chain) in chains {
        let mut last = 0u64;
        for c in chain {
            if c.time_ms < last || c.time_ms > now_ms.saturating_add(MAX_CLOCK_AHEAD_MS) {
                m.ignored_commits += 1;
                continue;
            }
            last = c.time_ms;
            for (i, op) in c.ops.iter().enumerate() {
                events.push((c.time_ms, *writer, c.seq, i, op));
            }
        }
    }
    events.sort_by_key(|a| (a.0, a.1, a.2, a.3));

    let mut rights: BTreeMap<WriterKey, Vec<Right>> = BTreeMap::new();
    rights.insert(*creator, vec![Right::Grant, Right::Write]);
    let mut records: BTreeMap<RecordId, Record> = BTreeMap::new();
    let has = |rights: &BTreeMap<WriterKey, Vec<Right>>, w: &WriterKey, r: Right| rights.get(w).is_some_and(|v| v.contains(&r));
    for (time_ms, writer, _, _, op) in events {
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
            Op::Checkpoint(_) => {}
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

/// An operation's place in the merge order: (commit time, writer, commit
/// sequence number, index in commit).
pub type Stamp = (u64, WriterKey, u64, u32);

/// Grants, revokes, identities and rekeys: they decide what other operations
/// mean, so they're evaluated as a whole, in stamp order.
pub fn is_control(op: &Op) -> bool {
    matches!(op, Op::Grant(..) | Op::Revoke(_) | Op::Identity(_) | Op::Rekey(..))
}

/// The commits of a chain that count: not dated before their predecessor,
/// not more than a day ahead of `now_ms`.
pub fn accepted(chain: &[WriterCommit], now_ms: u64) -> Vec<&WriterCommit> {
    let mut last = 0u64;
    let mut out = Vec::new();
    for c in chain {
        if c.time_ms < last || c.time_ms > now_ms.saturating_add(MAX_CLOCK_AHEAD_MS) {
            continue;
        }
        last = c.time_ms;
        out.push(c);
    }
    out
}

/// A namespace's state as a CRDT (ADR-0017): every field keeps the stamp
/// that set it, so data operations apply one at a time, in any order, with
/// the same result as [`merge`]'s replay. Control operations form a timeline
/// evaluated as a whole. A new one is added in place if it's newer than every
/// data operation seen (it can't change what they meant); otherwise the
/// state has to be rebuilt from the chains with [`State::build`].
#[derive(Debug, Clone, Default)]
pub struct State {
    creator: WriterKey,
    /// Every control operation seen, valid or not, by stamp.
    control: Vec<(Stamp, Op)>,
    /// The highest stamp of any data operation seen (applied or ignored).
    high: Option<Stamp>,
    ignored_control: usize,
    ignored_data: usize,
    /// Each writer's rights over time: (from stamp, rights; None once revoked).
    rights: BTreeMap<WriterKey, RightsTimeline>,
    identities: BTreeMap<WriterKey, [u8; 64]>,
    rekeys: Vec<RekeyEvent>,
    fields: BTreeMap<(RecordId, String), (Stamp, Option<Value>)>,
    blocks: BTreeMap<RecordId, (Stamp, Vec<FileRef>)>,
    /// Latest set or blocks per record: it exists if newer than its latest delete.
    live: BTreeMap<RecordId, Stamp>,
    deleted: BTreeMap<RecordId, Stamp>,
}

const ZERO: Stamp = (0, [0; 32], 0, 0);

/// A writer's rights from each stamp on (None: revoked).
type RightsTimeline = Vec<(Stamp, Option<Vec<Right>>)>;

impl State {
    /// A state with this control timeline and no data yet.
    pub fn with_control(creator: &WriterKey, mut control: Vec<(Stamp, Op)>) -> State {
        control.sort_by_key(|(s, _)| *s);
        let mut st = State { creator: *creator, control, ..Default::default() };
        st.timeline();
        st
    }

    /// Re-evaluates the control operations: rights, identities, rekeys.
    fn timeline(&mut self) {
        let creator = self.creator;
        self.rights = BTreeMap::from([(creator, vec![(ZERO, Some(vec![Right::Grant, Right::Write]))])]);
        self.identities.clear();
        self.rekeys.clear();
        self.ignored_control = 0;
        let control = std::mem::take(&mut self.control);
        for (s, op) in &control {
            let writer = s.1;
            let can_grant = self.has(&writer, Right::Grant, s);
            match op {
                Op::Identity(p) => {
                    if p[32..] == writer {
                        self.identities.insert(writer, *p);
                    } else {
                        self.ignored_control += 1;
                    }
                }
                Op::Rekey(epoch, entries) if can_grant => {
                    self.rekeys.push(RekeyEvent { epoch: *epoch, time_ms: s.0, by: writer, entries: entries.clone() })
                }
                Op::Grant(w, granted) if can_grant => {
                    if *w != creator {
                        let mut granted = granted.clone();
                        granted.sort();
                        granted.dedup();
                        self.rights.entry(*w).or_default().push((*s, Some(granted)));
                    }
                }
                Op::Revoke(w) if can_grant => {
                    if *w != creator {
                        self.rights.entry(*w).or_default().push((*s, None));
                    }
                }
                _ => self.ignored_control += 1,
            }
        }
        self.control = control;
    }

    /// Adds a control operation. Returns false, changing nothing, if a data
    /// operation already seen is newer: its meaning may change, so the caller
    /// rebuilds from the chains.
    pub fn add_control(&mut self, s: Stamp, op: Op) -> bool {
        if self.high.is_some_and(|h| h > s) {
            return false;
        }
        if self.control.iter().any(|(c, _)| *c == s) {
            return true;
        }
        let at = self.control.partition_point(|(c, _)| *c < s);
        self.control.insert(at, (s, op));
        self.timeline();
        true
    }

    /// Every control operation seen, by stamp.
    pub fn control(&self) -> &[(Stamp, Op)] {
        &self.control
    }

    /// The highest stamp of any data operation seen.
    pub fn high(&self) -> Option<Stamp> {
        self.high
    }

    /// Whether `writer` held `right` just before stamp `at`.
    fn has(&self, writer: &WriterKey, right: Right, at: &Stamp) -> bool {
        self.rights
            .get(writer)
            .and_then(|t| t.iter().rev().find(|(s, _)| s < at))
            .is_some_and(|(_, r)| r.as_ref().is_some_and(|r| r.contains(&right)))
    }

    /// Applies one data operation; any order gives the same state.
    pub fn apply(&mut self, s: Stamp, op: &Op) {
        if is_control(op) || matches!(op, Op::Checkpoint(_)) {
            return;
        }
        if self.high.is_none_or(|h| s > h) {
            self.high = Some(s);
        }
        if !self.has(&s.1, Right::Write, &s) {
            self.ignored_data += 1;
            return;
        }
        let newer = |old: Option<&Stamp>| old.is_none_or(|o| s > *o);
        match op {
            Op::Set(id, k, v) => {
                if newer(self.fields.get(&(*id, k.clone())).map(|(st, _)| st)) {
                    self.fields.insert((*id, k.clone()), (s, Some(v.clone())));
                }
                if newer(self.live.get(id)) {
                    self.live.insert(*id, s);
                }
            }
            Op::Unset(id, k) => {
                if newer(self.fields.get(&(*id, k.clone())).map(|(st, _)| st)) {
                    self.fields.insert((*id, k.clone()), (s, None));
                }
            }
            Op::Blocks(id, b) => {
                if newer(self.blocks.get(id).map(|(st, _)| st)) {
                    self.blocks.insert(*id, (s, b.clone()));
                }
                if newer(self.live.get(id)) {
                    self.live.insert(*id, s);
                }
            }
            Op::Delete(id) if newer(self.deleted.get(id)) => {
                self.deleted.insert(*id, s);
            }
            _ => {}
        }
    }

    /// Applies one commit. Returns false if it has a control operation older
    /// than data already seen: the caller rebuilds with [`State::build`].
    pub fn apply_commit(&mut self, writer: &WriterKey, c: &WriterCommit) -> bool {
        self.apply_commits(&[(*writer, c)])
    }

    /// Applies new commits: their control operations first, then their data,
    /// so arrival order doesn't matter. Returns false, applying nothing, if a
    /// control operation is older than data already seen.
    pub fn apply_commits(&mut self, commits: &[(WriterKey, &WriterCommit)]) -> bool {
        let mut control: Vec<(Stamp, &Op)> = Vec::new();
        for (w, c) in commits {
            for (i, op) in c.ops.iter().enumerate().filter(|(_, op)| is_control(op)) {
                control.push(((c.time_ms, *w, c.seq, i as u32), op));
            }
        }
        control.sort_by_key(|(s, _)| *s);
        if control.first().is_some_and(|(s, _)| self.high.is_some_and(|h| h > *s)) {
            return false; // nothing applied
        }
        for (s, op) in control {
            self.add_control(s, op.clone());
        }
        for (w, c) in commits {
            for (i, op) in c.ops.iter().enumerate() {
                self.apply((c.time_ms, *w, c.seq, i as u32), op);
            }
        }
        true
    }

    /// The state of every writer's chain: control first, then data in any order.
    pub fn build(creator: &WriterKey, chains: &BTreeMap<WriterKey, Vec<WriterCommit>>, now_ms: u64) -> State {
        let mut control = Vec::new();
        let mut data = Vec::new();
        for (w, chain) in chains {
            for c in accepted(chain, now_ms) {
                for (i, op) in c.ops.iter().enumerate() {
                    let s = (c.time_ms, *w, c.seq, i as u32);
                    if is_control(op) {
                        control.push((s, op.clone()));
                    } else {
                        data.push((s, op));
                    }
                }
            }
        }
        let mut st = State::with_control(creator, control);
        for (s, op) in data {
            st.apply(s, op);
        }
        st
    }

    /// Visible records, by ID.
    pub fn records(&self) -> Vec<Record> {
        let mut out: BTreeMap<RecordId, Record> = BTreeMap::new();
        for (id, live) in &self.live {
            if self.deleted.get(id).is_none_or(|d| live > d) {
                out.insert(*id, Record { id: *id, attrs: BTreeMap::new(), blocks: Vec::new() });
            }
        }
        for ((id, k), (s, v)) in &self.fields {
            if let (Some(r), Some(v)) = (out.get_mut(id), v)
                && self.deleted.get(id).is_none_or(|d| s > d)
            {
                r.attrs.insert(k.clone(), v.clone());
            }
        }
        for (id, (s, b)) in &self.blocks {
            if let Some(r) = out.get_mut(id)
                && self.deleted.get(id).is_none_or(|d| s > d)
            {
                r.blocks = b.clone();
            }
        }
        out.into_values().collect()
    }

    /// One record as it's visible now, if it is.
    pub fn record(&self, id: &RecordId) -> Option<Record> {
        let live = self.live.get(id)?;
        let deleted = self.deleted.get(id);
        if deleted.is_some_and(|d| live <= d) {
            return None;
        }
        let after_delete = |s: &Stamp| deleted.is_none_or(|d| s > d);
        let mut r = Record { id: *id, attrs: BTreeMap::new(), blocks: Vec::new() };
        for ((_, k), (s, v)) in self.fields.range((*id, String::new())..).take_while(|((rid, _), _)| rid == id) {
            if let Some(v) = v
                && after_delete(s)
            {
                r.attrs.insert(k.clone(), v.clone());
            }
        }
        if let Some((s, b)) = self.blocks.get(id)
            && after_delete(s)
        {
            r.blocks = b.clone();
        }
        Some(r)
    }

    /// The merged view, as [`merge`] gives it.
    pub fn merged(&self) -> Merged {
        Merged {
            identities: self.identities.clone(),
            rekeys: self.rekeys.clone(),
            records: self.records(),
            writers: self
                .rights
                .iter()
                .filter_map(|(w, t)| t.last().and_then(|(_, r)| r.clone()).map(|r| (*w, r)))
                .collect(),
            ignored_ops: self.ignored_control + self.ignored_data,
            ignored_commits: 0,
        }
    }
}

/// The namespace as of each of `own`'s commits, oldest first (ADR-0006: every
/// modification is a version): `own`'s commits up to it and every other
/// writer's commits up to its time. `visit(seq, time, state)` sees each.
/// One state is carried from version to version, so a whole history costs
/// about one replay, not one per version.
pub fn versions(
    creator: &WriterKey,
    chains: &BTreeMap<WriterKey, Vec<WriterCommit>>,
    own: &WriterKey,
    now_ms: u64,
    mut visit: impl FnMut(u64, u64, &State),
) {
    let accepted: BTreeMap<WriterKey, Vec<&WriterCommit>> = chains.iter().map(|(w, c)| (*w, accepted(c, now_ms))).collect();
    let mut taken: BTreeMap<WriterKey, usize> = accepted.keys().map(|w| (*w, 0)).collect();
    let mut st = State::with_control(creator, Vec::new());
    for c in chains.get(own).map(Vec::as_slice).unwrap_or_default() {
        let mut batch: Vec<(WriterKey, &WriterCommit)> = Vec::new();
        for (w, list) in &accepted {
            let from = taken[w];
            let upto = from
                + list[from..]
                    .iter()
                    .take_while(|x| if w == own { x.seq <= c.seq } else { x.time_ms <= c.time_ms })
                    .count();
            batch.extend(list[from..upto].iter().map(|x| (*w, *x)));
            taken.insert(*w, upto);
        }
        if !st.apply_commits(&batch) {
            // A grant or revoke older than data already applied: this version from scratch.
            let upto: BTreeMap<WriterKey, Vec<WriterCommit>> =
                accepted.iter().map(|(w, l)| (*w, l[..taken[w]].iter().map(|x| (*x).clone()).collect())).collect();
            st = State::build(creator, &upto, now_ms);
        }
        visit(c.seq, c.time_ms, &st);
    }
}

/// One record's CRDT state (ADR-0018): what a Prolly tree stores per record,
/// so a checkpoint can resume merging exactly where it left off.
/// ```text
/// srec  = { "blocks": nil | [stamp, [ref, …]], "deleted": nil | stamp,
///           "fields": { key: [stamp] (unset) | [stamp, value] (set), … }, "live": nil | stamp }
/// stamp = [time, writer (bin 32), seq, index]
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StampedRecord {
    pub blocks: Option<(Stamp, Vec<FileRef>)>,
    pub deleted: Option<Stamp>,
    pub fields: BTreeMap<String, (Stamp, Option<Value>)>,
    pub live: Option<Stamp>,
}

pub(crate) fn write_stamp(out: &mut Vec<u8>, s: &Stamp) {
    write_array_len(out, 4);
    crate::record::write_int(out, s.0 as i64);
    write_bin(out, &s.1);
    crate::record::write_int(out, s.2 as i64);
    crate::record::write_int(out, s.3 as i64);
}

pub(crate) fn read_stamp(r: &mut Reader) -> Result<Stamp, RecordError> {
    if r.array_len()? != 4 {
        return Err(RecordError::Malformed("stamp"));
    }
    let int = |r: &mut Reader| -> Result<u64, RecordError> {
        match r.value(0)? {
            Value::Int(i) if i >= 0 => Ok(i as u64),
            _ => Err(RecordError::Malformed("stamp number")),
        }
    };
    let time = int(r)?;
    let writer: WriterKey = r.bin()?.try_into().map_err(|_| RecordError::Malformed("stamp writer"))?;
    let seq = int(r)?;
    let index = int(r)?;
    Ok((time, writer, seq, index as u32))
}

pub(crate) fn read_opt_stamp(r: &mut Reader) -> Result<Option<Stamp>, RecordError> {
    if r.0.first() == Some(&0xc0) {
        r.byte()?;
        return Ok(None);
    }
    read_stamp(r).map(Some)
}

impl StampedRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_map_len(&mut out, 4);
        write_str(&mut out, "blocks");
        match &self.blocks {
            None => out.push(0xc0),
            Some((s, refs)) => {
                write_array_len(&mut out, 2);
                write_stamp(&mut out, s);
                write_array_len(&mut out, refs.len());
                for b in refs {
                    write_block(&mut out, b);
                }
            }
        }
        write_str(&mut out, "deleted");
        match &self.deleted {
            None => out.push(0xc0),
            Some(s) => write_stamp(&mut out, s),
        }
        write_str(&mut out, "fields");
        write_map_len(&mut out, self.fields.len());
        for (k, (s, v)) in &self.fields {
            write_str(&mut out, k);
            write_array_len(&mut out, if v.is_some() { 2 } else { 1 });
            write_stamp(&mut out, s);
            if let Some(v) = v {
                write_value(&mut out, v);
            }
        }
        write_str(&mut out, "live");
        match &self.live {
            None => out.push(0xc0),
            Some(s) => write_stamp(&mut out, s),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<StampedRecord, RecordError> {
        let mut r = Reader(bytes);
        if r.map_len()? != 4 || r.str()? != "blocks" {
            return Err(RecordError::Malformed("stamped record fields"));
        }
        let blocks = if r.0.first() == Some(&0xc0) {
            r.byte()?;
            None
        } else {
            if r.array_len()? != 2 {
                return Err(RecordError::Malformed("blocks"));
            }
            let s = read_stamp(&mut r)?;
            let n = r.array_len()?;
            let mut refs = Vec::with_capacity(n.min(1 << 12));
            for _ in 0..n {
                refs.push(read_block(&mut r)?);
            }
            Some((s, refs))
        };
        if r.str()? != "deleted" {
            return Err(RecordError::Malformed("stamped record fields"));
        }
        let deleted = read_opt_stamp(&mut r)?;
        if r.str()? != "fields" {
            return Err(RecordError::Malformed("stamped record fields"));
        }
        let n = r.map_len()?;
        let mut fields = BTreeMap::new();
        for _ in 0..n {
            let k = r.str()?;
            let m = r.array_len()?;
            let s = read_stamp(&mut r)?;
            let v = match m {
                1 => None,
                2 => Some(r.value(0)?),
                _ => return Err(RecordError::Malformed("field")),
            };
            fields.insert(k, (s, v));
        }
        if r.str()? != "live" {
            return Err(RecordError::Malformed("stamped record fields"));
        }
        let live = read_opt_stamp(&mut r)?;
        let rec = StampedRecord { blocks, deleted, fields, live };
        if !r.0.is_empty() {
            return Err(RecordError::Malformed("trailing bytes"));
        }
        canonical(bytes, rec.encode())?;
        Ok(rec)
    }
}

impl State {
    /// Every record's CRDT state (tombstones included), by ID.
    pub fn stamped(&self) -> Vec<(RecordId, StampedRecord)> {
        let mut out: BTreeMap<RecordId, StampedRecord> = BTreeMap::new();
        for (id, s) in &self.live {
            out.entry(*id).or_default().live = Some(*s);
        }
        for (id, s) in &self.deleted {
            out.entry(*id).or_default().deleted = Some(*s);
        }
        for ((id, k), f) in &self.fields {
            out.entry(*id).or_default().fields.insert(k.clone(), f.clone());
        }
        for (id, b) in &self.blocks {
            out.entry(*id).or_default().blocks = Some(b.clone());
        }
        out.into_iter().collect()
    }

    /// Restores a state from a checkpoint: its control operations, highest
    /// data stamp and records' CRDT state.
    pub fn restore(
        creator: &WriterKey,
        control: Vec<(Stamp, Op)>,
        high: Option<Stamp>,
        entries: impl IntoIterator<Item = (RecordId, StampedRecord)>,
    ) -> State {
        let mut st = State::with_control(creator, control);
        st.high = high;
        for (id, r) in entries {
            if let Some(s) = r.live {
                st.live.insert(id, s);
            }
            if let Some(s) = r.deleted {
                st.deleted.insert(id, s);
            }
            for (k, f) in r.fields {
                st.fields.insert((id, k), f);
            }
            if let Some(b) = r.blocks {
                st.blocks.insert(id, b);
            }
        }
        st
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: WriterKey = [1; 32];
    const BOB: WriterKey = [2; 32];
    const EVE: WriterKey = [3; 32];
    const R: RecordId = [7; 16];

    fn c(time_ms: u64, ops: Vec<Op>) -> WriterCommit {
        WriterCommit { seq: 0, time_ms, ops }
    }

    fn s(v: &str) -> Value {
        Value::Str(v.into())
    }

    /// Chains with sequence numbers by position (1, 2, …).
    fn chains(list: Vec<(WriterKey, Vec<WriterCommit>)>) -> BTreeMap<WriterKey, Vec<WriterCommit>> {
        list.into_iter()
            .map(|(w, mut cs)| {
                for (i, c) in cs.iter_mut().enumerate() {
                    c.seq = i as u64 + 1;
                }
                (w, cs)
            })
            .collect()
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

    /// The CRDT state gives exactly what the sequential merge gives, whatever
    /// order the data operations arrive in.
    #[test]
    fn state_matches_merge_in_any_order() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let writers = [ALICE, BOB, EVE];
        let ids: Vec<RecordId> = (0..4u8).map(|i| [i; 16]).collect();
        let keys = ["a", "b", "c"];
        for _ in 0..2000 {
            let mut chains: BTreeMap<WriterKey, Vec<WriterCommit>> = BTreeMap::new();
            for w in writers {
                let mut t = 0;
                for _ in 0..rnd(4) {
                    t += rnd(50);
                    let ops = (0..1 + rnd(4))
                        .map(|_| {
                            let id = ids[rnd(4) as usize];
                            let k = keys[rnd(3) as usize].to_string();
                            match rnd(10) {
                                0..=3 => Op::Set(id, k, Value::Int(rnd(5) as i64)),
                                4 => Op::Unset(id, k),
                                5 => Op::Blocks(id, vec![]),
                                6 => Op::Delete(id),
                                7 => Op::Grant(writers[rnd(3) as usize], if rnd(2) == 0 { vec![Right::Write] } else { vec![Right::Write, Right::Grant] }),
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
            let expect = merge(&ALICE, &chains, 10_000);
            let built = State::build(&ALICE, &chains, 10_000);
            assert_eq!(built.records(), expect.records);
            assert_eq!(built.merged().writers, expect.writers);
            // Data in a shuffled order, one operation at a time.
            let mut control = Vec::new();
            let mut data = Vec::new();
            for (w, chain) in &chains {
                for cm in accepted(chain, 10_000) {
                    for (i, op) in cm.ops.iter().enumerate() {
                        let st = (cm.time_ms, *w, cm.seq, i as u32);
                        if is_control(op) { control.push((st, op.clone())) } else { data.push((st, op.clone())) }
                    }
                }
            }
            for i in (1..data.len()).rev() {
                data.swap(i, rnd(i as u64 + 1) as usize);
            }
            let mut st = State::with_control(&ALICE, control);
            for (s, op) in &data {
                st.apply(*s, op);
            }
            assert_eq!(st.records(), expect.records, "shuffled order");
        }
    }

    /// History in one pass equals a full merge per version.
    #[test]
    fn versions_match_merge_per_version() {
        let mut seed = 0x51d7_348c_2f0e_9a6bu64;
        let mut rnd = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let writers = [ALICE, BOB, EVE];
        let ids: Vec<RecordId> = (0..4u8).map(|i| [i; 16]).collect();
        for _ in 0..500 {
            let mut chains: BTreeMap<WriterKey, Vec<WriterCommit>> = BTreeMap::new();
            for w in writers {
                let mut t = 0;
                for _ in 0..rnd(6) {
                    t += rnd(30);
                    let ops = (0..1 + rnd(3))
                        .map(|_| {
                            let id = ids[rnd(4) as usize];
                            let k = ["a", "b"][rnd(2) as usize].to_string();
                            match rnd(9) {
                                0..=3 => Op::Set(id, k, Value::Int(rnd(5) as i64)),
                                4 => Op::Unset(id, k),
                                5 => Op::Delete(id),
                                6 => Op::Grant(writers[rnd(3) as usize], vec![Right::Write]),
                                7 => Op::Revoke(writers[rnd(3) as usize]),
                                _ => Op::Blocks(id, vec![]),
                            }
                        })
                        .collect();
                    let list = chains.entry(w).or_default();
                    let seq = list.len() as u64 + 1;
                    list.push(WriterCommit { seq, time_ms: t, ops });
                }
            }
            let own = writers[rnd(3) as usize];
            let mut seen = 0;
            versions(&ALICE, &chains, &own, 10_000, |seq, time, st| {
                seen += 1;
                let upto: BTreeMap<WriterKey, Vec<WriterCommit>> = chains
                    .iter()
                    .map(|(w, c)| (*w, c.iter().filter(|x| if *w == own { x.seq <= seq } else { x.time_ms <= time }).cloned().collect()))
                    .collect();
                let expect = merge(&ALICE, &upto, 10_000).records;
                assert_eq!(st.records(), expect, "version {seq}");
                for r in &expect {
                    assert_eq!(st.record(&r.id).as_ref(), Some(r));
                }
                for id in &ids {
                    assert_eq!(st.record(id).is_some(), expect.iter().any(|r| r.id == *id));
                }
            });
            assert_eq!(seen, chains.get(&own).map_or(0, Vec::len));
        }
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
