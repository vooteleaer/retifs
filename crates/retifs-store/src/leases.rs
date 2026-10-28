//! Leases (ADR-0010/0011), persisted in the store's index.
//!
//! Holder side (keeping chunks for others):
//! ```text
//! LEASES        lease_id → expires (8) ‖ source count (1) ‖ sources (16 each) ‖ lease bytes
//! LEASE_CHUNKS  CID ‖ lease_id → ()          which leases keep a chunk
//! ```
//! Owner side (own data kept elsewhere):
//! ```text
//! OWN_LEASES    lease_id → holder (16) ‖ n (u16) ‖ root (33) × n ‖ stale (1) ‖ expires (8) ‖ receipt_until (8)
//!               ‖ proof (1) ‖ lease bytes
//! ```
//! A lease may serve several files (ADR-0014: mixed leases hide file boundaries);
//! `roots` lists them. When a file stops being kept there, the lease turns
//! *stale* and is repacked at its next renewal instead of renewed.
//! ```text
//! ```
//! Leased chunks carry the SERVING tier flag (hard: never evicted) and their
//! access token in the serving index, so the holder serves them to anyone who
//! proves the seed, exactly like the owner would. When the last lease keeping
//! a chunk expires, the flag and token go; a chunk with no other tier is removed.

use redb::{ReadableTable, TableDefinition};
use retifs_core::{
    lease::{Lease, LeaseId, Renewal, ID_LEN},
    ChunkToken, Cid,
};

use crate::{tier, wants::PeerId, SlabStore, StoreError, SERVE};

const LEASES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("leases");
const LEASE_CHUNKS: TableDefinition<&[u8], ()> = TableDefinition::new("lease_chunks");
pub(crate) const OWN_LEASES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("own_leases_v2");

/// Quota estimate per leased chunk: data chunks are at most the 16 KiB class.
pub const LEASE_CHUNK_ESTIMATE: u64 = 16 * 1024;

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(LEASES)?;
    w.open_table(LEASE_CHUNKS)?;
    w.open_table(OWN_LEASES)?;
    Ok(())
}

/// Chunks wanted for a lease, by CID and access token only (the holder has no seeds).
pub type BlindWants = Vec<(Cid, ChunkToken)>;

/// Outcome of offering a lease to this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accept {
    Accepted,
    /// Over the hold limit (or holding for others is off).
    NoRoom,
    /// Same lease ID, different signer or content.
    Conflict,
}

/// A lease this node keeps, with how much of it is local.
#[derive(Debug, Clone)]
pub struct HeldLease {
    pub lease: Lease,
    pub expires: u64,
    pub sources: Vec<PeerId>,
    pub held: usize,
}

/// A lease this node gave out for its own data.
#[derive(Debug, Clone)]
pub struct OwnLease {
    pub lease: Lease,
    pub holder: PeerId,
    /// Files this lease keeps chunks of (several when mixed).
    pub roots: Vec<Cid>,
    /// It lists chunks no file still needs here: repack at renewal.
    pub stale: bool,
    /// Current expiry (unix seconds): the lease's own, moved by renewals.
    pub expires: u64,
    /// Unix seconds the holder's latest valid receipt covers (0: none yet).
    pub receipt_until: u64,
    pub proof: ProofState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofState {
    Unchecked = 0,
    Passed = 1,
    Failed = 2,
}

fn parse_held(v: &[u8]) -> (u64, Vec<PeerId>, Lease) {
    let expires = u64::from_be_bytes(v[..8].try_into().unwrap());
    let n = v[8] as usize;
    let sources = v[9..9 + n * 16].chunks(16).map(|s| s.try_into().unwrap()).collect();
    let (lease, _) = Lease::decode(&v[9 + n * 16..]).expect("stored leases were verified");
    (expires, sources, lease)
}

fn held_value(expires: u64, sources: &[PeerId], lease_bytes: &[u8]) -> Vec<u8> {
    let mut v = expires.to_be_bytes().to_vec();
    v.push(sources.len() as u8);
    for s in sources {
        v.extend_from_slice(s);
    }
    v.extend_from_slice(lease_bytes);
    v
}

fn parse_own(v: &[u8]) -> OwnLease {
    let n = u16::from_be_bytes([v[16], v[17]]) as usize;
    let roots = v[18..18 + n * 33]
        .chunks(33)
        .map(|r| Cid::from_bytes(r.try_into().unwrap()).expect("CID version"))
        .collect();
    let v = &v[18 + n * 33..];
    OwnLease {
        holder: [0; 16],
        roots,
        stale: v[0] != 0,
        expires: u64::from_be_bytes(v[1..9].try_into().unwrap()),
        receipt_until: u64::from_be_bytes(v[9..17].try_into().unwrap()),
        proof: match v[17] {
            1 => ProofState::Passed,
            2 => ProofState::Failed,
            _ => ProofState::Unchecked,
        },
        lease: Lease::decode(&v[18..]).expect("own leases were signed here").0,
    }
}

fn parse_own_value(v: &[u8]) -> OwnLease {
    let mut o = parse_own(v);
    o.holder = v[..16].try_into().unwrap();
    o
}

fn own_value(o: &OwnLease) -> Vec<u8> {
    let mut v = o.holder.to_vec();
    v.extend_from_slice(&(o.roots.len() as u16).to_be_bytes());
    for r in &o.roots {
        v.extend_from_slice(r.as_bytes());
    }
    v.push(o.stale as u8);
    v.extend_from_slice(&o.expires.to_be_bytes());
    v.extend_from_slice(&o.receipt_until.to_be_bytes());
    v.push(o.proof as u8);
    v.extend_from_slice(&o.lease.encode());
    v
}

impl SlabStore {
    // ------------------------------------------------------------ holder side

    /// Accepts a verified lease if it fits `hold_limit` (bytes of leased
    /// chunks, estimated per chunk). Re-offering the same lease is a no-op.
    /// Chunks already local get the SERVING flag at once; the rest are pulled.
    pub fn accept_lease(&self, lease: &Lease, sources: &[PeerId], hold_limit: u64) -> Result<Accept, StoreError> {
        let id = lease.id.as_slice();
        let w = self.write()?;
        {
            let mut leases = w.open_table(LEASES)?;
            if let Some(old) = leases.get(id)? {
                let (_, _, old) = parse_held(old.value());
                return Ok(if old.signer == lease.signer && old.digest() == lease.digest() {
                    Accept::Accepted
                } else {
                    Accept::Conflict
                });
            }
            let mut held_chunks = 0u64;
            for e in leases.iter()? {
                let (_, v) = e?;
                held_chunks += parse_held(v.value()).2.entries.len() as u64;
            }
            if (held_chunks + lease.entries.len() as u64) * LEASE_CHUNK_ESTIMATE > hold_limit {
                return Ok(Accept::NoRoom);
            }
            leases.insert(id, held_value(lease.expires, &sources[..sources.len().min(8)], &lease.encode()).as_slice())?;
            let mut chunks = w.open_table(LEASE_CHUNKS)?;
            let mut serve = w.open_table(SERVE)?;
            for (cid, token) in &lease.entries {
                chunks.insert([cid.as_bytes().as_slice(), id].concat().as_slice(), ())?;
                serve.insert(cid.as_bytes().as_slice(), token.0.as_slice())?;
            }
        }
        w.commit()?;
        for (cid, _) in &lease.entries {
            if let Some(flags) = self.tier(cid)? {
                self.set_tier(cid, flags | tier::SERVING)?;
            }
        }
        Ok(Accept::Accepted)
    }

    /// Moves a held lease's expiry, if the renewal is signed by its signer and later.
    pub fn renew_lease(&self, renewal: &Renewal) -> Result<bool, StoreError> {
        let w = self.write()?;
        let ok = {
            let mut leases = w.open_table(LEASES)?;
            let found = leases.get(renewal.id.as_slice())?.map(|v| v.value().to_vec());
            match found {
                Some(v) => {
                    let (expires, sources, lease) = parse_held(&v);
                    if renewal.verify(&lease.signer).is_err() || renewal.expires <= expires {
                        false
                    } else {
                        let off = 9 + sources.len() * 16;
                        let value = held_value(renewal.expires, &sources, &v[off..]);
                        leases.insert(renewal.id.as_slice(), value.as_slice())?;
                        true
                    }
                }
                None => false,
            }
        };
        w.commit()?;
        Ok(ok)
    }

    pub fn held_lease(&self, id: &LeaseId) -> Result<Option<HeldLease>, StoreError> {
        let found = {
            let r = self.db.begin_read()?;
            r.open_table(LEASES)?.get(id.as_slice())?.map(|v| parse_held(v.value()))
        };
        let Some((expires, sources, lease)) = found else { return Ok(None) };
        let mut held = 0;
        for (cid, _) in &lease.entries {
            held += self.tier(cid)?.is_some_and(|f| f & tier::SERVING != 0) as usize;
        }
        Ok(Some(HeldLease { lease, expires, sources, held }))
    }

    /// Held leases with chunks still missing, and those chunks (CID, token).
    pub fn lease_wants(&self) -> Result<Vec<(HeldLease, BlindWants)>, StoreError> {
        let ids: Vec<LeaseId> = {
            let r = self.db.begin_read()?;
            let t = r.open_table(LEASES)?;
            t.iter()?.map(|e| e.map(|(k, _)| k.value().try_into().unwrap())).collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for id in ids {
            if let Some(h) = self.held_lease(&id)? {
                let mut missing = Vec::new();
                for (cid, token) in &h.lease.entries {
                    if !self.tier(cid)?.is_some_and(|f| f & tier::SERVING != 0) {
                        missing.push((*cid, *token));
                    }
                }
                if !missing.is_empty() {
                    out.push((h, missing));
                }
            }
        }
        Ok(out)
    }

    /// Stores a pulled (or pushed) chunk for the leases that keep it.
    pub fn lease_arrived(&self, cid: &Cid, ciphertext: &[u8]) -> Result<bool, StoreError> {
        if !self.is_leased(cid)? {
            return Ok(false);
        }
        self.insert(cid, ciphertext, tier::SERVING)?;
        Ok(true)
    }

    /// Whether lease `id` lists `cid` (pushed chunks must belong to the lease they come with).
    pub fn lease_covers(&self, id: &LeaseId, cid: &Cid) -> Result<bool, StoreError> {
        let r = self.db.begin_read()?;
        let key = [cid.as_bytes().as_slice(), id].concat();
        Ok(r.open_table(LEASE_CHUNKS)?.get(key.as_slice())?.is_some())
    }

    pub fn is_leased(&self, cid: &Cid) -> Result<bool, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(LEASE_CHUNKS)?;
        let start = cid.as_bytes().to_vec();
        let end = [cid.as_bytes().as_slice(), &[0xff; ID_LEN]].concat();
        Ok(t.range(start.as_slice()..=end.as_slice())?.next().is_some())
    }

    /// Drops leases that expired before `now` (unix seconds). Their chunks
    /// lose the SERVING flag and token unless another lease keeps them; a chunk
    /// left with no tier is removed. Returns the number of leases dropped.
    pub fn expire_leases(&self, now: u64) -> Result<usize, StoreError> {
        let expired: Vec<Lease> = {
            let r = self.db.begin_read()?;
            let t = r.open_table(LEASES)?;
            t.iter()?
                .filter_map(|e| e.ok())
                .map(|(_, v)| parse_held(v.value()))
                .filter(|(exp, _, _)| *exp < now)
                .map(|(_, _, l)| l)
                .collect()
        };
        for lease in &expired {
            let w = self.write()?;
            let mut orphans = Vec::new();
            {
                w.open_table(LEASES)?.remove(lease.id.as_slice())?;
                let mut chunks = w.open_table(LEASE_CHUNKS)?;
                for (cid, _) in &lease.entries {
                    chunks.remove([cid.as_bytes().as_slice(), &lease.id].concat().as_slice())?;
                    let end = [cid.as_bytes().as_slice(), &[0xff; ID_LEN]].concat();
                    if chunks.range(cid.as_bytes().as_slice()..=end.as_slice())?.next().is_none() {
                        orphans.push(*cid);
                    }
                }
            }
            w.commit()?;
            let mut gone = Vec::new();
            for cid in orphans {
                match self.tier(&cid)? {
                    Some(flags) if flags & tier::PINNED != 0 => {
                        self.set_tier(&cid, flags & !tier::SERVING)?; // own data: keep serving it
                    }
                    Some(flags) if flags & !tier::SERVING != 0 => {
                        self.set_tier(&cid, flags & !tier::SERVING)?;
                        gone.push(cid);
                    }
                    Some(_) => {
                        self.remove(&cid)?;
                        gone.push(cid);
                    }
                    None => gone.push(cid),
                }
            }
            let w = self.write()?;
            {
                let mut serve = w.open_table(SERVE)?;
                for cid in gone {
                    serve.remove(cid.as_bytes().as_slice())?;
                }
            }
            w.commit()?;
        }
        Ok(expired.len())
    }

    /// Ciphertext of the `index`-th chunk of a held lease (storage proofs).
    pub fn lease_chunk(&self, id: &LeaseId, index: usize) -> Result<Option<Vec<u8>>, StoreError> {
        let cid = {
            let r = self.db.begin_read()?;
            let t = r.open_table(LEASES)?;
            let Some(v) = t.get(id.as_slice())? else { return Ok(None) };
            match parse_held(v.value()).2.entries.get(index) {
                Some((cid, _)) => *cid,
                None => return Ok(None),
            }
        };
        self.fetch(&cid)
    }

    // ------------------------------------------------------------- owner side

    pub fn record_own_lease(&self, lease: &Lease, holder: &PeerId, roots: &[Cid]) -> Result<(), StoreError> {
        let own = OwnLease {
            lease: lease.clone(),
            holder: *holder,
            roots: roots.to_vec(),
            stale: false,
            expires: lease.expires,
            receipt_until: 0,
            proof: ProofState::Unchecked,
        };
        let w = self.write()?;
        w.open_table(OWN_LEASES)?.insert(lease.id.as_slice(), own_value(&own).as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn own_leases(&self) -> Result<Vec<OwnLease>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(OWN_LEASES)?;
        t.iter()?.map(|e| e.map(|(_, v)| parse_own_value(v.value())).map_err(StoreError::from)).collect()
    }

    /// Updates an own lease (new expiry after renewal, receipt, proof outcome).
    /// Leases this node gave out that keep chunks of `root`.
    pub fn own_leases_for(&self, root: &Cid) -> Result<Vec<OwnLease>, StoreError> {
        Ok(self.own_leases()?.into_iter().filter(|o| o.roots.contains(root)).collect())
    }

    /// Stops tracking an own lease (it's not renewed and runs out).
    pub fn remove_own_lease(&self, id: &LeaseId) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(OWN_LEASES)?.remove(id.as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// `root` is no longer kept under these leases (forgotten, trimmed, or
    /// lapsed at a holder): a lease left serving no file is dropped, one still
    /// serving others turns stale (repacked at its next renewal). Returns how
    /// many leases were touched.
    pub(crate) fn unlist_root(&self, root: &Cid, holder: Option<&PeerId>) -> Result<usize, StoreError> {
        let affected: Vec<OwnLease> = self
            .own_leases_for(root)?
            .into_iter()
            .filter(|o| holder.is_none_or(|h| o.holder == *h))
            .collect();
        let w = self.write()?;
        {
            let mut t = w.open_table(OWN_LEASES)?;
            for mut o in affected.iter().cloned() {
                o.roots.retain(|r| r != root);
                if o.roots.is_empty() {
                    t.remove(o.lease.id.as_slice())?;
                } else {
                    o.stale = true;
                    t.insert(o.lease.id.as_slice(), own_value(&o).as_slice())?;
                }
            }
        }
        w.commit()?;
        Ok(affected.len())
    }

    pub fn update_own_lease(&self, own: &OwnLease) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(OWN_LEASES)?.insert(own.lease.id.as_slice(), own_value(own).as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// Holders whose receipts cover every lease of `root` until at least `now`,
    /// and whose last storage proof didn't fail.
    pub fn confirmed_holders(&self, root: &Cid, now: u64) -> Result<Vec<PeerId>, StoreError> {
        let mut by_holder: std::collections::BTreeMap<PeerId, bool> = Default::default();
        for o in self.own_leases_for(root)? {
            let ok = o.receipt_until >= now && o.proof != ProofState::Failed;
            *by_holder.entry(o.holder).or_insert(true) &= ok;
        }
        Ok(by_holder.into_iter().filter(|(_, ok)| *ok).map(|(h, _)| h).collect())
    }
}
