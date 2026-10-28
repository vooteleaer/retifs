//! Channels (ADR-0015): ones this node writes, and ones it follows.
//!
//! ```text
//! OWN_CHANNELS  name → signing seed (32) ‖ read key (32) ‖ seq (8) ‖ has_last (1) [‖ cid (33) ‖ seed (32)] ‖ head
//! FOLLOWS       ns_id (16) → writer (32) ‖ read key (32) ‖ seq (8) ‖ current (1 + 73) ‖ previous (1 + 73)
//!                            ‖ hint count (1) ‖ hints (16 each) ‖ head
//! ```
//! The latest head of each is kept so this node can answer `/retifs/head`.

use redb::{ReadableTable, TableDefinition};
use retifs_core::{
    channel::{ChannelAddr, NsId},
    manifest::FileRef,
    Cid, Seed,
};

use crate::{wants::PeerId, SlabStore, StoreError};

const OWN_CHANNELS: TableDefinition<&str, &[u8]> = TableDefinition::new("own_channels");
const FOLLOWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("follows");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(OWN_CHANNELS)?;
    w.open_table(FOLLOWS)?;
    Ok(())
}

/// A channel this node writes.
#[derive(Debug, Clone)]
pub struct OwnChannel {
    pub name: String,
    pub signing_seed: [u8; 32],
    pub read_key: [u8; 32],
    /// Last published sequence number (0: nothing yet).
    pub seq: u64,
    /// The last commit chunk, which the next commit links.
    pub last: Option<(Cid, Seed)>,
    pub head: Vec<u8>,
}

/// A channel this node follows.
#[derive(Debug, Clone)]
pub struct Follow {
    pub addr: ChannelAddr,
    /// Highest verified sequence number (rollback protection).
    pub seq: u64,
    /// The version being kept (sought until complete).
    pub current: Option<FileRef>,
    /// The version it replaced: forgotten once `current` is complete.
    pub previous: Option<FileRef>,
    pub hints: Vec<PeerId>,
    pub head: Vec<u8>,
}

fn put_fileref(v: &mut Vec<u8>, f: &Option<FileRef>) {
    match f {
        Some(f) => {
            v.push(1);
            v.extend_from_slice(f.root.as_bytes());
            v.extend_from_slice(&f.seed.0);
            v.extend_from_slice(&f.size.to_be_bytes());
        }
        None => v.extend_from_slice(&[0; 74]),
    }
}

fn get_fileref(v: &[u8]) -> Option<FileRef> {
    (v[0] == 1).then(|| FileRef {
        root: Cid::from_bytes(v[1..34].try_into().unwrap()).expect("CID version"),
        seed: Seed(v[34..66].try_into().unwrap()),
        size: u64::from_be_bytes(v[66..74].try_into().unwrap()),
    })
}

fn own_value(c: &OwnChannel) -> Vec<u8> {
    let mut v = c.signing_seed.to_vec();
    v.extend_from_slice(&c.read_key);
    v.extend_from_slice(&c.seq.to_be_bytes());
    match &c.last {
        Some((cid, seed)) => {
            v.push(1);
            v.extend_from_slice(cid.as_bytes());
            v.extend_from_slice(&seed.0);
        }
        None => v.push(0),
    }
    v.extend_from_slice(&c.head);
    v
}

fn parse_own(name: &str, v: &[u8]) -> OwnChannel {
    let (last, head) = match v[72] {
        1 => (
            Some((Cid::from_bytes(v[73..106].try_into().unwrap()).expect("CID version"), Seed(v[106..138].try_into().unwrap()))),
            &v[138..],
        ),
        _ => (None, &v[73..]),
    };
    OwnChannel {
        name: name.to_string(),
        signing_seed: v[..32].try_into().unwrap(),
        read_key: v[32..64].try_into().unwrap(),
        seq: u64::from_be_bytes(v[64..72].try_into().unwrap()),
        last,
        head: head.to_vec(),
    }
}

fn follow_value(f: &Follow) -> Vec<u8> {
    let mut v = f.addr.writer.to_vec();
    v.extend_from_slice(&f.addr.read_key);
    v.extend_from_slice(&f.seq.to_be_bytes());
    put_fileref(&mut v, &f.current);
    put_fileref(&mut v, &f.previous);
    v.push(f.hints.len().min(255) as u8);
    for h in f.hints.iter().take(255) {
        v.extend_from_slice(h);
    }
    v.extend_from_slice(&f.head);
    v
}

fn parse_follow(v: &[u8]) -> Follow {
    let n = v[220] as usize;
    Follow {
        addr: ChannelAddr { writer: v[..32].try_into().unwrap(), read_key: v[32..64].try_into().unwrap() },
        seq: u64::from_be_bytes(v[64..72].try_into().unwrap()),
        current: get_fileref(&v[72..146]),
        previous: get_fileref(&v[146..220]),
        hints: v[221..221 + n * 16].chunks(16).map(|h| h.try_into().unwrap()).collect(),
        head: v[221 + n * 16..].to_vec(),
    }
}

impl SlabStore {
    pub fn create_channel(&self, name: &str, signing_seed: [u8; 32], read_key: [u8; 32]) -> Result<bool, StoreError> {
        let w = self.write()?;
        let created = {
            let mut t = w.open_table(OWN_CHANNELS)?;
            if t.get(name)?.is_some() {
                false
            } else {
                let c = OwnChannel { name: name.into(), signing_seed, read_key, seq: 0, last: None, head: Vec::new() };
                t.insert(name, own_value(&c).as_slice())?;
                true
            }
        };
        w.commit()?;
        Ok(created)
    }

    pub fn own_channel(&self, name: &str) -> Result<Option<OwnChannel>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(OWN_CHANNELS)?.get(name)?.map(|v| parse_own(name, v.value())))
    }

    pub fn own_channels(&self) -> Result<Vec<OwnChannel>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(OWN_CHANNELS)?;
        t.iter()?.map(|e| e.map(|(k, v)| parse_own(k.value(), v.value())).map_err(StoreError::from)).collect()
    }

    pub fn remove_own_channel(&self, name: &str) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(OWN_CHANNELS)?.remove(name)?;
        w.commit()?;
        Ok(())
    }

    pub fn update_own_channel(&self, c: &OwnChannel) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(OWN_CHANNELS)?.insert(c.name.as_str(), own_value(c).as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// Starts following a channel (or adds hints to one already followed).
    pub fn follow(&self, addr: &ChannelAddr, hints: &[PeerId]) -> Result<Follow, StoreError> {
        let id = addr.ns_id();
        let mut f = self.followed(&id)?.unwrap_or(Follow {
            addr: addr.clone(),
            seq: 0,
            current: None,
            previous: None,
            hints: Vec::new(),
            head: Vec::new(),
        });
        for h in hints {
            if !f.hints.contains(h) {
                f.hints.push(*h);
            }
        }
        self.update_follow(&f)?;
        Ok(f)
    }

    pub fn followed(&self, id: &NsId) -> Result<Option<Follow>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(FOLLOWS)?.get(id.as_slice())?.map(|v| parse_follow(v.value())))
    }

    pub fn follows(&self) -> Result<Vec<Follow>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(FOLLOWS)?;
        t.iter()?.map(|e| e.map(|(_, v)| parse_follow(v.value())).map_err(StoreError::from)).collect()
    }

    pub fn update_follow(&self, f: &Follow) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(FOLLOWS)?.insert(f.addr.ns_id().as_slice(), follow_value(f).as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// The latest head this node knows for a namespace (its own, or followed).
    pub fn head_for(&self, id: &NsId) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some(f) = self.followed(id)?
            && !f.head.is_empty()
        {
            return Ok(Some(f.head));
        }
        for c in self.own_channels()? {
            let writer = retifs_core::channel::ChannelKey::from_secrets(c.signing_seed, c.read_key).addr();
            if writer.ns_id() == *id && !c.head.is_empty() {
                return Ok(Some(c.head));
            }
        }
        Ok(None)
    }
}
