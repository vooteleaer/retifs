//! Multi-writer namespaces (ADR-0017): which namespace a name is, which
//! channel this node writes it with, and the other writers' latest heads.
//!
//! ```text
//! NS_INFO          name → creator (32) ‖ read key (32)
//! MEMBER_CHANNELS  channel name → ns_id (16)        own channels writing to another's namespace
//! WRITER_HEADS     ns_id (16) ‖ writer (32) → latest head (258) ‖ commit cid (33) ‖ commit seed (32)
//! NS_PEERS         name → peer (16) × n                 other members' nodes to sync with
//! NS_IDENTITY      name → X25519 secret (32) ‖ Ed25519 seed (32)   this node's writer identity
//! NS_KEYS          name → key (32) × n                  read keys after the first, by epoch
//! KEY_HEADS        ns_id (16) ‖ writer (32) ‖ key id (16) → that writer's latest head under that key
//! ```

use redb::TableDefinition;
use retifs_core::{channel::NsId, Cid, Seed};

use crate::{wants::PeerId, SlabStore, StoreError};

const NS_INFO: TableDefinition<&str, &[u8]> = TableDefinition::new("ns_info");
const MEMBER_CHANNELS: TableDefinition<&str, &[u8]> = TableDefinition::new("member_channels");
const WRITER_HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("writer_heads");
const NS_PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("ns_peers");
const NS_IDENTITY: TableDefinition<&str, &[u8]> = TableDefinition::new("ns_identity");
const NS_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("ns_keys");
const KEY_HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("key_heads");
/// Namespace name → its latest local checkpoint file (root ‖ seed ‖ u64 size).
const NS_CHECKPOINT: TableDefinition<&str, &[u8]> = TableDefinition::new("ns_checkpoint");
/// Namespace name → root CID of the checkpoint this node last committed to its chain.
const NS_CHECKPOINT_PUBLISHED: TableDefinition<&str, &[u8]> = TableDefinition::new("ns_checkpoint_published");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(NS_INFO)?;
    w.open_table(MEMBER_CHANNELS)?;
    w.open_table(WRITER_HEADS)?;
    w.open_table(NS_PEERS)?;
    w.open_table(NS_IDENTITY)?;
    w.open_table(NS_KEYS)?;
    w.open_table(KEY_HEADS)?;
    w.open_table(NS_CHECKPOINT)?;
    w.open_table(NS_CHECKPOINT_PUBLISHED)?;
    Ok(())
}

/// A namespace's creator key and read key.
pub type NsInfo = ([u8; 32], [u8; 32]);

/// A writer's latest known head and the commit it points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterHead {
    pub writer: [u8; 32],
    pub head: Vec<u8>,
    pub commit: (Cid, Seed),
}

impl SlabStore {
    /// Which namespace `name` is: its creator and read key.
    pub fn set_ns_info(&self, name: &str, creator: &[u8; 32], read_key: &[u8; 32]) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(NS_INFO)?.insert(name, [creator.as_slice(), read_key].concat().as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// (creator, read key) of namespace `name`.
    pub fn ns_info(&self, name: &str) -> Result<Option<NsInfo>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(NS_INFO)?.get(name)?.map(|v| {
            let v = v.value();
            (v[..32].try_into().unwrap(), v[32..64].try_into().unwrap())
        }))
    }

    /// This node's writer identity in namespace `name` (X25519 secret ‖ Ed25519 seed).
    pub fn set_ns_identity(&self, name: &str, identity: &[u8; 64]) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(NS_IDENTITY)?.insert(name, identity.as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// The namespace's latest checkpoint file kept here (ADR-0018).
    pub fn ns_checkpoint(&self, name: &str) -> Result<Option<retifs_core::FileRef>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(NS_CHECKPOINT)?.get(name)?.and_then(|v| {
            let v = v.value();
            (v.len() == 73).then(|| retifs_core::FileRef {
                root: Cid::from_bytes(v[..33].try_into().unwrap()).expect("CID version"),
                seed: Seed(v[33..65].try_into().unwrap()),
                size: u64::from_be_bytes(v[65..73].try_into().unwrap()),
            })
        }))
    }

    pub fn set_ns_checkpoint(&self, name: &str, file: &retifs_core::FileRef) -> Result<(), StoreError> {
        let v = [file.root.as_bytes().as_slice(), &file.seed.0, &file.size.to_be_bytes()].concat();
        let w = self.db.begin_write()?;
        w.open_table(NS_CHECKPOINT)?.insert(name, v.as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn ns_checkpoint_published(&self, name: &str) -> Result<Option<Cid>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(NS_CHECKPOINT_PUBLISHED)?.get(name)?.and_then(|v| Cid::from_bytes(v.value().try_into().ok()?)))
    }

    pub fn set_ns_checkpoint_published(&self, name: &str, root: &Cid) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(NS_CHECKPOINT_PUBLISHED)?.insert(name, root.as_bytes().as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn ns_identity(&self, name: &str) -> Result<Option<[u8; 64]>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(NS_IDENTITY)?.get(name)?.and_then(|v| v.value().try_into().ok()))
    }

    /// Read keys of namespace `name` known here, oldest first (ADR-0017 key
    /// rotation); the namespace's first key comes from its address.
    pub fn ns_keys(&self, name: &str) -> Result<Vec<[u8; 32]>, StoreError> {
        let r = self.db.begin_read()?;
        let mut keys: Vec<[u8; 32]> = self.ns_info(name)?.map(|(_, k)| vec![k]).unwrap_or_default();
        if let Some(v) = r.open_table(NS_KEYS)?.get(name)? {
            keys.extend(v.value().chunks(32).filter_map(|k| <[u8; 32]>::try_from(k).ok()));
        }
        Ok(keys)
    }

    /// Adds a newer read key; returns false if it was already known.
    pub fn add_ns_key(&self, name: &str, key: &[u8; 32]) -> Result<bool, StoreError> {
        let mut keys = self.ns_keys(name)?;
        if keys.contains(key) {
            return Ok(false);
        }
        keys.push(*key);
        let w = self.db.begin_write()?;
        w.open_table(NS_KEYS)?.insert(name, keys[1..].concat().as_slice())?;
        w.commit()?;
        Ok(true)
    }

    /// A writer's latest head encrypted under the read key with id `key_id`
    /// (own or fetched): lets members cross a key rotation (ADR-0017).
    pub fn set_key_head(&self, ns_id: &NsId, writer: &[u8; 32], key_id: &[u8; 16], head: &[u8]) -> Result<(), StoreError> {
        let key = [ns_id.as_slice(), writer, key_id].concat();
        let w = self.db.begin_write()?;
        w.open_table(KEY_HEADS)?.insert(key.as_slice(), head)?;
        w.commit()?;
        Ok(())
    }

    pub fn key_head(&self, ns_id: &NsId, writer: &[u8; 32], key_id: &[u8; 16]) -> Result<Option<Vec<u8>>, StoreError> {
        let key = [ns_id.as_slice(), writer, key_id].concat();
        let r = self.db.begin_read()?;
        Ok(r.open_table(KEY_HEADS)?.get(key.as_slice())?.map(|v| v.value().to_vec()))
    }

    /// Names of the namespaces this node writes or has joined.
    pub fn ns_names(&self) -> Result<Vec<String>, StoreError> {
        use redb::ReadableTable;
        let r = self.db.begin_read()?;
        let t = r.open_table(NS_INFO)?;
        t.iter()?.map(|e| e.map(|(k, _)| k.value().to_string()).map_err(StoreError::from)).collect()
    }

    /// Nodes to sync namespace `name` with (other members).
    pub fn add_ns_peers(&self, name: &str, peers: &[PeerId]) -> Result<(), StoreError> {
        let mut all = self.ns_peers(name)?;
        for p in peers {
            if !all.contains(p) {
                all.push(*p);
            }
        }
        let w = self.db.begin_write()?;
        w.open_table(NS_PEERS)?.insert(name, all.concat().as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn ns_peers(&self, name: &str) -> Result<Vec<PeerId>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(NS_PEERS)?
            .get(name)?
            .map(|v| v.value().chunks(16).filter_map(|p| p.try_into().ok()).collect())
            .unwrap_or_default())
    }

    /// Own channel `channel` writes to namespace `ns_id` (not its own).
    pub fn set_member_channel(&self, channel: &str, ns_id: &NsId) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(MEMBER_CHANNELS)?.insert(channel, ns_id.as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn member_channel(&self, channel: &str) -> Result<Option<NsId>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(MEMBER_CHANNELS)?.get(channel)?.and_then(|v| v.value().try_into().ok()))
    }

    pub fn set_writer_head(&self, ns_id: &NsId, h: &WriterHead) -> Result<(), StoreError> {
        let key = [ns_id.as_slice(), &h.writer].concat();
        let value = [h.head.as_slice(), h.commit.0.as_bytes(), &h.commit.1.0].concat();
        let w = self.db.begin_write()?;
        w.open_table(WRITER_HEADS)?.insert(key.as_slice(), value.as_slice())?;
        w.commit()?;
        Ok(())
    }

    /// Other writers' latest heads for a namespace.
    pub fn writer_heads(&self, ns_id: &NsId) -> Result<Vec<WriterHead>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(WRITER_HEADS)?;
        let start = ns_id.to_vec();
        let end = [ns_id.as_slice(), &[0xff; 33]].concat();
        let mut out = Vec::new();
        for e in t.range(start.as_slice()..end.as_slice())? {
            let (k, v) = e?;
            let (k, v) = (k.value(), v.value());
            if k.len() != 48 || v.len() < 65 {
                continue;
            }
            let n = v.len() - 65;
            out.push(WriterHead {
                writer: k[16..].try_into().unwrap(),
                head: v[..n].to_vec(),
                commit: (Cid::from_bytes(v[n..n + 33].try_into().unwrap()).expect("CID version"), Seed(v[n + 33..].try_into().unwrap())),
            });
        }
        Ok(out)
    }

    /// The latest head of one writer of a namespace, if known.
    pub fn writer_head(&self, ns_id: &NsId, writer: &[u8; 32]) -> Result<Option<WriterHead>, StoreError> {
        Ok(self.writer_heads(ns_id)?.into_iter().find(|h| h.writer == *writer))
    }
}
