//! Multi-writer namespaces (ADR-0017): which namespace a name is, which
//! channel this node writes it with, and the other writers' latest heads.
//!
//! ```text
//! NS_INFO          name → creator (32) ‖ read key (32)
//! MEMBER_CHANNELS  channel name → ns_id (16)        own channels writing to another's namespace
//! WRITER_HEADS     ns_id (16) ‖ writer (32) → latest head (258) ‖ commit cid (33) ‖ commit seed (32)
//! ```

use redb::TableDefinition;
use retifs_core::{channel::NsId, Cid, Seed};

use crate::{SlabStore, StoreError};

const NS_INFO: TableDefinition<&str, &[u8]> = TableDefinition::new("ns_info");
const MEMBER_CHANNELS: TableDefinition<&str, &[u8]> = TableDefinition::new("member_channels");
const WRITER_HEADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("writer_heads");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(NS_INFO)?;
    w.open_table(MEMBER_CHANNELS)?;
    w.open_table(WRITER_HEADS)?;
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
