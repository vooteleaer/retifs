//! Local slab store (ADR-0007), prototype.
//!
//! ```text
//! <root>/slabs/c<N>k/seg-000000 …   fixed-size slots, one directory per size class
//! <root>/index.redb                 CID → (class, segment, slot, tier); free slots; counters
//! ```
//! Write order is content first, then reference: the slot is written (and
//! fsynced) inside the same redb transaction that records it, so a crash
//! before commit leaves only a free slot with garbage in it.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use retifs_core::{chunk::CLASSES, Cid, Store};

/// CID → (class index, segment, slot, tier flags)
const INDEX: TableDefinition<&[u8], (u8, u32, u32, u8)> = TableDefinition::new("index");
/// Reusable slots: (class index, segment, slot)
const FREE: TableDefinition<(u8, u32, u32), ()> = TableDefinition::new("free");
/// Next never-used slot number per class index
const NEXT: TableDefinition<u8, u64> = TableDefinition::new("next");

pub const SLOTS_PER_SEGMENT: u64 = 256;

/// Tier flags (ADR-0005). A chunk may be in several tiers at once.
pub mod tier {
    pub const PINNED: u8 = 1;
    pub const CACHE: u8 = 2;
    pub const SERVING: u8 = 4;
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Db(Box<redb::Error>),
    NotAClassSize(usize),
    /// Stored or offered bytes don't hash to the CID. Drop and refetch.
    Corrupt(Cid),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Db(e) => write!(f, "index: {e}"),
            StoreError::NotAClassSize(n) => write!(f, "{n} bytes is not a chunk size class"),
            StoreError::Corrupt(c) => write!(f, "chunk {c} does not match its CID"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self { StoreError::Db(Box::new(e.into())) }
        }
    )*};
}
from_redb!(redb::Error, redb::DatabaseError, redb::TransactionError, redb::TableError, redb::StorageError, redb::CommitError);

pub struct SlabStore {
    root: PathBuf,
    db: Database,
    sync: bool,
}

impl SlabStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("slabs"))?;
        let db = Database::create(root.join("index.redb"))?;
        let w = db.begin_write()?;
        w.open_table(INDEX)?;
        w.open_table(FREE)?;
        w.open_table(NEXT)?;
        w.commit()?;
        Ok(SlabStore { root, db, sync: true })
    }

    /// fsync each written slot (default on). Off only for tests and benchmarks.
    pub fn set_sync(&mut self, on: bool) {
        self.sync = on;
    }

    /// Stores a chunk. Returns false if it was already present (its tier
    /// flags are merged). Rejects bytes that don't match the CID.
    pub fn insert(&mut self, cid: &Cid, ciphertext: &[u8], tier: u8) -> Result<bool, StoreError> {
        let class = class_index(ciphertext.len())?;
        if !cid.verify(ciphertext) {
            return Err(StoreError::Corrupt(*cid));
        }
        let key = cid.as_bytes().as_slice();
        let w = self.db.begin_write()?;
        let inserted = {
            let mut index = w.open_table(INDEX)?;
            let existing = index.get(key)?.map(|g| g.value());
            if let Some((c, seg, slot, t)) = existing {
                if t | tier != t {
                    index.insert(key, (c, seg, slot, t | tier))?;
                }
                false
            } else {
                let (seg, slot) = allocate(&w, class)?;
                self.write_slot(class, seg, slot, ciphertext)?;
                index.insert(key, (class, seg, slot, tier))?;
                true
            }
        };
        w.commit()?;
        Ok(inserted)
    }

    /// Reads and verifies a chunk. `Err(Corrupt)` means the stored copy is bad.
    pub fn fetch(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        let r = self.db.begin_read()?;
        let index = r.open_table(INDEX)?;
        let Some((class, seg, slot, _)) = index.get(cid.as_bytes().as_slice())?.map(|g| g.value()) else {
            return Ok(None);
        };
        let size = CLASSES[class as usize];
        let mut f = File::open(self.segment_path(class, seg))?;
        f.seek(SeekFrom::Start(slot as u64 * size as u64))?;
        let mut buf = vec![0u8; size];
        f.read_exact(&mut buf)?;
        if !cid.verify(&buf) {
            return Err(StoreError::Corrupt(*cid));
        }
        Ok(Some(buf))
    }

    /// Removes a chunk and frees its slot for reuse.
    pub fn remove(&mut self, cid: &Cid) -> Result<bool, StoreError> {
        let w = self.db.begin_write()?;
        let removed = {
            let mut index = w.open_table(INDEX)?;
            let old = index.remove(cid.as_bytes().as_slice())?.map(|g| g.value());
            if let Some((class, seg, slot, _)) = old {
                w.open_table(FREE)?.insert((class, seg, slot), ())?;
            }
            old.is_some()
        };
        w.commit()?;
        Ok(removed)
    }

    pub fn tier(&self, cid: &Cid) -> Result<Option<u8>, StoreError> {
        let r = self.db.begin_read()?;
        let index = r.open_table(INDEX)?;
        Ok(index.get(cid.as_bytes().as_slice())?.map(|g| g.value().3))
    }

    /// Replaces a chunk's tier flags. Moving between tiers copies no bytes.
    pub fn set_tier(&mut self, cid: &Cid, tier: u8) -> Result<bool, StoreError> {
        let w = self.db.begin_write()?;
        let found = {
            let mut index = w.open_table(INDEX)?;
            let key = cid.as_bytes().as_slice();
            let old = index.get(key)?.map(|g| g.value());
            if let Some((c, seg, slot, _)) = old {
                index.insert(key, (c, seg, slot, tier))?;
            }
            old.is_some()
        };
        w.commit()?;
        Ok(found)
    }

    pub fn len(&self) -> Result<u64, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(INDEX)?.len()?)
    }

    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    fn segment_path(&self, class: u8, seg: u32) -> PathBuf {
        self.root
            .join("slabs")
            .join(format!("c{}k", CLASSES[class as usize] / 1024))
            .join(format!("seg-{seg:06}"))
    }

    fn write_slot(&self, class: u8, seg: u32, slot: u32, bytes: &[u8]) -> Result<(), StoreError> {
        let path = self.segment_path(class, seg);
        fs::create_dir_all(path.parent().expect("segment has a parent dir"))?;
        let mut f = OpenOptions::new().create(true).truncate(false).write(true).open(path)?;
        f.seek(SeekFrom::Start(slot as u64 * bytes.len() as u64))?;
        f.write_all(bytes)?;
        if self.sync {
            f.sync_data()?;
        }
        Ok(())
    }
}

impl Store for SlabStore {
    type Error = StoreError;

    /// Own writes land in the pinned tier (ADR-0005).
    fn put(&mut self, cid: Cid, ciphertext: Vec<u8>) -> Result<(), StoreError> {
        self.insert(&cid, &ciphertext, tier::PINNED).map(|_| ())
    }

    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        self.fetch(cid)
    }
}

fn class_index(len: usize) -> Result<u8, StoreError> {
    CLASSES.iter().position(|&c| c == len).map(|i| i as u8).ok_or(StoreError::NotAClassSize(len))
}

/// Takes a free slot of this class, or the next never-used one.
fn allocate(w: &redb::WriteTransaction, class: u8) -> Result<(u32, u32), StoreError> {
    let mut free = w.open_table(FREE)?;
    let reusable = free
        .range((class, 0u32, 0u32)..=(class, u32::MAX, u32::MAX))?
        .next()
        .transpose()?
        .map(|(k, _)| k.value());
    if let Some(k) = reusable {
        free.remove(k)?;
        return Ok((k.1, k.2));
    }
    let mut next = w.open_table(NEXT)?;
    let n = next.get(class)?.map(|g| g.value()).unwrap_or(0);
    next.insert(class, n + 1)?;
    Ok(((n / SLOTS_PER_SEGMENT) as u32, (n % SLOTS_PER_SEGMENT) as u32))
}
