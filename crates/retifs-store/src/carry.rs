//! What a storage-less node carries over a restart besides its keyring
//! (ADR-0031): where its own data is kept. Its store is in memory; without
//! this, its leases would go unrenewed and its copies elsewhere run out.
//!
//! ```text
//! version (1) ‖ (table (1) ‖ key len (4) ‖ key ‖ value len (4) ‖ value) × n
//! ```
//! Tables, by number: 0 needed files, 1 own leases, 2 holder records,
//! 3 storage nodes heard. Rows are the store's own, as they are in its index.

use redb::{ReadableTable, TableDefinition};

use crate::{
    leases::OWN_LEASES,
    placement::{HOLDER_STATS, NEEDED, STORAGE_NODES},
    SlabStore, StoreError,
};

const VERSION: u8 = 1;

const TABLES: [TableDefinition<&[u8], &[u8]>; 4] = [NEEDED, OWN_LEASES, HOLDER_STATS, STORAGE_NODES];

impl SlabStore {
    /// This node's placement: the files it needs kept, its leases, the
    /// holders' records and the storage nodes it has heard.
    pub fn export_placement(&self) -> Result<Vec<u8>, StoreError> {
        let r = self.db.begin_read()?;
        let mut out = vec![VERSION];
        for (i, def) in TABLES.iter().enumerate() {
            let t = r.open_table(*def)?;
            for e in t.iter()? {
                let (k, v) = e?;
                out.push(i as u8);
                for part in [k.value(), v.value()] {
                    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
                    out.extend_from_slice(part);
                }
            }
        }
        Ok(out)
    }

    /// Puts an exported placement back (into a fresh store). Returns how many
    /// rows; a placement it can't read is left out whole.
    pub fn import_placement(&self, bytes: &[u8]) -> Result<usize, StoreError> {
        let Some((&VERSION, mut rest)) = bytes.split_first() else { return Ok(0) };
        let mut rows: Vec<(usize, &[u8], &[u8])> = Vec::new();
        fn take<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
            let n = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let part = rest.get(4..4 + n)?;
            *rest = &rest[4 + n..];
            Some(part)
        }
        while let Some((&table, after)) = rest.split_first() {
            rest = after;
            let (Some(k), Some(v)) = (take(&mut rest), take(&mut rest)) else { return Ok(0) };
            if (table as usize) >= TABLES.len() {
                return Ok(0);
            }
            rows.push((table as usize, k, v));
        }
        let w = self.write()?;
        {
            let mut tables = TABLES.iter().map(|d| w.open_table(*d)).collect::<Result<Vec<_>, _>>()?;
            for (t, k, v) in &rows {
                tables[*t].insert(*k, *v)?;
            }
        }
        w.commit()?;
        Ok(rows.len())
    }
}
