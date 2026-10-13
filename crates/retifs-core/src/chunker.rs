//! Content-defined chunking (FastCDC 2020).
//!
//! Chunk boundaries only affect dedup, not compatibility, so these parameters
//! are not an irreversible decision. They are tuned for LoRa-friendly chunks.

use fastcdc::v2020::FastCDC;

use crate::chunk::MAX_DATA;

pub const MIN_SIZE: u32 = 4 * 1024;
pub const AVG_SIZE: u32 = 16 * 1024;
pub const MAX_SIZE: u32 = 60 * 1024;

const _: () = assert!((MAX_SIZE as usize) <= MAX_DATA);

/// Splits `data` into content-defined pieces.
pub fn split(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    FastCDC::new(data, MIN_SIZE, AVG_SIZE, MAX_SIZE).map(move |c| &data[c.offset..c.offset + c.length])
}
