//! Content-defined chunking (FastCDC 2020).
//!
//! Chunk boundaries only affect dedup, not compatibility, so these parameters
//! are not an irreversible decision (writer policy v1, ADR-0008).
//!
//! Every chunk except a file's last falls between 8 KiB and 16 KiB − 68 bytes,
//! so it seals into exactly the 16 KiB class: about 10 % padding overhead
//! (vs 49 % with an unaligned 4/16/60 KiB chunker), and chunk sizes reveal
//! nothing about the content.

use fastcdc::v2020::FastCDC;

use crate::chunk::{class_for, OVERHEAD};

pub const TARGET_CLASS: usize = 16 * 1024;
pub const MIN_SIZE: u32 = 8 * 1024;
pub const AVG_SIZE: u32 = 12 * 1024;
/// The largest payload that still fits `TARGET_CLASS` (frame length prefix is 4 bytes).
pub const MAX_SIZE: u32 = (TARGET_CLASS - OVERHEAD - 4) as u32;

const _: () = assert!(MAX_SIZE == 16 * 1024 - 68);

/// Splits `data` into content-defined pieces.
pub fn split(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    debug_assert_eq!(class_for(MAX_SIZE as usize), Some(TARGET_CLASS));
    debug_assert_eq!(class_for(MIN_SIZE as usize), Some(TARGET_CLASS));
    FastCDC::new(data, MIN_SIZE, AVG_SIZE, MAX_SIZE).map(move |c| &data[c.offset..c.offset + c.length])
}
