//! Content-defined chunking (FastCDC 2020).
//!
//! Chunk boundaries only affect dedup, not compatibility, so these parameters
//! are not an irreversible decision (writer policy v1, ADR-0008).
//!
//! Every chunk except a file's last falls between 8 KiB and 16 KiB − 69 bytes,
//! so it seals into exactly the 16 KiB class: about 10 % padding overhead
//! (vs 49 % with an unaligned 4/16/60 KiB chunker), and chunk sizes reveal
//! nothing about the content.

use std::io::Read;

use fastcdc::v2020::{FastCDC, StreamCDC};

use crate::chunk::{class_for, FRAME_HEADER, OVERHEAD};

pub const TARGET_CLASS: usize = 16 * 1024;
pub const MIN_SIZE: u32 = 8 * 1024;
pub const AVG_SIZE: u32 = 12 * 1024;
/// The largest payload that still fits `TARGET_CLASS` uncompressed.
pub const MAX_SIZE: u32 = (TARGET_CLASS - OVERHEAD - FRAME_HEADER) as u32;

const _: () = assert!(MAX_SIZE == 16 * 1024 - 69);

/// Splits `data` into content-defined pieces.
pub fn split(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    debug_assert_eq!(class_for(MAX_SIZE as usize), Some(TARGET_CLASS));
    debug_assert_eq!(class_for(MIN_SIZE as usize), Some(TARGET_CLASS));
    FastCDC::new(data, MIN_SIZE, AVG_SIZE, MAX_SIZE).map(move |c| &data[c.offset..c.offset + c.length])
}

/// The same pieces as [`split`], read from a stream: never more than one
/// piece in memory.
pub fn split_reader<R: Read>(source: R) -> impl Iterator<Item = std::io::Result<Vec<u8>>> {
    StreamCDC::new(source, MIN_SIZE, AVG_SIZE, MAX_SIZE).map(|c| c.map(|c| c.data).map_err(|e| std::io::Error::other(e.to_string())))
}
