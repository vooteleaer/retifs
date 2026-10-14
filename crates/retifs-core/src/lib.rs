//! retifs core: the format-defining pieces (prototype, unstable).
//!
//! Chunk encryption, padding and CIDs follow ADR-0008 (status: proposed).
//! Nothing here may be used for real data until that ADR is accepted.

pub mod chunk;
pub mod chunker;
pub mod cid;
pub mod manifest;
pub mod secret;

pub use chunk::{open, seal, seal_with, ChunkError, Compression, Sealed, Seed};
pub use cid::Cid;
pub use manifest::{FileRef, ManifestError, Store};
pub use secret::ConvergenceSecret;
