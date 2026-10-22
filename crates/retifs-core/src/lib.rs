//! retifs core: the format-defining pieces (prototype, unstable).
//!
//! Chunk encryption, padding and CIDs follow ADR-0008 (status: proposed).
//! Nothing here may be used for real data until that ADR is accepted.

pub mod access;
pub mod channel;
pub mod checkpoint;
pub mod chunk;
pub mod chunker;
pub mod cid;
pub mod index;
pub mod invite;
pub mod keywrap;
pub mod lease;
pub mod ops;
pub mod prolly;
pub mod record;
pub mod manifest;
pub mod secret;
pub mod share;
pub mod stamp;
pub mod words;

pub use access::ChunkToken;
pub use chunk::{open, seal, seal_with, ChunkError, Compression, Sealed, Seed};
pub use cid::Cid;
pub use manifest::{FileRef, ManifestError, Store};
pub use secret::ConvergenceSecret;
