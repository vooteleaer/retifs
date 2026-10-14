//! retifs networking over Reticulum via Prns (prototype).
//!
//! - [`protocol`]: the `/retifs/get` wire format
//! - [`node`]: Prns node helpers (attach to prnsd, identity, destinations)
//! - [`transport`]: the transport seam (ADR-0003) and its Prns implementation
//! - [`fetch`]: local-first, batched, multi-link/multi-source fetching by read-cap
//! - [`seek`]: one `have` + `get` round for continuous seeking (ADR-0010)

pub mod fetch;
pub mod node;
pub mod protocol;
pub mod seek;
pub mod transport;
