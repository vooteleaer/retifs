//! retifs networking over Reticulum via Prns (prototype).
//!
//! - [`protocol`]: the `/retifs/get` wire format
//! - [`node`]: Prns node helpers (attach to prnsd, identity, destinations)
//! - [`fetch`]: batched, pipelined fetching of a whole file by read-cap

pub mod fetch;
pub mod node;
pub mod protocol;
