//! retifs as a Haiku file system (ADR-0002): a userlandfs module with
//! Haiku's own kernel file system interface, so a namespace is a volume
//! Tracker browses, with each record's attributes as Haiku attributes.
//! Like the FUSE mount it holds no keys and no store: it talks to the local
//! `retifsd` through `libretifs`.
//!
//! Read-only for now: files, directories, contents and attributes. Indexes
//! and live queries come next.
//!
//! Install the built library as `~/config/non-packaged/add-ons/userlandfs/retifs`
//! and mount a namespace with
//! `mount -t userlandfs -p "retifs ns=NAME [store=DIR] [wait=SECONDS]" /mnt/point`.
//! On other systems this crate builds empty.

#[cfg(target_os = "haiku")]
mod ffi;
#[cfg(target_os = "haiku")]
mod ops;
pub mod types;
mod volume;
