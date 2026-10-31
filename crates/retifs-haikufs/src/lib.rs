//! retifs as a Haiku file system (ADR-0002): a userlandfs module with
//! Haiku's own kernel file system interface, so a namespace is a volume
//! Tracker browses, with each record's attributes as Haiku attributes.
//! Like the FUSE mount it holds no keys and no store: it talks to the local
//! `retifsd` through `libretifs`.
//!
//! Read-only for now: files, directories, contents and attributes, and
//! queries in Haiku's query language, live ones included (Tracker's Find,
//! `query`), answered by retifs (see `query`).
//!
//! Install the built library as `~/config/non-packaged/add-ons/userlandfs/retifs`
//! and mount a namespace with
//! `mount -t userlandfs -p "retifs ns=NAME [store=DIR] [wait=SECONDS]" /mnt/point`.
//! On other systems only its plain parts build (for their tests).

// Off Haiku only the plain parts build (for their tests); the C side uses them.
#![cfg_attr(not(target_os = "haiku"), allow(dead_code))]

#[cfg(target_os = "haiku")]
mod ffi;
#[cfg(target_os = "haiku")]
mod ops;
mod query;
pub mod types;
mod volume;
