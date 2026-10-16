//! Records and namespace snapshots (phase 2, ADR-0016; irreversible decision 2:
//! canonical serialization). Draft v1.
//!
//! A record is a stable ID, attributes and content blocks. Everything signed
//! or content-addressed is encoded as **canonical msgpack** (the encoding RNS
//! and LXMF use), so equal data gives equal bytes:
//! - integers in their smallest form; floats always 64-bit, never NaN;
//! - strings UTF-8 and bytes as `bin`, both with the smallest length prefix;
//! - maps have string keys, sorted by their UTF-8 bytes, without duplicates.
//!
//! Decoding is strict: input that doesn't re-encode to the same bytes is rejected.
//!
//! ```text
//! record   = { "attrs": { key: value, … }, "blocks": [ [cid (bin 33), seed (bin 32), size], … ], "id": bin 16 }
//! snapshot = { "records": [ record, … sorted by id, unique ], "retifs": "ns-snapshot/1" }
//! value    = nil | bool | int (i64) | float (f64) | str | bin | [ value, … ]
//! ```
//! A snapshot is stored as an ordinary file (manifest, sealed chunks): one
//! version of a small namespace, e.g. a site or an app, published over a
//! channel (ADR-0015). Large namespaces will use Prolly trees instead.

use std::collections::BTreeMap;

use crate::{chunk::Seed, cid::Cid, manifest::FileRef};

pub const RECORD_ID_LEN: usize = 16;
pub const SNAPSHOT_TAG: &str = "ns-snapshot/1";

pub type RecordId = [u8; RECORD_ID_LEN];

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Value>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    Malformed(&'static str),
    /// Valid msgpack, but not the canonical form of what it encodes.
    NotCanonical,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Malformed(m) => write!(f, "malformed: {m}"),
            RecordError::NotCanonical => f.write_str("not canonical msgpack"),
        }
    }
}

impl std::error::Error for RecordError {}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub id: RecordId,
    pub attrs: BTreeMap<String, Value>,
    pub blocks: Vec<FileRef>,
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        write_map_len(out, 3);
        write_str(out, "attrs");
        write_map_len(out, self.attrs.len());
        // BTreeMap<String, _> iterates in byte order of the UTF-8 keys.
        for (k, v) in &self.attrs {
            write_str(out, k);
            write_value(out, v);
        }
        write_str(out, "blocks");
        write_array_len(out, self.blocks.len());
        for b in &self.blocks {
            write_array_len(out, 3);
            write_bin(out, b.root.as_bytes());
            write_bin(out, &b.seed.0);
            write_int(out, b.size as i64);
        }
        write_str(out, "id");
        write_bin(out, &self.id);
    }

    pub fn decode(bytes: &[u8]) -> Result<Record, RecordError> {
        let mut r = Reader(bytes);
        let rec = read_record(&mut r)?;
        if !r.0.is_empty() {
            return Err(RecordError::Malformed("trailing bytes"));
        }
        canonical(bytes, rec.encode())?;
        Ok(rec)
    }
}

/// All records of a namespace at one version.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot {
    /// Sorted by ID, unique.
    pub records: Vec<Record>,
}

impl Snapshot {
    pub fn new(mut records: Vec<Record>) -> Result<Snapshot, RecordError> {
        records.sort_by_key(|r| r.id);
        if records.windows(2).any(|w| w[0].id == w[1].id) {
            return Err(RecordError::Malformed("duplicate record id"));
        }
        Ok(Snapshot { records })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_map_len(&mut out, 2);
        write_str(&mut out, "records");
        write_array_len(&mut out, self.records.len());
        for r in &self.records {
            r.write(&mut out);
        }
        write_str(&mut out, "retifs");
        write_str(&mut out, SNAPSHOT_TAG);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Snapshot, RecordError> {
        let mut r = Reader(bytes);
        if r.map_len()? != 2 || r.str()? != "records" {
            return Err(RecordError::Malformed("snapshot fields"));
        }
        let n = r.array_len()?;
        let mut records = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            records.push(read_record(&mut r)?);
        }
        if r.str()? != "retifs" || r.str()? != SNAPSHOT_TAG || !r.0.is_empty() {
            return Err(RecordError::Malformed("not a namespace snapshot"));
        }
        let snap = Snapshot::new(records)?;
        canonical(bytes, snap.encode())?;
        Ok(snap)
    }

    /// Whether these bytes look like a snapshot (cheap check before decoding).
    pub fn is_snapshot(bytes: &[u8]) -> bool {
        bytes.len() > 20 && bytes.ends_with(SNAPSHOT_TAG.as_bytes())
    }
}

/// The canonical msgpack encoding of one value.
pub fn encode_value(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, v);
    out
}

fn canonical(input: &[u8], reencoded: Vec<u8>) -> Result<(), RecordError> {
    if input == reencoded.as_slice() { Ok(()) } else { Err(RecordError::NotCanonical) }
}

// ---------------------------------------------------------------- writing

fn write_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.push(0xc0),
        Value::Bool(b) => out.push(if *b { 0xc3 } else { 0xc2 }),
        Value::Int(i) => write_int(out, *i),
        Value::Float(f) => {
            assert!(!f.is_nan(), "NaN has no canonical form");
            out.push(0xcb);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Value::Str(s) => write_str(out, s),
        Value::Bytes(b) => write_bin(out, b),
        Value::List(items) => {
            write_array_len(out, items.len());
            for i in items {
                write_value(out, i);
            }
        }
    }
}

fn write_int(out: &mut Vec<u8>, i: i64) {
    if i >= 0 {
        let u = i as u64;
        match u {
            0..=0x7f => out.push(u as u8),
            0x80..=0xff => out.extend_from_slice(&[0xcc, u as u8]),
            0x100..=0xffff => {
                out.push(0xcd);
                out.extend_from_slice(&(u as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(0xce);
                out.extend_from_slice(&(u as u32).to_be_bytes());
            }
            _ => {
                out.push(0xcf);
                out.extend_from_slice(&u.to_be_bytes());
            }
        }
    } else {
        match i {
            -32..=-1 => out.push(i as i8 as u8),
            -128..=-33 => out.extend_from_slice(&[0xd0, i as i8 as u8]),
            -32768..=-129 => {
                out.push(0xd1);
                out.extend_from_slice(&(i as i16).to_be_bytes());
            }
            -2_147_483_648..=-32769 => {
                out.push(0xd2);
                out.extend_from_slice(&(i as i32).to_be_bytes());
            }
            _ => {
                out.push(0xd3);
                out.extend_from_slice(&i.to_be_bytes());
            }
        }
    }
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    let n = s.len();
    match n {
        0..=31 => out.push(0xa0 | n as u8),
        32..=0xff => out.extend_from_slice(&[0xd9, n as u8]),
        0x100..=0xffff => {
            out.push(0xda);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(0xdb);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(s.as_bytes());
}

fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
    let n = b.len();
    match n {
        0..=0xff => out.extend_from_slice(&[0xc4, n as u8]),
        0x100..=0xffff => {
            out.push(0xc5);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(0xc6);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(b);
}

fn write_array_len(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=15 => out.push(0x90 | n as u8),
        16..=0xffff => {
            out.push(0xdc);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(0xdd);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}

fn write_map_len(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=15 => out.push(0x80 | n as u8),
        16..=0xffff => {
            out.push(0xde);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(0xdf);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}

// ---------------------------------------------------------------- reading

fn read_record(r: &mut Reader) -> Result<Record, RecordError> {
    if r.map_len()? != 3 || r.str()? != "attrs" {
        return Err(RecordError::Malformed("record fields"));
    }
    let n = r.map_len()?;
    let mut attrs = BTreeMap::new();
    for _ in 0..n {
        let k = r.str()?;
        if k.is_empty() {
            return Err(RecordError::Malformed("empty attribute key"));
        }
        let v = r.value(0)?;
        if attrs.insert(k, v).is_some() {
            return Err(RecordError::Malformed("duplicate attribute"));
        }
    }
    if r.str()? != "blocks" {
        return Err(RecordError::Malformed("record fields"));
    }
    let n = r.array_len()?;
    let mut blocks = Vec::with_capacity(n.min(1 << 12));
    for _ in 0..n {
        if r.array_len()? != 3 {
            return Err(RecordError::Malformed("block ref"));
        }
        let cid = Cid::from_bytes(r.bin()?.try_into().map_err(|_| RecordError::Malformed("block cid"))?)
            .ok_or(RecordError::Malformed("CID version"))?;
        let seed = Seed(r.bin()?.try_into().map_err(|_| RecordError::Malformed("block seed"))?);
        let size = match r.value(0)? {
            Value::Int(n) if n >= 0 => n as u64,
            _ => return Err(RecordError::Malformed("block size")),
        };
        blocks.push(FileRef { root: cid, seed, size });
    }
    if r.str()? != "id" {
        return Err(RecordError::Malformed("record fields"));
    }
    let id: RecordId = r.bin()?.try_into().map_err(|_| RecordError::Malformed("record id"))?;
    Ok(Record { id, attrs, blocks })
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], RecordError> {
        if self.0.len() < n {
            return Err(RecordError::Malformed("truncated"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn byte(&mut self) -> Result<u8, RecordError> {
        Ok(self.take(1)?[0])
    }
    fn be(&mut self, n: usize) -> Result<u64, RecordError> {
        Ok(self.take(n)?.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }
    fn map_len(&mut self) -> Result<usize, RecordError> {
        let t = self.byte()?;
        match t {
            0x80..=0x8f => Ok((t & 0x0f) as usize),
            0xde => Ok(self.be(2)? as usize),
            0xdf => Ok(self.be(4)? as usize),
            _ => Err(RecordError::Malformed("expected a map")),
        }
    }
    fn array_len(&mut self) -> Result<usize, RecordError> {
        let t = self.byte()?;
        self.array_len_tagged(t)
    }
    fn array_len_tagged(&mut self, t: u8) -> Result<usize, RecordError> {
        match t {
            0x90..=0x9f => Ok((t & 0x0f) as usize),
            0xdc => Ok(self.be(2)? as usize),
            0xdd => Ok(self.be(4)? as usize),
            _ => Err(RecordError::Malformed("expected an array")),
        }
    }
    fn str(&mut self) -> Result<String, RecordError> {
        let t = self.byte()?;
        self.str_tagged(t)
    }
    fn str_tagged(&mut self, t: u8) -> Result<String, RecordError> {
        let n = match t {
            0xa0..=0xbf => (t & 0x1f) as usize,
            0xd9 => self.be(1)? as usize,
            0xda => self.be(2)? as usize,
            0xdb => self.be(4)? as usize,
            _ => return Err(RecordError::Malformed("expected a string")),
        };
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| RecordError::Malformed("invalid UTF-8"))
    }
    fn bin(&mut self) -> Result<Vec<u8>, RecordError> {
        let t = self.byte()?;
        self.bin_tagged(t)
    }
    fn bin_tagged(&mut self, t: u8) -> Result<Vec<u8>, RecordError> {
        let n = match t {
            0xc4 => self.be(1)?,
            0xc5 => self.be(2)?,
            0xc6 => self.be(4)?,
            _ => return Err(RecordError::Malformed("expected bytes")),
        } as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn value(&mut self, depth: usize) -> Result<Value, RecordError> {
        if depth > 32 {
            return Err(RecordError::Malformed("nesting too deep"));
        }
        let t = self.byte()?;
        Ok(match t {
            0xc0 => Value::Null,
            0xc2 => Value::Bool(false),
            0xc3 => Value::Bool(true),
            0x00..=0x7f => Value::Int(t as i64),
            0xe0..=0xff => Value::Int(t as i8 as i64),
            0xcc => Value::Int(self.be(1)? as i64),
            0xcd => Value::Int(self.be(2)? as i64),
            0xce => Value::Int(self.be(4)? as i64),
            0xcf => Value::Int(i64::try_from(self.be(8)?).map_err(|_| RecordError::Malformed("integer above i64"))?),
            0xd0 => Value::Int(self.be(1)? as u8 as i8 as i64),
            0xd1 => Value::Int(self.be(2)? as u16 as i16 as i64),
            0xd2 => Value::Int(self.be(4)? as u32 as i32 as i64),
            0xd3 => Value::Int(self.be(8)? as i64),
            0xcb => {
                let f = f64::from_bits(self.be(8)?);
                if f.is_nan() {
                    return Err(RecordError::Malformed("NaN"));
                }
                Value::Float(f)
            }
            0xa0..=0xbf | 0xd9 | 0xda | 0xdb => Value::Str(self.str_tagged(t)?),
            0xc4..=0xc6 => Value::Bytes(self.bin_tagged(t)?),
            0x90..=0x9f | 0xdc | 0xdd => {
                let n = self.array_len_tagged(t)?;
                let mut items = Vec::with_capacity(n.min(1 << 12));
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::List(items)
            }
            _ => return Err(RecordError::Malformed("unsupported msgpack type")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u8) -> Record {
        let mut attrs = BTreeMap::new();
        attrs.insert("path".into(), Value::Str(format!("/site/page{id}.mu")));
        attrs.insert("type".into(), Value::Str("page".into()));
        attrs.insert("size".into(), Value::Int(1234));
        attrs.insert("rating".into(), Value::Float(4.5));
        attrs.insert("tags".into(), Value::List(vec![Value::Str("a".into()), Value::Int(-40)]));
        Record { id: [id; 16], attrs, blocks: vec![FileRef { root: Cid::of(&[id]), seed: Seed([id; 32]), size: 99 }] }
    }

    #[test]
    fn records_and_snapshots_roundtrip_canonically() {
        let snap = Snapshot::new(vec![rec(2), rec(1)]).unwrap();
        assert_eq!(snap.records[0].id, [1; 16], "sorted by id");
        let bytes = snap.encode();
        assert!(Snapshot::is_snapshot(&bytes));
        assert_eq!(Snapshot::decode(&bytes).unwrap(), snap);
        assert!(Snapshot::new(vec![rec(1), rec(1)]).is_err());
        let r = rec(3).encode();
        assert_eq!(Record::decode(&r).unwrap(), rec(3));
    }

    #[test]
    fn integers_use_their_smallest_form_and_non_canonical_input_is_rejected() {
        for (i, hex) in [(0i64, "00"), (127, "7f"), (128, "cc80"), (300, "cd012c"), (-1, "ff"), (-33, "d0df"), (-40000, "d2ffff63c0")] {
            assert_eq!(hex::encode(encode_value(&Value::Int(i))), hex, "{i}");
        }
        // 5 encoded as uint8 (0xcc 05) instead of a fixint: same value, not canonical.
        let mut r = rec(4);
        r.attrs.clear();
        r.attrs.insert("n".into(), Value::Int(5));
        let good = r.encode();
        let pos = good.windows(2).position(|w| w == [0xa1, b'n']).unwrap() + 2;
        let bad = [&good[..pos], &[0xcc, 0x05], &good[pos + 1..]].concat();
        assert_eq!(Record::decode(&bad), Err(RecordError::NotCanonical));
    }
}
