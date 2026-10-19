//! The local record database (phase 2, ADR-0016): records per namespace and an
//! order-preserving index of their attribute values, for BeFS-style queries.
//!
//! ```text
//! NAMESPACES  name → ()
//! RECORDS     ns ‖ 0x00 ‖ id (16)                              → canonical record bytes
//! ATTRS       ns ‖ 0x00 ‖ key ‖ 0x00 ‖ sort key(value) ‖ id    → ()
//! ```
//! Sort keys order values within a type: ints and floats numerically, strings
//! and bytes bytewise. A list value is indexed once per element (`tags`).
//! Namespace names and attribute keys may not contain NUL.

use std::collections::{BTreeMap, BTreeSet};

use redb::{ReadableTable, TableDefinition};
use retifs_core::record::{Record, RecordId, Value};

use crate::{SlabStore, StoreError};

const NAMESPACES: TableDefinition<&str, ()> = TableDefinition::new("namespaces");
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
const ATTRS: TableDefinition<&[u8], ()> = TableDefinition::new("attrs");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(NAMESPACES)?;
    w.open_table(RECORDS)?;
    w.open_table(ATTRS)?;
    Ok(())
}

/// One condition of a query; a query is the AND of its terms.
#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Eq(String, Value),
    /// `key` within `lo ..= hi` (either bound open), same value type as the bounds.
    Range(String, Option<Value>, Option<Value>, bool, bool),
    Prefix(String, String),
    Has(String),
}

impl Term {
    /// Parses one term: `key=value`, `key>v`, `key>=v`, `key<v`, `key<=v`,
    /// `key^=prefix`, `has:key`. Values: `true`/`false`, integers, decimals,
    /// otherwise a string (quote with "" to force a string).
    pub fn parse(s: &str) -> Result<Term, String> {
        if let Some(k) = s.strip_prefix("has:") {
            return Ok(Term::Has(k.to_string()));
        }
        for op in ["^=", ">=", "<=", "=", ">", "<"] {
            if let Some(i) = s.find(op) {
                let (k, v) = (s[..i].to_string(), &s[i + op.len()..]);
                if k.is_empty() {
                    break;
                }
                return Ok(match op {
                    "^=" => Term::Prefix(k, unquote(v)),
                    "=" => Term::Eq(k, parse_value(v)),
                    ">" => Term::Range(k, Some(parse_value(v)), None, false, true),
                    ">=" => Term::Range(k, Some(parse_value(v)), None, true, true),
                    "<" => Term::Range(k, None, Some(parse_value(v)), true, false),
                    _ => Term::Range(k, None, Some(parse_value(v)), true, true),
                });
            }
        }
        Err(format!("can't parse query term {s:?}"))
    }
}

impl Term {
    /// Whether a record satisfies this term, the same way the index answers it
    /// (for records held in memory, e.g. an older version's snapshot).
    pub fn matches(&self, r: &Record) -> bool {
        let keys = |k: &str| r.attrs.get(k).map(index_values).unwrap_or_default();
        match self {
            Term::Has(k) => r.attrs.contains_key(k),
            Term::Eq(k, v) => sort_key(v).is_some_and(|want| keys(k).contains(&want)),
            Term::Prefix(k, p) => keys(k).iter().any(|sk| sk.first() == Some(&4) && sk[1..].starts_with(p.as_bytes())),
            Term::Range(k, lo, hi, lo_incl, hi_incl) => {
                let tag = lo.as_ref().or(hi.as_ref()).and_then(sort_key).map(|s| s[0]);
                let (lo, hi) = (lo.as_ref().and_then(sort_key), hi.as_ref().and_then(sort_key));
                keys(k).iter().any(|sk| {
                    Some(sk[0]) == tag
                        && lo.as_ref().is_none_or(|l| if *lo_incl { sk >= l } else { sk > l })
                        && hi.as_ref().is_none_or(|h| if *hi_incl { sk <= h } else { sk < h })
                })
            }
        }
    }
}

fn unquote(v: &str) -> String {
    v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v).to_string()
}

/// A value typed on the command line: bool, integer, decimal or string.
pub fn parse_value(v: &str) -> Value {
    if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
        return Value::Str(unquote(v));
    }
    match v {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => v
            .parse::<i64>()
            .map(Value::Int)
            .or_else(|_| v.parse::<f64>().ok().filter(|f| f.is_finite()).map(Value::Float).ok_or(()))
            .unwrap_or_else(|_| Value::Str(v.to_string())),
    }
}

/// Order-preserving encoding of a scalar value (type tag first).
fn sort_key(v: &Value) -> Option<Vec<u8>> {
    Some(match v {
        Value::Null => vec![0],
        Value::Bool(b) => vec![1, *b as u8],
        Value::Int(i) => [&[2u8][..], &((*i as u64) ^ (1 << 63)).to_be_bytes()].concat(),
        Value::Float(f) => {
            let bits = f.to_bits();
            let ordered = if bits >> 63 == 1 { !bits } else { bits | (1 << 63) };
            [&[3u8][..], &ordered.to_be_bytes()].concat()
        }
        Value::Str(s) => [&[4u8][..], s.as_bytes()].concat(),
        Value::Bytes(b) => [&[5u8][..], b].concat(),
        Value::List(_) => return None,
    })
}

fn index_values(v: &Value) -> Vec<Vec<u8>> {
    match v {
        Value::List(items) => items.iter().filter_map(sort_key).collect(),
        other => sort_key(other).into_iter().collect(),
    }
}

fn ns_prefix(ns: &str) -> Vec<u8> {
    [ns.as_bytes(), &[0]].concat()
}

fn attr_prefix(ns: &str, key: &str) -> Vec<u8> {
    [ns.as_bytes(), &[0], key.as_bytes(), &[0]].concat()
}

fn index_keys(ns: &str, r: &Record) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (k, v) in &r.attrs {
        for sk in index_values(v) {
            out.push([attr_prefix(ns, k).as_slice(), &sk, &r.id].concat());
        }
    }
    out
}

/// Keys starting with `prefix`: `prefix ..` its successor.
fn after(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return end;
        }
    }
    vec![0xff; prefix.len() + 1]
}

impl SlabStore {
    pub fn create_namespace(&self, ns: &str) -> Result<(), StoreError> {
        if ns.is_empty() || ns.contains('\0') {
            return Err(StoreError::Full("namespace names are non-empty, without NUL"));
        }
        let w = self.db.begin_write()?;
        w.open_table(NAMESPACES)?.insert(ns, ())?;
        w.commit()?;
        Ok(())
    }

    pub fn namespaces(&self) -> Result<Vec<String>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(NAMESPACES)?;
        t.iter()?.map(|e| e.map(|(k, _)| k.value().to_string()).map_err(StoreError::from)).collect()
    }

    /// Stores (or replaces) a record and reindexes its attributes.
    pub fn put_record(&self, ns: &str, rec: &Record) -> Result<(), StoreError> {
        if rec.attrs.keys().any(|k| k.contains('\0')) {
            return Err(StoreError::Full("attribute keys may not contain NUL"));
        }
        let key = [ns_prefix(ns).as_slice(), &rec.id].concat();
        let w = self.db.begin_write()?;
        {
            w.open_table(NAMESPACES)?.insert(ns, ())?;
            let mut records = w.open_table(RECORDS)?;
            let mut attrs = w.open_table(ATTRS)?;
            if let Some(old) = records.get(key.as_slice())?.map(|v| v.value().to_vec())
                && let Ok(old) = Record::decode(&old)
            {
                for k in index_keys(ns, &old) {
                    attrs.remove(k.as_slice())?;
                }
            }
            records.insert(key.as_slice(), rec.encode().as_slice())?;
            for k in index_keys(ns, rec) {
                attrs.insert(k.as_slice(), ())?;
            }
        }
        w.commit()?;
        Ok(())
    }

    pub fn get_record(&self, ns: &str, id: &RecordId) -> Result<Option<Record>, StoreError> {
        let r = self.db.begin_read()?;
        let key = [ns_prefix(ns).as_slice(), id].concat();
        Ok(r.open_table(RECORDS)?.get(key.as_slice())?.and_then(|v| Record::decode(v.value()).ok()))
    }

    pub fn delete_record(&self, ns: &str, id: &RecordId) -> Result<bool, StoreError> {
        let key = [ns_prefix(ns).as_slice(), id].concat();
        let w = self.db.begin_write()?;
        let found = {
            let mut records = w.open_table(RECORDS)?;
            let old = records.remove(key.as_slice())?.map(|v| v.value().to_vec());
            if let Some(old) = &old
                && let Ok(old) = Record::decode(old)
            {
                let mut attrs = w.open_table(ATTRS)?;
                for k in index_keys(ns, &old) {
                    attrs.remove(k.as_slice())?;
                }
            }
            old.is_some()
        };
        w.commit()?;
        Ok(found)
    }

    /// All records of a namespace, by ID.
    pub fn records(&self, ns: &str) -> Result<Vec<Record>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(RECORDS)?;
        let start = ns_prefix(ns);
        let end = after(&start);
        t.range(start.as_slice()..end.as_slice())?
            .filter_map(|e| e.ok().and_then(|(_, v)| Record::decode(v.value()).ok()).map(Ok))
            .collect()
    }

    /// Records matching every term, by ID.
    pub fn query(&self, ns: &str, terms: &[Term]) -> Result<Vec<Record>, StoreError> {
        let mut ids: Option<BTreeSet<RecordId>> = None;
        for t in terms {
            let found = self.term_ids(ns, t)?;
            ids = Some(match ids {
                None => found,
                Some(prev) => prev.intersection(&found).copied().collect(),
            });
            if ids.as_ref().is_some_and(|s| s.is_empty()) {
                break;
            }
        }
        let mut out = Vec::new();
        match ids {
            None => out = self.records(ns)?,
            Some(ids) => {
                for id in ids {
                    if let Some(r) = self.get_record(ns, &id)? {
                        out.push(r);
                    }
                }
            }
        }
        Ok(out)
    }

    fn term_ids(&self, ns: &str, t: &Term) -> Result<BTreeSet<RecordId>, StoreError> {
        let r = self.db.begin_read()?;
        let attrs = r.open_table(ATTRS)?;
        let (lo, hi): (Vec<u8>, Vec<u8>) = match t {
            Term::Has(k) => {
                let p = attr_prefix(ns, k);
                (p.clone(), after(&p))
            }
            Term::Eq(k, v) => {
                let p = [attr_prefix(ns, k), sort_key(v).unwrap_or_default()].concat();
                (p.clone(), after(&p))
            }
            Term::Prefix(k, s) => {
                let p = [attr_prefix(ns, k), vec![4], s.as_bytes().to_vec()].concat();
                (p.clone(), after(&p))
            }
            Term::Range(k, lo, hi, lo_incl, hi_incl) => {
                let base = attr_prefix(ns, k);
                // The type of the bounds limits the range to that type.
                let tag = lo.as_ref().or(hi.as_ref()).and_then(sort_key).map(|s| s[0]).unwrap_or(0);
                let lo_key = match lo.as_ref().and_then(sort_key) {
                    Some(sk) if *lo_incl => [base.as_slice(), &sk].concat(),
                    Some(sk) => after(&[base.as_slice(), &sk].concat()),
                    None => [base.as_slice(), &[tag]].concat(),
                };
                let hi_key = match hi.as_ref().and_then(sort_key) {
                    Some(sk) if *hi_incl => after(&[base.as_slice(), &sk].concat()),
                    Some(sk) => [base.as_slice(), &sk].concat(),
                    None => after(&[base.as_slice(), &[tag]].concat()),
                };
                (lo_key, hi_key)
            }
        };
        let mut out = BTreeSet::new();
        if lo >= hi {
            return Ok(out);
        }
        for e in attrs.range(lo.as_slice()..hi.as_slice())? {
            let (k, _) = e?;
            let k = k.value();
            if k.len() >= 16 {
                out.insert(k[k.len() - 16..].try_into().unwrap());
            }
        }
        Ok(out)
    }

    /// Replaces a namespace's records with a snapshot's (a followed channel's new version).
    pub fn replace_namespace(&self, ns: &str, records: &[Record]) -> Result<(), StoreError> {
        let keep: BTreeMap<RecordId, &Record> = records.iter().map(|r| (r.id, r)).collect();
        for old in self.records(ns)? {
            if !keep.contains_key(&old.id) {
                self.delete_record(ns, &old.id)?;
            }
        }
        for r in records {
            if self.get_record(ns, &r.id)?.as_ref() != Some(r) {
                self.put_record(ns, r)?;
            }
        }
        Ok(())
    }
}
