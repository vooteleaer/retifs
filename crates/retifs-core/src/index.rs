//! The blind index (ADR-0019, irreversible decision 10): exact-match search
//! that a node can answer without the read key.
//!
//! ```text
//! token key     = HKDF-SHA256(ikm = read key, salt = "retifs/v1/index-token",  info = "", L = 32)
//! search secret = HKDF-SHA256(ikm = read key, salt = "retifs/v1/index-search", info = "", L = 32)
//! token         = HMAC-SHA256(token key, canonical msgpack [key, value])[0..16]
//! K_t           = HKDF-SHA256(ikm = token key, salt = "retifs/v1/index-entry", info = token, L = 32)
//! entry         = AES-256-Encrypt(K_t, record id)                  one block
//! index         = Prolly tree of token ‖ entry (32-byte keys) → nil, sealed under the search secret
//!
//! index channel (ADR-0015): signing seed = HKDF-SHA256(ikm = read key, salt = "retifs/v1/index-writer", L = 32),
//!                           read key     = the search secret
//! descriptor    = { "index": nil | [cid (bin 33), seed (bin 32)],      one per channel version,
//!                   "state": bin Token(state key, [cid, seed, size]),    canonical msgpack
//!                   "time":  int (unix ms) }
//! state key     = HKDF-SHA256(ikm = token key, salt = "retifs/v1/index-state", info = "", L = 64)
//! query proof   = HMAC-SHA256(search secret, "retifs/v1/index-query" ‖ link id)
//! ```
//! - Every member derives the index channel from the read key, so a search
//!   capability is just its address (`retifs-ch:1:…`), and any member can
//!   find the index without asking. A revoke rotates the read key and so
//!   moves the index to a new channel.
//! - The descriptor names the checkpoint the index describes, encrypted to
//!   members: a search node can't open the state with it.
//! - Members hold the read key and so both keys. A search node is given the
//!   search secret only: it opens the index and scans by token, but can't
//!   compute a token for a guessed value or decrypt an entry.
//! - An entry depends on its token, so one record's entries under two tokens
//!   are unrelated: a search node can't intersect posting lists.
//! - Only declared keys are indexed (an index-settings record), and a list
//!   value is indexed per element.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    channel::{token_decrypt, token_seal, ChannelKey},
    chunk::Seed,
    cid::Cid,
    manifest::{FileRef, Store},
    prolly::{self, Root, TreeError},
    record::{read_block, write_array_len, write_bin, write_block, write_int, write_map_len, write_str, write_value, Reader, RecordError, RecordId, Value},
    secret::ConvergenceSecret,
};

pub const TOKEN_LEN: usize = 16;
pub type Token = [u8; TOKEN_LEN];
/// A record ID under its token's key.
pub type Entry = [u8; 16];

const TOKEN_SALT: &[u8] = b"retifs/v1/index-token";
const SEARCH_SALT: &[u8] = b"retifs/v1/index-search";
const ENTRY_SALT: &[u8] = b"retifs/v1/index-entry";
const WRITER_SALT: &[u8] = b"retifs/v1/index-writer";
const STATE_SALT: &[u8] = b"retifs/v1/index-state";
const QUERY_LABEL: &[u8] = b"retifs/v1/index-query";
/// A record with `type` = this declares which keys are searchable.
pub const SETTINGS_TYPE: &str = "retifs.index";
/// The settings record's attribute listing the keys (a list of strings;
/// `prefix:*` matches every key starting with `prefix:`).
pub const SETTINGS_KEYS: &str = "keys";

/// What a search node is given: opens the index, computes no tokens.
pub fn search_secret(read_key: &[u8; 32]) -> ConvergenceSecret {
    ConvergenceSecret::personal(hkdf(read_key, SEARCH_SALT, b""))
}

/// The index channel of the namespace with this read key: every member
/// derives the same one; its address is the search capability.
pub fn channel_key(read_key: &[u8; 32]) -> ChannelKey {
    ChannelKey::from_secrets(hkdf(read_key, WRITER_SALT, b""), *search_secret(read_key).as_bytes())
}

/// Proves to a search node, bound to the link, that the asker holds the search secret.
pub fn query_proof(search: &ConvergenceSecret, link_id: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(search.as_bytes()).expect("HMAC takes any key length");
    mac.update(QUERY_LABEL);
    mac.update(link_id);
    mac.finalize().into_bytes().into()
}

/// What one index channel version says: the index and (for members) the checkpoint it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub index: Option<Root>,
    pub state: Vec<u8>,
    pub time_ms: u64,
}

impl Descriptor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_map_len(&mut out, 3);
        write_str(&mut out, "index");
        match &self.index {
            None => out.push(0xc0),
            Some((cid, seed)) => {
                write_array_len(&mut out, 2);
                write_bin(&mut out, cid.as_bytes());
                write_bin(&mut out, &seed.0);
            }
        }
        write_str(&mut out, "state");
        write_bin(&mut out, &self.state);
        write_str(&mut out, "time");
        write_int(&mut out, self.time_ms as i64);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Descriptor, RecordError> {
        let mut r = Reader(bytes);
        if r.map_len()? != 3 || r.str()? != "index" {
            return Err(RecordError::Malformed("descriptor fields"));
        }
        let index = if r.0.first() == Some(&0xc0) {
            r.byte()?;
            None
        } else {
            if r.array_len()? != 2 {
                return Err(RecordError::Malformed("index root"));
            }
            let cid = Cid::from_bytes(r.bin()?.try_into().map_err(|_| RecordError::Malformed("index cid"))?)
                .ok_or(RecordError::Malformed("CID version"))?;
            let seed = Seed(r.bin()?.try_into().map_err(|_| RecordError::Malformed("index seed"))?);
            Some((cid, seed))
        };
        if r.str()? != "state" {
            return Err(RecordError::Malformed("descriptor fields"));
        }
        let state = r.bin()?;
        if r.str()? != "time" {
            return Err(RecordError::Malformed("descriptor fields"));
        }
        let time_ms = match r.value(0)? {
            Value::Int(t) if t >= 0 => t as u64,
            _ => return Err(RecordError::Malformed("descriptor time")),
        };
        if !r.0.is_empty() {
            return Err(RecordError::Malformed("trailing bytes"));
        }
        let d = Descriptor { index, state, time_ms };
        crate::record::canonical(bytes, d.encode())?;
        Ok(d)
    }
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out).expect("32 bytes is a valid HKDF output length");
    out
}

/// A member's keys for one namespace's index (from its read key).
#[derive(Clone)]
pub struct IndexKeys {
    token_key: [u8; 32],
}

impl IndexKeys {
    pub fn derive(read_key: &[u8; 32]) -> Self {
        IndexKeys { token_key: hkdf(read_key, TOKEN_SALT, b"") }
    }

    /// The token for `key = value`: what a member sends to search.
    pub fn token(&self, key: &str, value: &Value) -> Token {
        let mut msg = Vec::new();
        write_array_len(&mut msg, 2);
        write_str(&mut msg, key);
        write_value(&mut msg, value);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.token_key).expect("HMAC takes any key length");
        mac.update(&msg);
        mac.finalize().into_bytes()[..TOKEN_LEN].try_into().unwrap()
    }

    fn cipher(&self, token: &Token) -> Aes256 {
        Aes256::new(&hkdf(&self.token_key, ENTRY_SALT, token).into())
    }

    pub fn entry(&self, token: &Token, id: &RecordId) -> Entry {
        let mut block = GenericArray::from(*id);
        self.cipher(token).encrypt_block(&mut block);
        block.into()
    }

    fn state_key(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        Hkdf::<Sha256>::new(Some(STATE_SALT), &self.token_key).expand(b"", &mut out).expect("64 bytes is a valid HKDF output length");
        out
    }

    /// The checkpoint reference as a descriptor carries it (members only).
    pub fn seal_state(&self, checkpoint: &FileRef, iv: [u8; 16]) -> Vec<u8> {
        let mut pt = Vec::new();
        write_block(&mut pt, checkpoint);
        token_seal(&self.state_key(), &iv, &pt)
    }

    pub fn open_state(&self, sealed: &[u8]) -> Option<FileRef> {
        let pt = token_decrypt(&self.state_key(), sealed)?;
        let mut r = Reader(&pt);
        let f = read_block(&mut r).ok()?;
        r.0.is_empty().then_some(f)
    }

    pub fn open_entry(&self, token: &Token, entry: &Entry) -> RecordId {
        let mut block = GenericArray::from(*entry);
        self.cipher(token).decrypt_block(&mut block);
        block.into()
    }
}

/// Whether `key` is searchable under the declared patterns.
pub fn declared(key: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) if prefix.ends_with(':') => key.starts_with(prefix) && key.len() > prefix.len(),
        _ => p == key,
    })
}

/// The declared keys from a namespace's settings records (their `keys` lists, merged).
pub fn declared_keys<'a>(records: impl IntoIterator<Item = &'a [(String, Value)]>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for attrs in records {
        let is_settings = attrs.iter().any(|(k, v)| k == "type" && *v == Value::Str(SETTINGS_TYPE.into()));
        if !is_settings {
            continue;
        }
        for (k, v) in attrs {
            if k != SETTINGS_KEYS {
                continue;
            }
            let items: &[Value] = match v {
                Value::List(l) => l,
                other => std::slice::from_ref(other),
            };
            out.extend(items.iter().filter_map(|i| match i {
                Value::Str(s) => Some(s.trim().to_string()),
                _ => None,
            }));
        }
    }
    out.retain(|s| !s.is_empty());
    out.sort();
    out.dedup();
    out
}

/// The tree keys (token ‖ entry, sorted, unique) for these records' declared attributes.
pub fn index_keys<'a>(keys: &IndexKeys, records: impl IntoIterator<Item = (RecordId, &'a [(String, Value)])>, patterns: &[String]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for (id, attrs) in records {
        for (k, v) in attrs {
            if !declared(k, patterns) {
                continue;
            }
            let values: &[Value] = match v {
                Value::List(l) => l,
                Value::Null => &[],
                other => std::slice::from_ref(other),
            };
            for value in values {
                let t = keys.token(k, value);
                let mut key = [0u8; 32];
                key[..16].copy_from_slice(&t);
                key[16..].copy_from_slice(&keys.entry(&t, &id));
                out.push(key);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Stores the index of `tree_keys` as a Prolly tree under the search secret.
pub fn build<S: Store>(store: &mut S, search: &ConvergenceSecret, tree_keys: Vec<[u8; 32]>) -> Result<Option<Root>, TreeError<S::Error>> {
    prolly::build(store, search, tree_keys.into_iter().map(|k| (k, vec![0xc0])).collect())
}

/// The entries under `token` (what a search node answers; needs no keys).
pub fn lookup<S: Store>(store: &S, root: &Root, token: &Token) -> Result<Vec<Entry>, TreeError<S::Error>> {
    Ok(prolly::scan_prefix(store, root, token)?
        .into_iter()
        .filter_map(|(k, _)| k.get(TOKEN_LEN..).and_then(|e| e.try_into().ok()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::Cid;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Mem(HashMap<Cid, Vec<u8>>);
    impl Store for Mem {
        type Error = std::convert::Infallible;
        fn put(&mut self, cid: Cid, ct: Vec<u8>) -> Result<(), Self::Error> {
            self.0.insert(cid, ct);
            Ok(())
        }
        fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(cid).cloned())
        }
    }

    fn s(v: &str) -> Value {
        Value::Str(v.into())
    }

    #[test]
    fn declared_patterns() {
        let p = vec!["album".to_string(), "tags:*".to_string()];
        assert!(declared("album", &p));
        assert!(declared("tags:urgent", &p));
        assert!(!declared("tags:", &p));
        assert!(!declared("albums", &p));
        assert!(!declared("title", &p));
        let settings = vec![("type".to_string(), s(SETTINGS_TYPE)), ("keys".to_string(), Value::List(vec![s("album"), s(" type ")]))];
        let other = vec![("type".to_string(), s("image")), ("keys".to_string(), Value::List(vec![s("title")]))];
        assert_eq!(declared_keys([settings.as_slice(), other.as_slice()]), vec!["album".to_string(), "type".to_string()]);
    }

    #[test]
    fn entries_open_and_are_unlinkable_across_tokens() {
        let k = IndexKeys::derive(&[7; 32]);
        let id = [3u8; 16];
        let (a, b) = (k.token("album", &s("Prangli")), k.token("type", &s("image")));
        assert_eq!(k.open_entry(&a, &k.entry(&a, &id)), id);
        assert_ne!(k.entry(&a, &id), k.entry(&b, &id));
        // Values are typed: Int 5 and Str "5" differ.
        assert_ne!(k.token("n", &Value::Int(5)), k.token("n", &s("5")));
        // Another namespace (read key) gives other tokens.
        assert_ne!(IndexKeys::derive(&[8; 32]).token("album", &s("Prangli")), a);
    }

    #[test]
    fn descriptor_channel_and_state() {
        let keys = IndexKeys::derive(&[1; 32]);
        let cp = FileRef { root: Cid::of(b"checkpoint"), seed: Seed([4; 32]), size: 1234 };
        let d = Descriptor { index: Some((Cid::of(b"index"), Seed([5; 32]))), state: keys.seal_state(&cp, [6; 16]), time_ms: 1_700_000_000_000 };
        assert_eq!(Descriptor::decode(&d.encode()).unwrap(), d);
        let empty = Descriptor { index: None, ..d.clone() };
        assert_eq!(Descriptor::decode(&empty.encode()).unwrap(), empty);
        assert_eq!(keys.open_state(&d.state), Some(cp));
        assert_eq!(IndexKeys::derive(&[2; 32]).open_state(&d.state), None, "other members' keys don't open it");
        // Every member derives the same channel; its read key is the search secret.
        assert_eq!(channel_key(&[1; 32]).addr().to_string(), channel_key(&[1; 32]).addr().to_string());
        assert!(channel_key(&[1; 32]).addr().to_string().ends_with(&hex::encode(search_secret(&[1; 32]).as_bytes())));
        assert_ne!(channel_key(&[1; 32]).ns_id(), channel_key(&[2; 32]).ns_id());
    }

    #[test]
    fn search_finds_exactly_the_matching_records() {
        let read_key = [9u8; 32];
        let keys = IndexKeys::derive(&read_key);
        let patterns = vec!["album".to_string(), "type".to_string(), "tags:*".to_string()];
        let mut recs: Vec<(RecordId, Vec<(String, Value)>)> = Vec::new();
        for i in 0..2000u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_be_bytes());
            let mut attrs = vec![("type".to_string(), s(if i % 2 == 0 { "image" } else { "note" })), ("title".to_string(), s(&format!("t{i}")))];
            if i % 100 == 7 {
                attrs.push(("album".to_string(), s("Prangli 2026")));
            }
            if i == 42 {
                attrs.push(("tags:urgent".to_string(), Value::Bool(true)));
            }
            recs.push((id, attrs));
        }
        let tree_keys = index_keys(&keys, recs.iter().map(|(id, a)| (*id, a.as_slice())), &patterns);
        let mut st = Mem::default();
        let root = build(&mut st, &search_secret(&read_key), tree_keys).unwrap().unwrap();

        let find = |key: &str, value: Value| -> Vec<RecordId> {
            let t = keys.token(key, &value);
            let mut ids: Vec<RecordId> = lookup(&st, &root, &t).unwrap().iter().map(|e| keys.open_entry(&t, e)).collect();
            ids.sort();
            ids
        };
        let album = find("album", s("Prangli 2026"));
        assert_eq!(album.len(), 20);
        assert!(album.iter().all(|id| u32::from_be_bytes(id[..4].try_into().unwrap()) % 100 == 7));
        assert_eq!(find("type", s("image")).len(), 1000);
        assert_eq!(find("tags:urgent", Value::Bool(true)).len(), 1);
        assert!(find("title", s("t5")).is_empty(), "undeclared keys aren't indexed");
        assert!(find("album", s("Prangli")).is_empty(), "exact match only");
    }
}
