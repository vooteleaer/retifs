//! Signed channels (ADR-0015, irreversible decisions 5 and 8; draft v1): one
//! writer's append-only chain of versions, which followers track.
//!
//! ```text
//! address = "retifs-ch:1:" ‖ hex(writer Ed25519 public key) ‖ ":" ‖ hex(read key)
//! ns_id   = SHA-256("retifs/v1/ns" ‖ writer)[0..16]
//!
//! commit  = body ‖ sig(64)                      stored as an ordinary sealed chunk,
//! body    = 0x01 ‖ ns_id (16) ‖ writer (32)      convergence secret
//!           ‖ seq (u64 BE) ‖ time (u64 BE, unix ms)   for_record(read key, "retifs/v1/commits")
//!           ‖ has_prev (u8) [‖ prev cid (33) ‖ prev seed (32)]
//!           ‖ root cid (33) ‖ root seed (32) ‖ root size (u64 BE)
//! sig     = Ed25519(writer, "retifs/v1/commit" ‖ body)
//!
//! head    = 0x01 ‖ ns_id (16) ‖ writer (32) ‖ seq (u64 BE) ‖ time (u64 BE, unix s)
//!           ‖ commit cid (33) ‖ Token(head key, commit seed) (96) ‖ sig (64)        258 B
//! sig     = Ed25519(writer, "retifs/v1/head" ‖ all fields before it)
//! head key = HKDF-SHA256(ikm = read key, salt = "retifs/v1/head-seed", info = "", L = 64)
//! ```
//! - **Holders stay blind:** commits are chunks like any other; a head shows
//!   only the namespace, the writer key, the sequence number and a commit CID.
//! - **Rollback protection (decision 5):** anyone can verify a head and keep
//!   the highest `seq` per writer, without the read key. `time` lets readers
//!   refuse stale heads (freeze protection) where a channel promises updates.
//! - **Multi-writer later (ADR-0006):** every commit and head names its writer
//!   and has its own `seq`; a namespace with several writers merges their
//!   chains. Here one writer = one channel, and `ns_id` derives from its key.

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    chunk::{seal, Sealed, Seed},
    cid::{Cid, CID_LEN},
    manifest::FileRef,
    secret::ConvergenceSecret,
};

pub const VERSION: u8 = 1;
pub const NS_ID_LEN: usize = 16;
pub const HEAD_LEN: usize = 1 + 16 + 32 + 8 + 8 + CID_LEN + SEALED_SEED_LEN + 64;
const SEALED_SEED_LEN: usize = 16 + 48 + 32;
const NS_LABEL: &[u8] = b"retifs/v1/ns";
const COMMITS_RECORD: &[u8] = b"retifs/v1/commits";
const COMMIT_LABEL: &[u8] = b"retifs/v1/commit";
const HEAD_LABEL: &[u8] = b"retifs/v1/head";
const HEAD_SEED_SALT: &[u8] = b"retifs/v1/head-seed";
const ADDR_PREFIX: &str = "retifs-ch:1:";

pub type NsId = [u8; NS_ID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    Malformed(&'static str),
    BadSignature,
    /// Signed by another writer, or for another namespace, than expected.
    WrongChannel,
    /// The head's commit seed doesn't decrypt with this read key.
    WrongKey,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Malformed(m) => write!(f, "malformed: {m}"),
            ChannelError::BadSignature => f.write_str("bad signature"),
            ChannelError::WrongChannel => f.write_str("not from this channel"),
            ChannelError::WrongKey => f.write_str("wrong read key"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// Names a read key without revealing it: SHA-256("retifs/v1/key-id" ‖ key)[0..16].
/// Members ask for "your latest head under this key" to cross a key rotation (ADR-0017).
pub fn key_id(read_key: &[u8; 32]) -> [u8; 16] {
    Sha256::digest([b"retifs/v1/key-id".as_slice(), read_key].concat())[..16].try_into().unwrap()
}

pub fn ns_id(writer: &[u8; 32]) -> NsId {
    Sha256::digest([NS_LABEL, writer].concat())[..NS_ID_LEN].try_into().unwrap()
}

/// What followers hold: who may write, and the key to read.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelAddr {
    pub writer: [u8; 32],
    pub read_key: [u8; 32],
}

impl std::fmt::Debug for ChannelAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelAddr({}…)", hex::encode(&self.writer[..4]))
    }
}

impl ChannelAddr {
    pub fn ns_id(&self) -> NsId {
        ns_id(&self.writer)
    }

    fn commit_secret(&self) -> ConvergenceSecret {
        ConvergenceSecret::for_record(&self.read_key, COMMITS_RECORD)
    }

    fn head_key(&self) -> [u8; 64] {
        let mut k = [0u8; 64];
        Hkdf::<Sha256>::new(Some(HEAD_SEED_SALT), &self.read_key)
            .expand(&[], &mut k)
            .expect("64 bytes is a valid HKDF output length");
        k
    }
}

impl std::fmt::Display for ChannelAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{ADDR_PREFIX}{}:{}", hex::encode(self.writer), hex::encode(self.read_key))
    }
}

impl std::str::FromStr for ChannelAddr {
    type Err = ChannelError;
    fn from_str(s: &str) -> Result<Self, ChannelError> {
        let rest = s.trim().strip_prefix(ADDR_PREFIX).ok_or(ChannelError::Malformed("not a retifs-ch:1 address"))?;
        let (w, k) = rest.split_once(':').ok_or(ChannelError::Malformed("address"))?;
        let parse = |h: &str| -> Result<[u8; 32], ChannelError> {
            hex::decode(h).ok().and_then(|b| b.try_into().ok()).ok_or(ChannelError::Malformed("address key"))
        };
        Ok(ChannelAddr { writer: parse(w)?, read_key: parse(k)? })
    }
}

/// The writer's side: signing key and read key.
pub struct ChannelKey {
    signing: SigningKey,
    pub read_key: [u8; 32],
    /// The namespace written to, when it isn't this writer's own (a member of
    /// another's namespace, ADR-0017).
    ns: Option<NsId>,
}

impl ChannelKey {
    pub fn from_secrets(signing_seed: [u8; 32], read_key: [u8; 32]) -> Self {
        ChannelKey { signing: SigningKey::from_bytes(&signing_seed), read_key, ns: None }
    }

    /// A member's key: its own signing key, writing to namespace `ns_id`.
    pub fn member(signing_seed: [u8; 32], read_key: [u8; 32], ns_id: NsId) -> Self {
        ChannelKey { signing: SigningKey::from_bytes(&signing_seed), read_key, ns: Some(ns_id) }
    }

    pub fn ns_id(&self) -> NsId {
        self.ns.unwrap_or_else(|| ns_id(&self.signing.verifying_key().to_bytes()))
    }

    pub fn writer(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn signing_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn addr(&self) -> ChannelAddr {
        ChannelAddr { writer: self.signing.verifying_key().to_bytes(), read_key: self.read_key }
    }
}

/// One version of the channel: which tree, after which commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub ns_id: NsId,
    pub writer: [u8; 32],
    pub seq: u64,
    pub time_ms: u64,
    pub prev: Option<(Cid, Seed)>,
    pub root: FileRef,
    pub signature: [u8; 64],
}

impl Commit {
    /// Signs commit `seq` and seals it as a chunk (store it, then sign a head for it).
    pub fn create(key: &ChannelKey, seq: u64, time_ms: u64, prev: Option<(Cid, Seed)>, root: FileRef) -> (Commit, Sealed) {
        let addr = key.addr();
        let mut c = Commit { ns_id: key.ns_id(), writer: key.writer(), seq, time_ms, prev, root, signature: [0; 64] };
        c.signature = key.signing.sign(&[COMMIT_LABEL, &c.body()].concat()).to_bytes();
        let sealed = seal(&addr.commit_secret(), &c.encode()).expect("a commit fits a chunk");
        (c, sealed)
    }

    fn body(&self) -> Vec<u8> {
        let mut b = vec![VERSION];
        b.extend_from_slice(&self.ns_id);
        b.extend_from_slice(&self.writer);
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.time_ms.to_be_bytes());
        match &self.prev {
            Some((cid, seed)) => {
                b.push(1);
                b.extend_from_slice(cid.as_bytes());
                b.extend_from_slice(&seed.0);
            }
            None => b.push(0),
        }
        b.extend_from_slice(self.root.root.as_bytes());
        b.extend_from_slice(&self.root.seed.0);
        b.extend_from_slice(&self.root.size.to_be_bytes());
        b
    }

    pub fn encode(&self) -> Vec<u8> {
        [self.body().as_slice(), &self.signature].concat()
    }

    /// Parses a commit's plaintext and checks it belongs to `addr`'s namespace
    /// and is signed by the writer it names. Whether that writer may write is
    /// the merge's question (ADR-0017); a single-writer follower also checks
    /// `writer == addr.writer`.
    pub fn decode(bytes: &[u8], addr: &ChannelAddr) -> Result<Commit, ChannelError> {
        let mut r = Reader(bytes);
        if r.take(1)? != [VERSION] {
            return Err(ChannelError::Malformed("commit version"));
        }
        let ns_id: NsId = r.array()?;
        let writer: [u8; 32] = r.array()?;
        let seq = u64::from_be_bytes(r.array()?);
        let time_ms = u64::from_be_bytes(r.array()?);
        let prev = match r.take(1)?[0] {
            0 => None,
            1 => Some((r.cid()?, Seed(r.array()?))),
            _ => return Err(ChannelError::Malformed("prev flag")),
        };
        let root = FileRef { root: r.cid()?, seed: Seed(r.array()?), size: u64::from_be_bytes(r.array()?) };
        let signature: [u8; 64] = r.array()?;
        if !r.0.is_empty() {
            return Err(ChannelError::Malformed("trailing bytes"));
        }
        let c = Commit { ns_id, writer, seq, time_ms, prev, root, signature };
        if c.ns_id != addr.ns_id() {
            return Err(ChannelError::WrongChannel);
        }
        verify(&c.writer, &[COMMIT_LABEL, &c.body()].concat(), &c.signature)?;
        Ok(c)
    }
}

/// The signed pointer to a channel's latest commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub ns_id: NsId,
    pub writer: [u8; 32],
    pub seq: u64,
    pub time_s: u64,
    pub commit: Cid,
    sealed_seed: [u8; SEALED_SEED_LEN],
    pub signature: [u8; 64],
}

impl Head {
    /// `iv` must be fresh randomness (it only hides the seed; tests pass a fixed one).
    pub fn sign(key: &ChannelKey, seq: u64, time_s: u64, commit: Cid, seed: &Seed, iv: [u8; 16]) -> Head {
        let addr = key.addr();
        let mut h = Head {
            ns_id: key.ns_id(),
            writer: key.writer(),
            seq,
            time_s,
            commit,
            sealed_seed: token_encrypt(&addr.head_key(), &iv, &seed.0),
            signature: [0; 64],
        };
        h.signature = key.signing.sign(&[HEAD_LABEL, &h.encode()[..HEAD_LEN - 64]].concat()).to_bytes();
        h
    }

    pub fn encode(&self) -> [u8; HEAD_LEN] {
        let mut b = Vec::with_capacity(HEAD_LEN);
        b.push(VERSION);
        b.extend_from_slice(&self.ns_id);
        b.extend_from_slice(&self.writer);
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.time_s.to_be_bytes());
        b.extend_from_slice(self.commit.as_bytes());
        b.extend_from_slice(&self.sealed_seed);
        b.extend_from_slice(&self.signature);
        b.try_into().unwrap()
    }

    /// Parses and verifies a head's signature by the writer it names. Anyone can
    /// do this, without the read key. Whether the writer may write to `ns_id`
    /// is decided by the namespace's grants (ADR-0017).
    pub fn decode(bytes: &[u8]) -> Result<Head, ChannelError> {
        if bytes.len() != HEAD_LEN {
            return Err(ChannelError::Malformed("head length"));
        }
        let mut r = Reader(bytes);
        if r.take(1)? != [VERSION] {
            return Err(ChannelError::Malformed("head version"));
        }
        let h = Head {
            ns_id: r.array()?,
            writer: r.array()?,
            seq: u64::from_be_bytes(r.array()?),
            time_s: u64::from_be_bytes(r.array()?),
            commit: r.cid()?,
            sealed_seed: r.array()?,
            signature: r.array()?,
        };
        verify(&h.writer, &[HEAD_LABEL, &bytes[..HEAD_LEN - 64]].concat(), &h.signature)?;
        Ok(h)
    }

    /// The commit's seed, for followers holding the read key.
    pub fn commit_seed(&self, addr: &ChannelAddr) -> Result<Seed, ChannelError> {
        if self.ns_id != addr.ns_id() {
            return Err(ChannelError::WrongChannel);
        }
        let pt = token_decrypt(&addr.head_key(), &self.sealed_seed).ok_or(ChannelError::WrongKey)?;
        Ok(Seed(pt.try_into().map_err(|_| ChannelError::WrongKey)?))
    }
}

/// RNS Token: iv ‖ AES-256-CBC(PKCS7) ‖ HMAC-SHA256(iv ‖ ciphertext); key = signing (32) ‖ encryption (32).
fn token_encrypt(key: &[u8; 64], iv: &[u8; 16], pt: &[u8; 32]) -> [u8; SEALED_SEED_LEN] {
    let ct = cbc::Encryptor::<Aes256>::new(key[32..].into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(pt);
    let signed = [iv.as_slice(), &ct].concat();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..32]).expect("HMAC takes any key length");
    mac.update(&signed);
    [signed.as_slice(), &mac.finalize().into_bytes()].concat().try_into().unwrap()
}

/// RNS Token over any plaintext (the index descriptor's state reference, ADR-0019).
pub(crate) fn token_seal(key: &[u8; 64], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let ct = cbc::Encryptor::<Aes256>::new(key[32..].into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(pt);
    let signed = [iv.as_slice(), &ct].concat();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..32]).expect("HMAC takes any key length");
    mac.update(&signed);
    [signed.as_slice(), &mac.finalize().into_bytes()].concat()
}

pub(crate) fn token_decrypt(key: &[u8; 64], token: &[u8]) -> Option<Vec<u8>> {
    let (signed, tag) = token.split_at(token.len().checked_sub(32)?);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[..32]).expect("HMAC takes any key length");
    mac.update(signed);
    mac.verify_slice(tag).ok()?;
    let (iv, ct) = signed.split_at(16);
    cbc::Decryptor::<Aes256>::new(key[32..].into(), iv.into()).decrypt_padded_vec_mut::<Pkcs7>(ct).ok()
}

fn verify(signer: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<(), ChannelError> {
    let key = VerifyingKey::from_bytes(signer).map_err(|_| ChannelError::BadSignature)?;
    key.verify(message, &Signature::from_bytes(sig)).map_err(|_| ChannelError::BadSignature)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ChannelError> {
        if self.0.len() < n {
            return Err(ChannelError::Malformed("truncated"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ChannelError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn cid(&mut self) -> Result<Cid, ChannelError> {
        Cid::from_bytes(self.array()?).ok_or(ChannelError::Malformed("CID version"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open;

    fn key(n: u8) -> ChannelKey {
        ChannelKey::from_secrets([n; 32], [n + 100; 32])
    }

    #[test]
    fn commit_chain_and_head_roundtrip() {
        let k = key(1);
        let addr: ChannelAddr = k.addr().to_string().parse().unwrap();
        assert_eq!(addr, k.addr());
        let root = FileRef { root: Cid::of(b"tree"), seed: Seed([3; 32]), size: 42 };
        let (c1, s1) = Commit::create(&k, 1, 1000, None, root);
        let (c2, s2) = Commit::create(&k, 2, 2000, Some((s1.cid, s1.seed)), root);

        let head = Head::sign(&k, 2, 2, s2.cid, &s2.seed, [9; 16]);
        let wire = head.encode();
        assert_eq!(wire.len(), 258, "a head fits one packet");
        let back = Head::decode(&wire).unwrap();
        assert_eq!(back, head);
        let seed = back.commit_seed(&addr).unwrap();
        let pt = open(&back.commit, &seed, &s2.ciphertext).unwrap();
        let got = Commit::decode(&pt, &addr).unwrap();
        assert_eq!(got, c2);
        let (pcid, pseed) = got.prev.unwrap();
        assert_eq!(Commit::decode(&open(&pcid, &pseed, &s1.ciphertext).unwrap(), &addr).unwrap(), c1);
    }

    #[test]
    fn members_write_under_the_namespace_and_sign_as_themselves() {
        let owner = key(1);
        let addr = owner.addr();
        let member = ChannelKey::member([9; 32], addr.read_key, addr.ns_id());
        let root = FileRef { root: Cid::of(b"ops"), seed: Seed([4; 32]), size: 10 };
        let (c, s) = Commit::create(&member, 1, 1000, None, root);
        assert_eq!((c.ns_id, c.writer), (addr.ns_id(), member.writer()));
        let head = Head::decode(&Head::sign(&member, 1, 1, s.cid, &s.seed, [9; 16]).encode()).unwrap();
        assert_eq!(head.writer, member.writer());
        let seed = head.commit_seed(&addr).unwrap();
        assert_eq!(Commit::decode(&open(&s.cid, &seed, &s.ciphertext).unwrap(), &addr).unwrap(), c);
    }

    #[test]
    fn heads_and_commits_are_bound_to_their_writer() {
        let (k, other) = (key(1), key(2));
        let root = FileRef { root: Cid::of(b"tree"), seed: Seed([3; 32]), size: 42 };
        let (_, s) = Commit::create(&k, 1, 1000, None, root);
        let mut wire = Head::sign(&k, 1, 1, s.cid, &s.seed, [9; 16]).encode();
        wire[60] ^= 1; // the seq
        assert_eq!(Head::decode(&wire), Err(ChannelError::BadSignature));
        let head = Head::decode(&Head::sign(&k, 1, 1, s.cid, &s.seed, [9; 16]).encode()).unwrap();
        assert_eq!(head.commit_seed(&other.addr()), Err(ChannelError::WrongChannel));
        let wrong_key = ChannelAddr { writer: k.addr().writer, read_key: [0; 32] };
        assert_eq!(head.commit_seed(&wrong_key), Err(ChannelError::WrongKey));
        let pt = open(&s.cid, &s.seed, &s.ciphertext).unwrap();
        assert_eq!(Commit::decode(&pt, &other.addr()), Err(ChannelError::WrongChannel));
    }
}
