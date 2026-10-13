//! Per-chunk encryption (ADR-0008, construction v1).
//!
//! ```text
//! frame    = u32_be(len) ‖ data ‖ zero fill to (class − 64)
//! seed     = HMAC-SHA256(convergence_secret, frame)
//! okm      = HKDF-SHA256(ikm = seed, salt = "retifs/v1/chunk", info = "", L = 80)
//! chunk    = iv ‖ AES-256-CBC(enc_key, iv, PKCS7(frame)) ‖ HMAC-SHA256(sign_key, iv ‖ ct)
//! ```
//! The result is an RNS Token with key `okm[0..64]` and a derived IV, and its
//! length is exactly the size class.

use std::fmt;

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{cid::Cid, secret::ConvergenceSecret};

type HmacSha256 = Hmac<Sha256>;
type Enc = cbc::Encryptor<Aes256>;
type Dec = cbc::Decryptor<Aes256>;

const CHUNK_SALT: &[u8] = b"retifs/v1/chunk";

/// Ciphertext sizes: 1 KiB … 256 KiB.
pub const CLASSES: [usize; 9] = [1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14, 1 << 15, 1 << 16, 1 << 17, 1 << 18];
/// IV (16) + one full PKCS7 block (16) + HMAC (32).
pub const OVERHEAD: usize = 64;
const LEN_PREFIX: usize = 4;
/// Largest payload that fits in one chunk.
pub const MAX_DATA: usize = CLASSES[CLASSES.len() - 1] - OVERHEAD - LEN_PREFIX;

/// The per-chunk read secret. Stored in the manifest next to the CID.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Seed(pub [u8; 32]);

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(…)")
    }
}

#[derive(Debug, Clone)]
pub struct Sealed {
    pub cid: Cid,
    pub seed: Seed,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkError {
    TooLarge,
    NotAClassSize,
    CidMismatch,
    BadMac,
    BadPadding,
    BadFrame,
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChunkError::TooLarge => "data exceeds the largest chunk class",
            ChunkError::NotAClassSize => "ciphertext length is not a size class",
            ChunkError::CidMismatch => "ciphertext does not match its CID",
            ChunkError::BadMac => "chunk HMAC is invalid",
            ChunkError::BadPadding => "chunk padding is invalid",
            ChunkError::BadFrame => "chunk frame is malformed",
        })
    }
}

impl std::error::Error for ChunkError {}

/// Smallest size class whose ciphertext can hold `data_len` bytes.
pub fn class_for(data_len: usize) -> Option<usize> {
    CLASSES.iter().copied().find(|&c| data_len + LEN_PREFIX <= c - OVERHEAD)
}

pub fn seal(secret: &ConvergenceSecret, data: &[u8]) -> Result<Sealed, ChunkError> {
    let class = class_for(data.len()).ok_or(ChunkError::TooLarge)?;
    let frame = frame(data, class);
    let seed = Seed(hmac(secret.as_bytes(), &frame));
    let keys = Keys::derive(&seed);

    let ct = Enc::new(&keys.enc.into(), &keys.iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&frame);
    let mut out = Vec::with_capacity(class);
    out.extend_from_slice(&keys.iv);
    out.extend_from_slice(&ct);
    let tag = hmac(&keys.sign, &out);
    out.extend_from_slice(&tag);
    debug_assert_eq!(out.len(), class);

    Ok(Sealed { cid: Cid::of(&out), seed, ciphertext: out })
}

pub fn open(cid: &Cid, seed: &Seed, chunk: &[u8]) -> Result<Vec<u8>, ChunkError> {
    if !CLASSES.contains(&chunk.len()) {
        return Err(ChunkError::NotAClassSize);
    }
    if !cid.verify(chunk) {
        return Err(ChunkError::CidMismatch);
    }
    let keys = Keys::derive(seed);
    let (signed, tag) = chunk.split_at(chunk.len() - 32);
    let mut mac = HmacSha256::new_from_slice(&keys.sign).expect("HMAC takes any key length");
    mac.update(signed);
    mac.verify_slice(tag).map_err(|_| ChunkError::BadMac)?;

    let (iv, ct) = signed.split_at(16);
    let iv: [u8; 16] = iv.try_into().expect("16-byte IV");
    let frame = Dec::new(&keys.enc.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| ChunkError::BadPadding)?;
    unframe(&frame)
}

fn frame(data: &[u8], class: usize) -> Vec<u8> {
    let len = u32::try_from(data.len()).expect("checked against MAX_DATA");
    let mut f = Vec::with_capacity(class - OVERHEAD);
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(data);
    f.resize(class - OVERHEAD, 0);
    f
}

fn unframe(frame: &[u8]) -> Result<Vec<u8>, ChunkError> {
    let (len, rest) = frame.split_first_chunk::<LEN_PREFIX>().ok_or(ChunkError::BadFrame)?;
    let len = u32::from_be_bytes(*len) as usize;
    if len > rest.len() || rest[len..].iter().any(|&b| b != 0) {
        return Err(ChunkError::BadFrame);
    }
    Ok(rest[..len].to_vec())
}

struct Keys {
    sign: [u8; 32],
    enc: [u8; 32],
    iv: [u8; 16],
}

impl Keys {
    fn derive(seed: &Seed) -> Self {
        let mut okm = [0u8; 80];
        Hkdf::<Sha256>::new(Some(CHUNK_SALT), &seed.0)
            .expand(&[], &mut okm)
            .expect("80 bytes is a valid HKDF output length");
        Keys {
            sign: okm[0..32].try_into().unwrap(),
            enc: okm[32..64].try_into().unwrap(),
            iv: okm[64..80].try_into().unwrap(),
        }
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
