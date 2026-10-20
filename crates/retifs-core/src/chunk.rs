//! Per-chunk encryption (ADR-0008, construction v1, draft).
//!
//! ```text
//! frame    = encoding (u8) ‖ u32_be(len) ‖ payload ‖ zero fill to (class − 64)
//!            encoding 0 = raw, 1 = zstd (payload is the compressed data)
//! seed     = HMAC-SHA256(convergence_secret, frame)
//! okm      = HKDF-SHA256(ikm = seed, salt = "retifs/v1/chunk", info = "", L = 80)
//! chunk    = iv ‖ AES-256-CBC(enc_key, iv, PKCS7(frame)) ‖ HMAC-SHA256(sign_key, iv ‖ ct)
//! ```
//! The result is an RNS Token with key `okm[0..64]` and a derived IV, and its
//! length is exactly the size class.
//!
//! Compression happens before encryption (ciphertext doesn't compress, ADR-0013)
//! and is opt-in: a compressed chunk may land in a smaller class, which reveals
//! that the content was compressible.

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

/// Ciphertext sizes: 512 B … 256 KiB. 512 B carries a commit or a small
/// operations file in one chunk, halving small writes on slow links (decided 2026-10-20).
pub const CLASSES: [usize; 10] = [1 << 9, 1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14, 1 << 15, 1 << 16, 1 << 17, 1 << 18];
/// IV (16) + one full PKCS7 block (16) + HMAC (32).
pub const OVERHEAD: usize = 64;
/// Frame header: encoding byte + u32 payload length.
pub const FRAME_HEADER: usize = 5;
/// Largest payload that fits in one chunk.
pub const MAX_DATA: usize = CLASSES[CLASSES.len() - 1] - OVERHEAD - FRAME_HEADER;
/// zstd level used by writers (fixed, so equal input gives equal output with one zstd version).
pub const ZSTD_LEVEL: i32 = 3;

const ENC_RAW: u8 = 0;
const ENC_ZSTD: u8 = 1;

/// Whether a writer may compress a chunk's data before encrypting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// Never compress (default: the size class then reveals nothing about compressibility).
    #[default]
    Off,
    /// Compress with zstd when it saves at least 1/8 of the size.
    Zstd,
}

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
    BadCompression,
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
            ChunkError::BadCompression => "chunk payload does not decompress",
        })
    }
}

impl std::error::Error for ChunkError {}

/// Smallest size class whose ciphertext can hold a payload of `payload_len` bytes.
pub fn class_for(payload_len: usize) -> Option<usize> {
    CLASSES.iter().copied().find(|&c| payload_len + FRAME_HEADER <= c - OVERHEAD)
}

/// Seals `data` without compression.
pub fn seal(secret: &ConvergenceSecret, data: &[u8]) -> Result<Sealed, ChunkError> {
    seal_with(secret, data, Compression::Off)
}

pub fn seal_with(secret: &ConvergenceSecret, data: &[u8], compression: Compression) -> Result<Sealed, ChunkError> {
    if data.len() > MAX_DATA {
        return Err(ChunkError::TooLarge);
    }
    let compressed = match compression {
        Compression::Off => None,
        Compression::Zstd => zstd::bulk::compress(data, ZSTD_LEVEL)
            .ok()
            .filter(|z| z.len() + z.len() / 7 < data.len()), // saves at least 1/8
    };
    let (encoding, payload) = match &compressed {
        Some(z) => (ENC_ZSTD, z.as_slice()),
        None => (ENC_RAW, data),
    };
    let class = class_for(payload.len()).ok_or(ChunkError::TooLarge)?;
    let frame = frame(encoding, payload, class);
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

fn frame(encoding: u8, payload: &[u8], class: usize) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("checked against MAX_DATA");
    let mut f = Vec::with_capacity(class - OVERHEAD);
    f.push(encoding);
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(payload);
    f.resize(class - OVERHEAD, 0);
    f
}

fn unframe(frame: &[u8]) -> Result<Vec<u8>, ChunkError> {
    let (header, rest) = frame.split_first_chunk::<FRAME_HEADER>().ok_or(ChunkError::BadFrame)?;
    let [encoding, l0, l1, l2, l3] = *header;
    let len = u32::from_be_bytes([l0, l1, l2, l3]) as usize;
    if len > rest.len() || rest[len..].iter().any(|&b| b != 0) {
        return Err(ChunkError::BadFrame);
    }
    let payload = &rest[..len];
    match encoding {
        ENC_RAW => Ok(payload.to_vec()),
        ENC_ZSTD => zstd::bulk::decompress(payload, MAX_DATA).map_err(|_| ChunkError::BadCompression),
        _ => Err(ChunkError::BadFrame),
    }
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
