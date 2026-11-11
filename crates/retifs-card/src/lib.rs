//! A node's RNS identity on an OpenPGP card, such as a YubiKey 5 (firmware
//! 5.2.3 or later): the signature key is Ed25519, the decryption key X25519
//! (cv25519), both made on the card, so the secret never leaves it
//! ([recon](../../../docs/recon/yubikey.md)). The card does the two things an
//! RNS identity does with its secret: sign (PSO:COMPUTE DIGITAL SIGNATURE,
//! pure Ed25519 over the message) and agree on a key (PSO:DECIPHER, X25519
//! with the other side's public key). Everything else (HKDF, Token, hashes)
//! stays RNS's own, in software.
//!
//! Talks to the card over PC/SC (Windows' WinSCard, pcsc-lite on Linux).

use std::fmt;

use pcsc::{Context, Protocols, Scope, ShareMode};
use sha2::{Digest, Sha256};

/// The OpenPGP application's AID (prefix; the rest names the card).
const OPENPGP_AID: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardError {
    /// No reader has a card with the OpenPGP application.
    NoCard,
    /// The PIN was refused; this many tries are left.
    WrongPin(u8),
    /// The PIN is needed first ([`Card::verify_pin`]).
    PinNeeded,
    /// A key slot holds no key, or not one of the right kind.
    NoKey(&'static str),
    /// The card answered with this status word.
    Status(u16),
    PcSc(String),
    Malformed(&'static str),
}

impl fmt::Display for CardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CardError::NoCard => write!(f, "no OpenPGP card (YubiKey) found"),
            CardError::WrongPin(left) => write!(f, "wrong PIN ({left} tries left)"),
            CardError::PinNeeded => write!(f, "the card's PIN is needed"),
            CardError::NoKey(slot) => write!(f, "the card's {slot} key isn't an Ed25519/X25519 key"),
            CardError::Status(sw) => write!(f, "the card answered {sw:04X}"),
            CardError::PcSc(e) => write!(f, "smart card: {e}"),
            CardError::Malformed(what) => write!(f, "the card's answer is malformed: {what}"),
        }
    }
}

impl std::error::Error for CardError {}

impl From<pcsc::Error> for CardError {
    fn from(e: pcsc::Error) -> Self {
        CardError::PcSc(e.to_string())
    }
}

/// Which PIN a verification is for: signing (PW1 mode 81) or the other
/// operations, key agreement among them (PW1 mode 82).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinUse {
    Sign,
    Other,
}

/// An OpenPGP card holding an RNS identity.
pub struct Card {
    card: pcsc::Card,
    reader: String,
}

/// The identity's public part as RNS lays it out: X25519 public ‖ Ed25519 public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentity {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}

impl PublicIdentity {
    /// The 64 bytes RNS calls the identity's public key.
    pub fn bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519);
        out[32..].copy_from_slice(&self.ed25519);
        out
    }

    /// The RNS identity hash: the first 16 bytes of SHA-256 over the public key.
    pub fn hash(&self) -> [u8; 16] {
        Sha256::digest(self.bytes())[..16].try_into().expect("16 bytes")
    }

    /// An RNS destination of this identity: `full_name` like `retifs.node`.
    pub fn destination(&self, full_name: &str) -> [u8; 16] {
        let name_hash = &Sha256::digest(full_name.as_bytes())[..10];
        let mut h = Sha256::new();
        h.update(name_hash);
        h.update(self.hash());
        h.finalize()[..16].try_into().expect("16 bytes")
    }
}

impl Card {
    /// The first reader with an OpenPGP card in it.
    pub fn open() -> Result<Card, CardError> {
        let ctx = Context::establish(Scope::User)?;
        let len = ctx.list_readers_len()?;
        let mut buf = vec![0u8; len];
        let readers: Vec<std::ffi::CString> = ctx.list_readers(&mut buf)?.map(|r| r.to_owned()).collect();
        for reader in readers {
            let Ok(card) = ctx.connect(&reader, ShareMode::Shared, Protocols::ANY) else { continue };
            let mut c = Card { card, reader: reader.to_string_lossy().into_owned() };
            if c.select().is_ok() {
                return Ok(c);
            }
        }
        Err(CardError::NoCard)
    }

    /// The reader the card is in.
    pub fn reader(&self) -> &str {
        &self.reader
    }

    fn select(&mut self) -> Result<(), CardError> {
        self.apdu(0x00, 0xA4, 0x04, 0x00, &OPENPGP_AID, false).map(|_| ())
    }

    /// Sends one command (extended length when the data needs it), following
    /// "more data" answers; Ok with the answer's data on 9000.
    fn apdu(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: bool) -> Result<Vec<u8>, CardError> {
        let mut cmd = vec![cla, ins, p1, p2];
        let extended = data.len() > 255;
        if !data.is_empty() {
            if extended {
                cmd.extend_from_slice(&[0x00, (data.len() >> 8) as u8, data.len() as u8]);
            } else {
                cmd.push(data.len() as u8);
            }
            cmd.extend_from_slice(data);
        }
        if le {
            if extended {
                cmd.extend_from_slice(&[0x00, 0x00]);
            } else if data.is_empty() {
                cmd.push(0x00);
            } else {
                cmd.push(0x00);
            }
        }
        let mut out = Vec::new();
        let mut buf = vec![0u8; 65_538];
        let mut answer = self.card.transmit(&cmd, &mut buf)?.to_vec();
        loop {
            if answer.len() < 2 {
                return Err(CardError::Malformed("no status word"));
            }
            let (body, sw) = answer.split_at(answer.len() - 2);
            out.extend_from_slice(body);
            let sw = u16::from_be_bytes([sw[0], sw[1]]);
            match sw {
                0x9000 => return Ok(out),
                // More to come: GET RESPONSE.
                sw if sw >> 8 == 0x61 => {
                    answer = self.card.transmit(&[0x00, 0xC0, 0x00, 0x00, sw as u8], &mut buf)?.to_vec();
                }
                0x6982 => return Err(CardError::PinNeeded),
                sw if sw >> 4 == 0x63C => return Err(CardError::WrongPin((sw & 0xF) as u8)),
                sw => return Err(CardError::Status(sw)),
            }
        }
    }

    /// The public key in a slot (`0xB6` signature, `0xB8` decryption), read
    /// without changing it (GENERATE ASYMMETRIC KEY PAIR, read mode).
    fn public_key(&mut self, crt: u8, slot: &'static str) -> Result<[u8; 32], CardError> {
        let r = self.apdu(0x00, 0x47, 0x81, 0x00, &[crt, 0x00], true)?;
        // 7F49 len { 86 len point }
        let at = r.windows(2).position(|w| w == [0x86, 0x20]).ok_or(CardError::NoKey(slot))?;
        r.get(at + 2..at + 34).and_then(|k| k.try_into().ok()).ok_or(CardError::NoKey(slot))
    }

    /// The identity's public part: the decryption key (X25519) and the signature key (Ed25519).
    pub fn public_identity(&mut self) -> Result<PublicIdentity, CardError> {
        Ok(PublicIdentity { x25519: self.public_key(0xB8, "decryption")?, ed25519: self.public_key(0xB6, "signature")? })
    }

    /// Verifies the user PIN for signing or for the other operations.
    pub fn verify_pin(&mut self, pin: &str, usage: PinUse) -> Result<(), CardError> {
        let p2 = match usage {
            PinUse::Sign => 0x81,
            PinUse::Other => 0x82,
        };
        self.apdu(0x00, 0x20, 0x00, p2, pin.as_bytes(), false).map(|_| ())
    }

    /// Signs `message` with the card's Ed25519 key (pure Ed25519: the card
    /// hashes the message itself, as RNS signs).
    pub fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], CardError> {
        let sig = self.apdu(0x00, 0x2A, 0x9E, 0x9A, message, true)?;
        sig.try_into().map_err(|_| CardError::Malformed("an Ed25519 signature is 64 bytes"))
    }

    /// X25519 with the card's decryption key and `peer` (the other side's
    /// public key): the shared secret RNS feeds into its HKDF.
    pub fn agree(&mut self, peer: &[u8; 32]) -> Result<[u8; 32], CardError> {
        // A6 { 7F49 { 86 20 <point> } }
        let mut data = vec![0xA6, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x20];
        data.extend_from_slice(peer);
        let shared = self.apdu(0x00, 0x2A, 0x80, 0x86, &data, true)?;
        shared.try_into().map_err(|_| CardError::Malformed("an X25519 secret is 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_hash_and_destination_as_rns() {
        // The card made in the recon (docs/recon/yubikey.md): Python RNS gave
        // identity 12e9125e… and retifs.node 258d3c39… for these public keys.
        let id = PublicIdentity {
            x25519: hex::decode("4f30f06604f14fd9059eebce00f645063a72ca45bf94ab18d54aa10be8f9d852").unwrap().try_into().unwrap(),
            ed25519: hex::decode("bb3e8a8c6af96b39a9a94894604fd0a5cc6bbe7a2a404cad8a92e37190970f63").unwrap().try_into().unwrap(),
        };
        assert_eq!(hex::encode(id.hash()), "12e9125e209f8c0f67acc1fe70b9e4f1");
        assert_eq!(hex::encode(id.destination("retifs.node")), "258d3c394d3376c4662048ca83bd2f2d");
    }
}
