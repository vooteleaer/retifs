//! Invitations (ADR-0020): write access to a namespace in one step.
//!
//! An invitation is canonical msgpack, base32 in a `retifs:invite/…` link:
//!
//! ```text
//! { "expires": ms, "limits": { "keys"?: [str], "until"?: ms }, "node": bin 16,
//!   "ns": bin 64 (writer ‖ read key), "q"?: str, "rights": [str], "secret": bin 32 }
//! ```
//!
//! Its creator keeps `id = SHA-256("retifs/v1/invite" ‖ secret)` as pending.
//! The recipient joins (the address reads) and redeems over a Link to the
//! creator's node (`/retifs/invite`) with
//! `id ‖ writer key ‖ its node ‖ HMAC-SHA256(secret, link id ‖ writer key ‖ its node)`:
//! bound to that Link, naming the key to grant and the node to sync with.
//! The first good redemption spends it.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    channel::ChannelAddr,
    record::{canonical, write_array_len, write_bin, write_int, write_map_len, write_str, Reader, RecordError, Value},
};

const ID_LABEL: &[u8] = b"retifs/v1/invite";

/// The length of a redemption request.
pub const REDEEM_LEN: usize = 32 + 32 + 16 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub ns: ChannelAddr,
    /// The creator's node (its `retifs.node` address), to redeem with.
    pub node: [u8; 16],
    pub secret: [u8; 32],
    /// `grant` too, besides `write`.
    pub grant: bool,
    /// Limits of the grant (ADR-0017): attribute keys, and an end.
    pub keys: Vec<String>,
    pub until: Option<u64>,
    /// When the invitation can no longer be redeemed (ms since the epoch).
    pub expires: u64,
    /// What the recipient's app opens on.
    pub q: Option<String>,
}

/// The ID a creator keeps an invitation under.
pub fn id_of(secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest([ID_LABEL, secret.as_slice()].concat()).into()
}

fn mac(secret: &[u8; 32], link_id: &[u8], writer: &[u8; 32], node: &[u8; 16]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length");
    m.update(link_id);
    m.update(writer);
    m.update(node);
    m
}

/// A redemption request over the Link `link_id`: `id ‖ writer ‖ node ‖ proof`.
pub fn redeem_request(secret: &[u8; 32], link_id: &[u8], writer: &[u8; 32], node: &[u8; 16]) -> Vec<u8> {
    let proof = mac(secret, link_id, writer, node).finalize().into_bytes();
    [id_of(secret).as_slice(), writer, node, &proof].concat()
}

/// A redemption request's parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redemption {
    pub id: [u8; 32],
    pub writer: [u8; 32],
    pub node: [u8; 16],
    pub proof: [u8; 32],
}

pub fn parse_redeem(body: &[u8]) -> Option<Redemption> {
    (body.len() == REDEEM_LEN).then(|| Redemption {
        id: body[..32].try_into().unwrap(),
        writer: body[32..64].try_into().unwrap(),
        node: body[64..80].try_into().unwrap(),
        proof: body[80..].try_into().unwrap(),
    })
}

/// Whether `proof` is good for this secret, Link, writer and node (in
/// constant time).
pub fn verify(secret: &[u8; 32], link_id: &[u8], writer: &[u8; 32], node: &[u8; 16], proof: &[u8; 32]) -> bool {
    mac(secret, link_id, writer, node).verify_slice(proof).is_ok()
}

impl Invitation {
    pub fn id(&self) -> [u8; 32] {
        id_of(&self.secret)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_map_len(&mut out, 6 + usize::from(self.q.is_some()));
        write_str(&mut out, "expires");
        write_int(&mut out, self.expires as i64);
        write_str(&mut out, "limits");
        write_map_len(&mut out, usize::from(!self.keys.is_empty()) + usize::from(self.until.is_some()));
        if !self.keys.is_empty() {
            write_str(&mut out, "keys");
            write_array_len(&mut out, self.keys.len());
            for k in &self.keys {
                write_str(&mut out, k);
            }
        }
        if let Some(u) = self.until {
            write_str(&mut out, "until");
            write_int(&mut out, u as i64);
        }
        write_str(&mut out, "node");
        write_bin(&mut out, &self.node);
        write_str(&mut out, "ns");
        write_bin(&mut out, &[self.ns.writer, self.ns.read_key].concat());
        if let Some(q) = &self.q {
            write_str(&mut out, "q");
            write_str(&mut out, q);
        }
        write_str(&mut out, "rights");
        let rights: &[&str] = if self.grant { &["grant", "write"] } else { &["write"] };
        write_array_len(&mut out, rights.len());
        for r in rights {
            write_str(&mut out, r);
        }
        write_str(&mut out, "secret");
        write_bin(&mut out, &self.secret);
        out
    }

    /// The inverse of [`Invitation::encode`]; anything not in its canonical
    /// form is refused.
    pub fn decode(bytes: &[u8]) -> Result<Invitation, RecordError> {
        let bad = RecordError::Malformed;
        let mut r = Reader(bytes);
        let n = r.map_len()?;
        let (mut expires, mut node, mut ns, mut secret, mut q) = (None, None, None, None, None);
        let (mut keys, mut until, mut grant) = (Vec::new(), None, false);
        let uint = |v: Value| match v {
            Value::Int(i) if i >= 0 => Ok(i as u64),
            _ => Err(bad("expected a time")),
        };
        for _ in 0..n {
            match r.str()?.as_str() {
                "expires" => expires = Some(uint(r.value(1)?)?),
                "limits" => {
                    for _ in 0..r.map_len()? {
                        match r.str()?.as_str() {
                            "keys" => {
                                for _ in 0..r.array_len()? {
                                    keys.push(r.str()?);
                                }
                            }
                            "until" => until = Some(uint(r.value(1)?)?),
                            _ => return Err(bad("unknown limit")),
                        }
                    }
                }
                "node" => node = Some(r.bin()?.try_into().map_err(|_| bad("node"))?),
                "ns" => {
                    let b: [u8; 64] = r.bin()?.try_into().map_err(|_| bad("ns"))?;
                    ns = Some(ChannelAddr { writer: b[..32].try_into().unwrap(), read_key: b[32..].try_into().unwrap() });
                }
                "q" => q = Some(r.str()?),
                "rights" => {
                    for _ in 0..r.array_len()? {
                        match r.str()?.as_str() {
                            "grant" => grant = true,
                            "write" => {}
                            _ => return Err(bad("unknown right")),
                        }
                    }
                }
                "secret" => secret = Some(r.bin()?.try_into().map_err(|_| bad("secret"))?),
                _ => return Err(bad("unknown invitation field")),
            }
        }
        if !r.0.is_empty() {
            return Err(bad("trailing bytes"));
        }
        let inv = Invitation {
            ns: ns.ok_or(bad("no ns"))?,
            node: node.ok_or(bad("no node"))?,
            secret: secret.ok_or(bad("no secret"))?,
            grant,
            keys,
            until,
            expires: expires.ok_or(bad("no expiry"))?,
            q,
        };
        canonical(bytes, inv.encode())?;
        Ok(inv)
    }

    /// As it goes in a link: base32 (RFC 4648, lowercase, no padding).
    pub fn to_text(&self) -> String {
        base32_encode(&self.encode())
    }

    pub fn from_text(s: &str) -> Result<Invitation, RecordError> {
        Invitation::decode(&base32_decode(s).ok_or(RecordError::Malformed("not base32"))?)
    }
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes base32 in either case; None for anything else or non-zero
/// trailing bits.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_lowercase())? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    (acc & ((1 << bits) - 1) == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv() -> Invitation {
        Invitation {
            ns: ChannelAddr { writer: [1; 32], read_key: [2; 32] },
            node: [3; 16],
            secret: [4; 32],
            grant: false,
            keys: vec!["title".into(), "@content".into()],
            until: Some(1_800_000_000_000),
            expires: 1_792_600_000_000,
            q: Some("type=event".into()),
        }
    }

    #[test]
    fn round_trips_and_refuses_non_canonical() {
        for i in [inv(), Invitation { keys: vec![], until: None, q: None, grant: true, ..inv() }] {
            assert_eq!(Invitation::from_text(&i.to_text()).unwrap(), i);
            assert_eq!(Invitation::from_text(&i.to_text().to_uppercase()).unwrap(), i);
        }
        let mut b = inv().encode();
        b.push(0xc0);
        assert!(Invitation::decode(&b).is_err());
        // The expiry as a 64-bit int where a smaller form exists.
        assert!(Invitation::decode(&[0x81, 0xa7, b'e', b'x', b'p', b'i', b'r', b'e', b's', 0xcf, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn proofs_bind_link_writer_and_node() {
        let s = [9; 32];
        let body = redeem_request(&s, b"link-one", &[5; 32], &[6; 16]);
        let Redemption { id, writer, node, proof } = parse_redeem(&body).unwrap();
        assert_eq!((id, writer, node), (id_of(&s), [5; 32], [6; 16]));
        assert!(verify(&s, b"link-one", &writer, &node, &proof));
        assert!(!verify(&s, b"link-two", &writer, &node, &proof));
        assert!(!verify(&s, b"link-one", &[7; 32], &node, &proof));
        assert!(!verify(&s, b"link-one", &writer, &[8; 16], &proof));
        assert!(!verify(&[0; 32], b"link-one", &writer, &node, &proof));
    }

    #[test]
    fn base32_matches_rfc4648() {
        for (raw, enc) in [("", ""), ("f", "my"), ("fo", "mzxq"), ("foo", "mzxw6"), ("foob", "mzxw6yq"), ("fooba", "mzxw6ytb"), ("foobar", "mzxw6ytboi")] {
            assert_eq!(base32_encode(raw.as_bytes()), enc);
            assert_eq!(base32_decode(enc).unwrap(), raw.as_bytes());
        }
        assert!(base32_decode("mz1").is_none());
        assert!(base32_decode("mzxr").is_none(), "non-zero trailing bits");
    }
}
