//! Regenerates `test-vectors/invite-v1.json` (ADR-0020: invitations, their
//! IDs and redemption proofs).
//!
//!     cargo run -p retifs-core --example gen_invite_vectors > crates/retifs-core/test-vectors/invite-v1.json

use retifs_core::{channel::ChannelAddr, invite::{self, Invitation}};
use serde_json::json;
use sha2::{Digest, Sha256};

fn input<const N: usize>(label: &str, i: u32) -> [u8; N] {
    Sha256::digest([label.as_bytes(), &i.to_be_bytes()].concat())[..N].try_into().unwrap()
}

fn main() {
    let cases: Vec<Invitation> = vec![
        Invitation {
            ns: ChannelAddr { writer: input("writer", 0), read_key: input("read key", 0) },
            node: input("node", 0),
            secret: input("secret", 0),
            grant: false,
            keys: vec![],
            until: None,
            expires: 1_792_600_000_000,
            q: None,
        },
        Invitation {
            ns: ChannelAddr { writer: input("writer", 1), read_key: input("read key", 1) },
            node: input("node", 1),
            secret: input("secret", 1),
            grant: true,
            keys: vec!["title".into(), "@content".into()],
            until: Some(1_800_000_000_000),
            expires: 1_792_686_400_000,
            q: Some("type=event, calendar=family".into()),
        },
    ];
    let out: Vec<_> = cases
        .iter()
        .enumerate()
        .map(|(i, inv)| {
            let link_id: [u8; 16] = input("link", i as u32);
            let writer: [u8; 32] = input("member writer", i as u32);
            let node: [u8; 16] = input("member node", i as u32);
            json!({
                "fields": {
                    "expires": inv.expires,
                    "keys": inv.keys,
                    "until": inv.until,
                    "node": hex::encode(inv.node),
                    "ns": hex::encode([inv.ns.writer, inv.ns.read_key].concat()),
                    "q": inv.q,
                    "grant": inv.grant,
                    "secret": hex::encode(inv.secret),
                },
                "encoded": hex::encode(inv.encode()),
                "text": inv.to_text(),
                "id": hex::encode(inv.id()),
                "redeem": {
                    "link_id": hex::encode(link_id),
                    "writer": hex::encode(writer),
                    "node": hex::encode(node),
                    "request": hex::encode(invite::redeem_request(&inv.secret, &link_id, &writer, &node)),
                },
            })
        })
        .collect();
    let doc = json!({
        "about": "ADR-0020: an invitation is canonical msgpack {expires, limits {keys?, until?}, node, ns (writer || read key), q?, rights, secret}, base32 (RFC 4648, lowercase, no padding) in retifs:invite/ links; id = SHA-256(\"retifs/v1/invite\" || secret); a redemption is id || writer || node || HMAC-SHA256(secret, link id || writer || node)",
        "cases": out,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
