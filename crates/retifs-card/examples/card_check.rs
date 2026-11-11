//! `cargo run -p retifs-card --example card_check`: with an OpenPGP card
//! (YubiKey) holding the identity, signs and agrees on a key on the card and
//! checks both in software (ed25519-dalek, X25519). The PIN comes from
//! `RETIFS_CARD_PIN` (default: the factory 123456). Prints what Python RNS
//! can check too (docs/recon/yubikey/verify_card_rust.py).

use curve25519_dalek::MontgomeryPoint;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use retifs_card::{Card, PinUse};

fn main() {
    let pin = std::env::var("RETIFS_CARD_PIN").unwrap_or_else(|_| "123456".into());
    let mut card = Card::open().unwrap_or_else(|e| panic!("{e}"));
    println!("reader      {}", card.reader());
    let id = card.public_identity().unwrap_or_else(|e| panic!("{e}"));
    println!("public      {}", hex::encode(id.bytes()));
    println!("identity    {}", hex::encode(id.hash()));
    println!("retifs.node {}", hex::encode(id.destination("retifs.node")));

    // Signing: a packet-sized message, checked against the card's public key.
    card.verify_pin(&pin, PinUse::Sign).unwrap_or_else(|e| panic!("{e}"));
    let message: Vec<u8> = (0..400u32).map(|i| (i * 7) as u8).collect();
    let sig = card.sign(&message).unwrap_or_else(|e| panic!("{e}"));
    let vk = VerifyingKey::from_bytes(&id.ed25519).expect("Ed25519 public key");
    vk.verify(&message, &Signature::from_bytes(&sig)).expect("the card's signature verifies");
    println!("message     {}", hex::encode(&message));
    println!("signature   {}", hex::encode(sig));

    // Agreement: an ephemeral key made here; both sides must reach the same secret.
    card.verify_pin(&pin, PinUse::Other).unwrap_or_else(|e| panic!("{e}"));
    let mut eph = [0u8; 32];
    getrandom::fill(&mut eph).expect("OS entropy");
    let eph_pub = MontgomeryPoint::mul_base_clamped(eph).to_bytes();
    let on_card = card.agree(&eph_pub).unwrap_or_else(|e| panic!("{e}"));
    let in_software = MontgomeryPoint(id.x25519).mul_clamped(eph).to_bytes();
    assert_eq!(on_card, in_software, "the card's X25519 agrees with software");
    println!("agreement   same secret on the card and in software");
    println!("ok");
}
