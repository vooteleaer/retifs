//! `cargo run --release -p retifs-card --example card_timing`: how long the
//! card takes to sign (32 and 400 bytes) and to agree on a key, over 20 runs.
use std::time::Instant;

use retifs_card::{Card, PinUse};

fn main() {
    let pin = std::env::var("RETIFS_CARD_PIN").unwrap_or_else(|_| "123456".into());
    let mut card = Card::open().unwrap_or_else(|e| panic!("{e}"));
    card.verify_pin(&pin, PinUse::Sign).unwrap_or_else(|e| panic!("{e}"));
    card.verify_pin(&pin, PinUse::Other).unwrap_or_else(|e| panic!("{e}"));
    let peer = card.public_identity().unwrap_or_else(|e| panic!("{e}")).x25519;
    let runs = 20;
    for (what, n) in [("sign 32 B", 32usize), ("sign 400 B", 400)] {
        let msg = vec![0x5a; n];
        let mut ms: Vec<f64> = (0..runs)
            .map(|_| {
                let t = Instant::now();
                card.sign(&msg).unwrap_or_else(|e| panic!("{e}"));
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect();
        ms.sort_by(f64::total_cmp);
        println!("{what}: median {:.0} ms, min {:.0}, max {:.0}", ms[runs / 2], ms[0], ms[runs - 1]);
    }
    let mut ms: Vec<f64> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            card.agree(&peer).unwrap_or_else(|e| panic!("{e}"));
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    ms.sort_by(f64::total_cmp);
    println!("agree: median {:.0} ms, min {:.0}, max {:.0}", ms[runs / 2], ms[0], ms[runs - 1]);
}
