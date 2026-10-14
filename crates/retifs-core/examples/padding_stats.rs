//! Padding overhead of the chunker + size classes, per file size.
//!
//!     cargo run --release -p retifs-core --example padding_stats [FILE…]

use retifs_core::chunk::{class_for, CLASSES};
use retifs_core::chunker;

fn noise(len: usize, mut s: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

fn report(name: &str, data: &[u8]) {
    let mut per_class = [0usize; CLASSES.len()];
    let mut padded = 0usize;
    let mut chunks = 0usize;
    for c in chunker::split(data) {
        let class = class_for(c.len()).unwrap();
        per_class[CLASSES.iter().position(|&x| x == class).unwrap()] += 1;
        padded += class;
        chunks += 1;
    }
    let hist: Vec<String> = CLASSES
        .iter()
        .zip(per_class)
        .filter(|(_, n)| *n > 0)
        .map(|(c, n)| format!("{}k:{:.0}%", c / 1024, n as f64 * 100.0 / chunks as f64))
        .collect();
    println!(
        "{name:<28} {:>9} KiB  {chunks:>6} chunks  avg {:>5.1} KiB  overhead {:>4.0}%   {}",
        data.len() / 1024,
        data.len() as f64 / chunks.max(1) as f64 / 1024.0,
        (padded as f64 / data.len() as f64 - 1.0) * 100.0,
        hist.join(" ")
    );
}

fn main() {
    for mb in [1, 10, 100] {
        report(&format!("random {mb} MB"), &noise(mb << 20, mb as u64 * 7 + 1));
    }
    for path in std::env::args().skip(1) {
        match std::fs::read(&path) {
            Ok(d) => report(path.rsplit(['/', '\\']).next().unwrap(), &d),
            Err(e) => eprintln!("{path}: {e}"),
        }
    }
}
