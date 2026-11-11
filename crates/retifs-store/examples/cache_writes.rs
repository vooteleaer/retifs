//! `cargo run --release -p retifs-store --example cache_writes`: 4000 cache
//! chunks of 16 KiB written one at a time and in rounds of 32 (as fetches
//! arrive), then all read back, in a fresh store each time.
use std::time::Instant;

use retifs_core::{seal, ConvergenceSecret};
use retifs_store::{tier, SlabStore};

fn chunks(n: usize, salt: u8) -> Vec<(retifs_core::Cid, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let data: Vec<u8> = (0..16_000u32).map(|j| (i as u32 ^ j ^ salt as u32) as u8).collect();
            let s = seal(&ConvergenceSecret::public(), &data).expect("seal");
            (s.cid, s.ciphertext)
        })
        .collect()
}

fn main() {
    let n = 4000;
    for (what, batch) in [("one at a time", 1usize), ("rounds of 32", 32)] {
        let dir = std::env::temp_dir().join(format!("retifs-cache-writes-{batch}"));
        let _ = std::fs::remove_dir_all(&dir);
        let st = SlabStore::open(&dir).expect("store");
        let items = chunks(n, batch as u8);
        let t = Instant::now();
        for part in items.chunks(batch) {
            if batch == 1 {
                st.insert(&part[0].0, &part[0].1, tier::CACHE).expect("insert");
            } else {
                st.insert_batch(part, tier::CACHE).expect("insert");
            }
        }
        let write = t.elapsed();
        let t = Instant::now();
        for (cid, _) in &items {
            st.fetch(cid).expect("fetch").expect("present");
        }
        let read = t.elapsed();
        println!("{what}: write {:.0} chunks/s, read {:.0} chunks/s", n as f64 / write.as_secs_f64(), n as f64 / read.as_secs_f64());
        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
