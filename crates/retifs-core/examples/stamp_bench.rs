//! Time to find stamps of increasing cost (one lease's material).
//!
//!     cargo run --release -p retifs-core --example stamp_bench
use std::time::Instant;

fn main() {
    let material = b"retifs/v1/stamp benchmark material".to_vec();
    let t = Instant::now();
    let wb = retifs_core::stamp::workblock(&material);
    println!("workblock: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    for cost in [8u8, 12, 16, 18, 20, 22, 24] {
        let t = Instant::now();
        let mut n = 0;
        for i in 0..4u8 {
            let m = [material.as_slice(), &[i]].concat();
            let st = retifs_core::stamp::generate(&m, cost);
            n += 1;
            let _ = st;
        }
        let secs = t.elapsed().as_secs_f64() / n as f64;
        println!("cost {cost:>2}: {secs:>8.3} s per stamp (mean of {n}, includes workblock)");
        let _ = &wb;
    }
}
