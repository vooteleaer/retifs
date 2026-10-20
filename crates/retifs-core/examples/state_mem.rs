//! How much memory a namespace's merged state takes: builds the state of
//! N records with four fields each and counts the bytes allocated.
//!
//!     cargo run --release -p retifs-core --example state_mem [N]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use retifs_core::ops::{Op, Right, State, WriterCommit};
use retifs_core::record::Value;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Counting = Counting;

fn main() {
    let n: u32 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(100_000);
    let creator = [1u8; 32];
    let mut commits = Vec::new();
    let mut ops = vec![Op::Grant([2; 32], vec![Right::Write])];
    for i in 0..n {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&i.to_be_bytes());
        ops.push(Op::Set(id, "title".into(), Value::Str(format!("photo {i}"))));
        ops.push(Op::Set(id, "album".into(), Value::Str(format!("a{}", i % 500))));
        ops.push(Op::Set(id, "n".into(), Value::Int(i as i64)));
        ops.push(Op::Set(id, "type".into(), Value::Str("image".into())));
        if ops.len() >= 2000 {
            commits.push(WriterCommit { seq: commits.len() as u64 + 1, time_ms: 1000 + commits.len() as u64, ops: std::mem::take(&mut ops) });
        }
    }
    if !ops.is_empty() {
        commits.push(WriterCommit { seq: commits.len() as u64 + 1, time_ms: 1000 + commits.len() as u64, ops });
    }
    let chains: BTreeMap<_, _> = [(creator, commits)].into_iter().collect();
    let before = LIVE.load(Relaxed);
    let mut state = State::build(&creator, &chains, 10_000_000);
    let _ = state.take_dirty();
    let state_bytes = LIVE.load(Relaxed) - before;
    drop(chains);
    let before_list = LIVE.load(Relaxed);
    let records = state.records();
    let list_bytes = LIVE.load(Relaxed) - before_list;
    println!(
        "{n} records x 4 fields: merged state {:.1} MiB ({} B/record); the same as a record list {:.1} MiB; the commits {:.1} MiB",
        state_bytes as f64 / 1048576.0,
        state_bytes / n as usize,
        list_bytes as f64 / 1048576.0,
        before as f64 / 1048576.0
    );
    drop(records);
    println!("live after dropping the list: {:.1} MiB", LIVE.load(Relaxed) as f64 / 1048576.0);
}
