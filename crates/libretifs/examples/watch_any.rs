//! Waits for a change in any of the libraries named, as an app would:
//!
//!     cargo run -p libretifs --example watch_any -- STORE NS...
//!
//! Prints the library that changed and how long the wait took.

use std::time::{Duration, Instant};

use libretifs::{Client, Request, Response};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let store = std::path::PathBuf::from(args.next().expect("STORE"));
    let libraries: Vec<String> = args.collect();
    let mut watches = Vec::new();
    for ns in &libraries {
        let mut c = Client::connect(&store).await.expect("connect");
        let count = match c.call(Request::Watch { ns: ns.clone(), since: 0, timeout_ms: 0 }).await.expect("count") {
            Response::Changed { count } => count,
            r => panic!("unexpected {r:?}"),
        };
        watches.push((Client::connect(&store).await.expect("connect"), ns.clone(), count));
    }
    println!("watching {libraries:?}");
    let t = Instant::now();
    let changed = libretifs::watch_any(watches, Duration::from_secs(60)).await.expect("watch");
    println!("{changed:?} after {} ms", t.elapsed().as_millis());
}
