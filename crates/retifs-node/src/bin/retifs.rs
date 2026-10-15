//! retifs CLI (prototype): a thin client of the local retifsd (libretifs).
//!
//!     retifs [--store DIR] ping
//!     retifs [--store DIR] put FILE [--public] [--compress] [--publish] [--record NAME | --one-off]
//!
//! `put` treats the file's absolute path as its record by default, so putting
//! an edited file again stores only the changed chunks (ADR-0008).
//!     retifs [--store DIR] get READ-CAP [--from NODE]... [-o OUT] [--links N] [--batch N]
//!     retifs [--store DIR] status READ-CAP
//!     retifs [--store DIR] want READ-CAP [--from NODE]...
//!     retifs [--store DIR] replicate READ-CAP --to NODE...
//!
//! `replicate` keeps an own file on other nodes under signed leases (ADR-0011);
//! `status` then shows how many of them confirmed with a receipt.
//!
//! `get` reads from the daemon's local store first, then fetches the rest from
//! the given nodes; fetched chunks stay cached in the daemon's store.

use std::path::PathBuf;

use libretifs::{default_store_dir, Client};

fn usage() -> ! {
    eprintln!(
        "retifs [--store DIR] ping\n\
         retifs [--store DIR] put FILE [--public] [--compress] [--publish] [--record NAME | --one-off]\n\
         retifs [--store DIR] get READ-CAP [--from NODE]... [-o OUT] [--links N] [--batch N]\n\
         retifs [--store DIR] status READ-CAP\n\
         retifs [--store DIR] want READ-CAP [--from NODE]...
         retifs [--store DIR] replicate READ-CAP --to NODE..."
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut store = default_store_dir();
    if let Some(i) = args.iter().position(|a| a == "--store") {
        store = args.get(i + 1).cloned().unwrap_or_else(|| usage()).into();
        args.drain(i..=i + 1);
    }
    let mut it = args.into_iter();
    let command = it.next().unwrap_or_else(|| usage());

    let mut client = Client::connect(&store).await.unwrap_or_else(|e| fail(e));
    match command.as_str() {
        "ping" => {
            let (node, chunks, usage) = client.ping().await.unwrap_or_else(|e| fail(e));
            println!("retifsd <{node}>, {chunks} chunks in store");
            if let Some(u) = usage {
                println!(
                    "  own (pinned) {}  promised (leased) {}  of store limit {}\n  cache {} of {}  spare {}\n  volume: {} free of {}, reserve {}",
                    human(u.pinned), human(u.leased), human(u.store_limit),
                    human(u.cache), human(u.cache_max), human(u.spare),
                    human(u.disk_available), human(u.disk_total), human(u.reserve)
                );
            }
        }
        "put" => {
            let path: PathBuf = it.next().unwrap_or_else(|| usage()).into();
            let flags: Vec<String> = it.collect();
            let public = flags.iter().any(|a| a == "--public");
            let compress = flags.iter().any(|a| a == "--compress");
            let publish = flags.iter().any(|a| a == "--publish");
            let record = if flags.iter().any(|a| a == "--one-off") {
                None
            } else if let Some(i) = flags.iter().position(|a| a == "--record") {
                Some(flags.get(i + 1).cloned().unwrap_or_else(|| usage()))
            } else {
                Some(std::path::absolute(&path).unwrap_or_else(|_| path.clone()).to_string_lossy().into_owned())
            };
            let data = std::fs::read(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
            let cap = client.put(data, public, compress, publish, record).await.unwrap_or_else(|e| fail(e));
            println!("{cap}");
        }
        "get" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let (mut from, mut out, mut links, mut batch) = (Vec::new(), PathBuf::from("retifs.out"), 1usize, 0usize);
            while let Some(arg) = it.next() {
                let mut value = || it.next().unwrap_or_else(|| usage());
                match arg.as_str() {
                    "--from" => from.push(value()),
                    "-o" | "--out" => out = value().into(),
                    "--links" => links = value().parse().unwrap_or_else(|_| usage()),
                    "--batch" => batch = value().parse().unwrap_or_else(|_| usage()),
                    _ => usage(),
                }
            }
            let (data, s) = client.get(&cap, &from, links, batch).await.unwrap_or_else(|e| fail(e));
            std::fs::write(&out, &data).unwrap_or_else(|e| fail(format!("{}: {e}", out.display())));
            let secs = s.millis as f64 / 1000.0;
            println!(
                "{} bytes in {:.2} s ({:.1} Mbps) after {:.2} s connecting: {} chunks, {} local, {} requests, {} retries, {} network bytes over {} link(s) -> {}",
                data.len(), secs, data.len() as f64 * 8.0 / secs.max(1e-6) / 1e6, s.connect_millis as f64 / 1000.0,
                s.chunks, s.from_local, s.requests, s.retries, s.network_bytes, s.links, out.display()
            );
        }
        "want" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let mut from = Vec::new();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--from" => from.push(it.next().unwrap_or_else(|| usage())),
                    _ => usage(),
                }
            }
            let s = client.want(&cap, &from).await.unwrap_or_else(|e| fail(e));
            print_status(&s);
        }
        "replicate" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let mut to = Vec::new();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--to" => to.push(it.next().unwrap_or_else(|| usage())),
                    _ => usage(),
                }
            }
            if to.is_empty() {
                usage();
            }
            let s = client.replicate(&cap, &to).await.unwrap_or_else(|e| fail(e));
            print_status(&s);
        }
        "status" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let s = client.status(&cap).await.unwrap_or_else(|e| fail(e));
            print_status(&s);
        }
        _ => usage(),
    }
}

fn print_status(s: &libretifs::Status) {
    let total = s.total_chunks.map_or("?".to_string(), |t| t.to_string());
    println!(
        "{} bytes: {}/{} chunks local{}{}{}",
        s.size, s.local_chunks, total,
        if s.missing_nodes > 0 { format!(", {} manifest node(s) not held locally", s.missing_nodes) } else { String::new() },
        if s.complete() { " (complete, readable offline)" } else { "" },
        if s.seeking { format!(", seeking ({} holder(s) known)", s.holders_known) } else { String::new() }
    );
    if s.leased_to > 0 {
        println!("  leased to {} node(s), {} confirmed by receipt", s.leased_to, s.replicas);
    }
}

fn human(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (mut v, mut i) = (b as f64, 0);
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", UNITS[i]) }
}

fn fail(e: impl std::fmt::Display) -> ! {
    eprintln!("retifs: {e}");
    std::process::exit(1);
}
