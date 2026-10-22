//! `retifs-mount NS MOUNTPOINT [--store DIR]`: a namespace as a directory
//! tree (ADR-0002), through `retifsd`'s local API. Linux (FUSE) only.

#[cfg(target_os = "linux")]
use retifs_tree as tree;

#[cfg(target_os = "linux")]
mod fs;

fn usage() -> ! {
    eprintln!("retifs-mount [--store DIR] [--wait SECONDS] [--via NODE] NS MOUNTPOINT");
    eprintln!("  --wait: how long a read waits for content that isn't here yet (default 30)");
    eprintln!("  --via: the namespace is on another of your nodes (ADR-0019), not this one");
    std::process::exit(2)
}

fn main() {
    let mut store = libretifs::default_store_dir();
    let mut wait = std::time::Duration::from_secs(30);
    let mut via = None;
    let mut rest = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--store" => store = args.next().unwrap_or_else(|| usage()).into(),
            "--wait" => wait = std::time::Duration::from_secs(args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--via" => via = Some(args.next().unwrap_or_else(|| usage())),
            "-h" | "--help" => usage(),
            _ => rest.push(a),
        }
    }
    let [ns, mountpoint] = <[String; 2]>::try_from(rest).unwrap_or_else(|_| usage());
    run(&store, &ns, std::path::Path::new(&mountpoint), wait, via);
}

#[cfg(target_os = "linux")]
fn run(store: &std::path::Path, ns: &str, mountpoint: &std::path::Path, wait: std::time::Duration, via: Option<String>) {
    let on = via.as_deref().map(|v| format!(" on node {v}")).unwrap_or_default();
    eprintln!("retifs-mount: namespace {ns}{on} at {} (unmount with fusermount3 -u or umount)", mountpoint.display());
    if let Err(e) = fs::mount(store, ns, mountpoint, wait, via) {
        eprintln!("retifs-mount: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_store: &std::path::Path, _ns: &str, _mountpoint: &std::path::Path, _wait: std::time::Duration, _via: Option<String>) {
    eprintln!("retifs-mount: FUSE mounts are Linux only for now (ADR-0002); Haiku's userlandfs frontend comes later");
    std::process::exit(1);
}
