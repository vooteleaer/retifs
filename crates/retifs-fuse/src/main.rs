//! `retifs-mount NS MOUNTPOINT [--store DIR]`: a namespace as a directory
//! tree (ADR-0002), through `retifsd`'s local API. Linux (FUSE) only.

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod tree;

#[cfg(target_os = "linux")]
mod fs;

fn usage() -> ! {
    eprintln!("retifs-mount [--store DIR] NS MOUNTPOINT");
    std::process::exit(2)
}

fn main() {
    let mut store = libretifs::default_store_dir();
    let mut rest = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--store" => store = args.next().unwrap_or_else(|| usage()).into(),
            "-h" | "--help" => usage(),
            _ => rest.push(a),
        }
    }
    let [ns, mountpoint] = <[String; 2]>::try_from(rest).unwrap_or_else(|_| usage());
    run(&store, &ns, std::path::Path::new(&mountpoint));
}

#[cfg(target_os = "linux")]
fn run(store: &std::path::Path, ns: &str, mountpoint: &std::path::Path) {
    eprintln!("retifs-mount: namespace {ns} at {} (unmount with fusermount3 -u or umount)", mountpoint.display());
    if let Err(e) = fs::mount(store, ns, mountpoint) {
        eprintln!("retifs-mount: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_store: &std::path::Path, _ns: &str, _mountpoint: &std::path::Path) {
    eprintln!("retifs-mount: FUSE mounts are Linux only for now (ADR-0002); Haiku's userlandfs frontend comes later");
    std::process::exit(1);
}
