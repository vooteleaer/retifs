//! `retifs-cloudfiles NS FOLDER`: a namespace as a Cloud Files sync root in
//! Explorer (ADR-0002), through `retifsd`'s local API. Windows only.

#[cfg_attr(not(windows), allow(dead_code))]
mod names;

#[cfg(windows)]
mod provider;
#[cfg(windows)]
mod share_menu;

fn usage() -> ! {
    eprintln!("retifs-cloudfiles [--store DIR] [--wait SECONDS] NS FOLDER");
    eprintln!("retifs-cloudfiles --unregister NS");
    eprintln!("retifs-cloudfiles [--store DIR] --share PATH");
    eprintln!("retifs-cloudfiles [--store DIR] --share-in NS ROOT PATH   (what Explorer's Share with retifs runs)");
    eprintln!("  --wait: how long opening a file waits for content that isn't here yet (default 30)");
    std::process::exit(2)
}

fn main() {
    let mut store = libretifs::default_store_dir();
    let mut wait = std::time::Duration::from_secs(30);
    let mut unregister = false;
    let mut share = None;
    let mut within = None;
    let mut rest = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--store" => store = args.next().unwrap_or_else(|| usage()).into(),
            "--wait" => wait = std::time::Duration::from_secs(args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--unregister" => unregister = true,
            "--share" => share = Some(args.next().unwrap_or_else(|| usage())),
            "--share-in" => {
                let ns = args.next().unwrap_or_else(|| usage());
                let root = args.next().unwrap_or_else(|| usage());
                within = Some((ns, std::path::PathBuf::from(root)));
                share = Some(args.next().unwrap_or_else(|| usage()));
            }
            "-h" | "--help" => usage(),
            _ => rest.push(a),
        }
    }
    let result = match (unregister, rest.as_slice()) {
        _ if share.is_some() => run_share(&store, std::path::Path::new(share.as_deref().unwrap()), within),
        (true, [ns]) => run_unregister(ns),
        (false, [ns, folder]) => run(&store, ns, std::path::Path::new(folder), wait),
        _ => usage(),
    };
    if let Err(e) = result {
        eprintln!("retifs-cloudfiles: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run(store: &std::path::Path, ns: &str, folder: &std::path::Path, wait: std::time::Duration) -> Result<(), String> {
    provider::run(store, ns, folder, wait)
}

#[cfg(windows)]
fn run_unregister(ns: &str) -> Result<(), String> {
    provider::unregister(ns)
}

#[cfg(windows)]
fn run_share(store: &std::path::Path, path: &std::path::Path, within: Option<(String, std::path::PathBuf)>) -> Result<(), String> {
    share_menu::share(store, path, within)
}

#[cfg(not(windows))]
fn run_share(_: &std::path::Path, _: &std::path::Path, _: Option<(String, std::path::PathBuf)>) -> Result<(), String> {
    run(std::path::Path::new(""), "", std::path::Path::new(""), Default::default())
}

#[cfg(not(windows))]
fn run(_: &std::path::Path, _: &str, _: &std::path::Path, _: std::time::Duration) -> Result<(), String> {
    Err("the Cloud Files provider is Windows only; on Linux use retifs-mount (ADR-0002)".into())
}

#[cfg(not(windows))]
fn run_unregister(_: &str) -> Result<(), String> {
    run(std::path::Path::new(""), "", std::path::Path::new(""), Default::default())
}
