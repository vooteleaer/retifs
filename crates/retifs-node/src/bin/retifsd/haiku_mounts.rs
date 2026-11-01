//! On Haiku, every library is a volume in `~/retifs/<library>` (the
//! `retifs` userlandfs module, retifs-haikufs): retifsd mounts each one it
//! has once the desktop is up, a library joined later within seconds, and
//! unmounts one it has left. Not before the desktop: a userlandfs mount while
//! the login session is still starting blocked the user's launch_daemon, and
//! Deskbar and Tracker never came up.
//!
//! A mount is recorded under the store (`mounts/<library>`) as `retifs
//! mount` records it, so `retifs mount` lists it and `retifs unmount` takes
//! it down (until the next start of retifsd).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{Daemon, visible_namespaces};

/// How often the libraries are looked at again.
const EVERY: Duration = Duration::from_secs(10);
/// A mount that failed is tried again after this.
const RETRY: Duration = Duration::from_secs(300);
/// By their full paths: a launch_daemon job (retifsd at login) has no PATH.
const PS: &str = "/boot/system/bin/ps";
const MOUNT: &str = "/boot/system/bin/mount";
const UNMOUNT: &str = "/boot/system/bin/unmount";

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/boot/home".into())
}

fn dir_of(ns: &str) -> PathBuf {
    home().join("retifs").join(ns)
}

/// Whether a volume is mounted at `dir`: it is on another device than the
/// folder it's in.
fn is_mounted(dir: &Path) -> bool {
    let (Ok(d), Some(Ok(p))) = (std::fs::metadata(dir), dir.parent().map(std::fs::metadata)) else { return false };
    d.dev() != p.dev()
}

/// Whether the desktop is up: Tracker runs.
fn desktop_up() -> bool {
    Command::new(PS).output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.trim_start().starts_with("/boot/system/Tracker")))
}

fn mount(store: &Path, ns: &str) -> Result<(), String> {
    let dir = dir_of(ns);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // The module takes its parameters split at spaces.
    let params = format!("retifs ns={ns} store={}", store.display());
    let o = Command::new(MOUNT).args(["-t", "userlandfs", "-p", &params]).arg(&dir).output().map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
    }
    let records = store.join("mounts");
    let _ = std::fs::create_dir_all(&records);
    let _ = std::fs::write(records.join(ns), format!("0\n{}\n\n", dir.display()));
    Ok(())
}

fn unmount(store: &Path, ns: &str, dir: &Path) {
    if is_mounted(dir) && !Command::new(UNMOUNT).arg(dir).status().is_ok_and(|s| s.success()) {
        eprintln!("haiku: couldn't unmount {}", dir.display());
        return;
    }
    let _ = std::fs::remove_file(store.join("mounts").join(ns));
    let _ = std::fs::remove_dir(dir); // the empty mount point, if nothing else is in it
    println!("haiku: {ns} unmounted from {}", dir.display());
}

/// The libraries this node had mounted (by this or `retifs mount`).
fn recorded(store: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(store.join("mounts")) else { return Vec::new() };
    entries
        .flatten()
        .filter(|e| e.path().extension().is_none())
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path()).ok()?;
            Some((e.file_name().to_string_lossy().into_owned(), PathBuf::from(text.lines().nth(1)?)))
        })
        .collect()
}

pub async fn keeper(d: Arc<Daemon>, store: PathBuf) {
    while !tokio::task::spawn_blocking(desktop_up).await.unwrap_or(false) {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    // Let the desktop finish coming up.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut failed: HashMap<String, Instant> = HashMap::new();
    loop {
        let names = visible_namespaces(&d).unwrap_or_default();
        let store2 = store.clone();
        let failed_now: Vec<String> = failed.iter().filter(|(_, at)| at.elapsed() < RETRY).map(|(n, _)| n.clone()).collect();
        let result = tokio::task::spawn_blocking(move || {
            let mut newly_failed = Vec::new();
            for ns in &names {
                if is_mounted(&dir_of(ns)) || failed_now.contains(ns) {
                    continue;
                }
                match mount(&store2, ns) {
                    Ok(()) => println!("haiku: {ns} mounted at {}", dir_of(ns).display()),
                    Err(e) => {
                        eprintln!("haiku: mounting {ns}: {e}");
                        newly_failed.push(ns.clone());
                    }
                }
            }
            // Left: no longer a library here.
            for (ns, dir) in recorded(&store2) {
                if !names.contains(&ns) {
                    unmount(&store2, &ns, &dir);
                }
            }
            newly_failed
        })
        .await;
        for ns in result.unwrap_or_default() {
            failed.insert(ns, Instant::now());
        }
        tokio::time::sleep(EVERY).await;
    }
}
