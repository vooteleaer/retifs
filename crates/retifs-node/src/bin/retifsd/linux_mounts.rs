//! On Linux, every library is a folder in `~/retifs/<library>` (the FUSE
//! frontend, `retifs-mount`): retifsd mounts each one it has, a library
//! joined later within seconds, and unmounts one it has left. Only for the
//! user's own store (retifsd started without `--store`, as the .deb's user
//! service is) and not with `--no-mounts`: a test node's store isn't
//! anyone's files.
//!
//! A mount is recorded under the store (`mounts/<library>`) as `retifs
//! mount` records it, so `retifs mount` lists it and `retifs unmount` takes
//! it down; one taken down stays down until retifsd starts again. A frontend
//! that stopped (its record left behind) is started again.

use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{visible_namespaces, Daemon};

/// How often the libraries are looked at again.
const EVERY: Duration = Duration::from_secs(10);
/// A mount that failed is tried again after this.
const RETRY: Duration = Duration::from_secs(300);
/// How long after its frontend exited a mount waits to be started again.
const EXIT_GRACE: Duration = Duration::from_secs(20);

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/".into())
}

fn dir_of(ns: &str) -> PathBuf {
    home().join("retifs").join(ns)
}

fn record_of(store: &Path, ns: &str) -> PathBuf {
    store.join("mounts").join(ns)
}

/// Whether something is mounted at `dir`, from the kernel's mount table:
/// never a stat of the folder, which would be a FUSE request the frontend
/// answers by asking this daemon (a `retifs unmount` hung behind one).
fn is_mounted(dir: &Path) -> bool {
    let want = dir.to_string_lossy();
    std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|t| t.lines().any(|l| l.split(' ').nth(4).is_some_and(|m| unescape(m) == want)))
}

/// A mount point as /proc/self/mountinfo writes it (space, tab, newline and
/// backslash as octal escapes).
fn unescape(s: &str) -> String {
    s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
}

/// The FUSE frontend: next to retifsd (the .deb, cargo install), else on the PATH.
fn frontend() -> PathBuf {
    let here = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("retifs-mount")));
    here.filter(|p| p.is_file()).unwrap_or_else(|| "retifs-mount".into())
}

/// The frontend's pid from a mount's record, if it's still running.
fn recorded_pid(store: &Path, ns: &str) -> Option<u32> {
    let text = std::fs::read_to_string(record_of(store, ns)).ok()?;
    let pid: u32 = text.lines().next()?.trim().parse().ok()?;
    Path::new(&format!("/proc/{pid}")).exists().then_some(pid)
}

fn mount(store: &Path, ns: &str) -> Result<Child, String> {
    let dir = dir_of(ns);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let records = store.join("mounts");
    std::fs::create_dir_all(&records).map_err(|e| e.to_string())?;
    let log = std::fs::File::create(records.join(format!("{ns}.log"))).map_err(|e| e.to_string())?;
    let child = Command::new(frontend())
        .arg("--store")
        .arg(store)
        .arg(ns)
        .arg(&dir)
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .map_err(|e| format!("{}: {e}", frontend().display()))?;
    std::fs::write(record_of(store, ns), format!("{}\n{}\n\n", child.id(), dir.display())).map_err(|e| e.to_string())?;
    Ok(child)
}

/// A library left: its folder unmounted (the frontend then exits by itself).
fn unmount(store: &Path, ns: &str) {
    let dir = dir_of(ns);
    if is_mounted(&dir)
        && !Command::new("fusermount3").arg("-u").arg(&dir).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
        && !Command::new("fusermount3").arg("-uz").arg(&dir).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    {
        eprintln!("mounts: couldn't unmount {}", dir.display());
        return;
    }
    let _ = std::fs::remove_file(record_of(store, ns));
    let _ = std::fs::remove_dir(&dir); // the empty mount point, if nothing else is in it
    println!("mounts: {ns} unmounted from {}", dir.display());
}

/// "Share with retifs…" for the file managers that are here (ADR-0021):
/// Nautilus's scripts folder and Dolphin's service menus, in the user's own
/// folders. Written when missing or different; nothing for one not installed.
fn file_manager_menus() {
    let on_path = |exe: &str| std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(exe).is_file()));
    let share = home().join(".local/share");
    let menus: [(&str, PathBuf, &str); 2] = [
        ("nautilus", share.join("nautilus/scripts/Share with retifs"), include_str!("../../../../../packaging/linux/share-nautilus.sh")),
        ("dolphin", share.join("kio/servicemenus/retifs-share.desktop"), include_str!("../../../../../packaging/linux/retifs-share.desktop")),
    ];
    for (exe, path, text) in menus {
        if !on_path(exe) || std::fs::read_to_string(&path).is_ok_and(|t| t == text) {
            continue;
        }
        let written = path.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|_| std::fs::write(&path, text)).and_then(|_| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        });
        match written {
            Ok(()) => println!("mounts: Share with retifs added to {exe} ({})", path.display()),
            Err(e) => eprintln!("mounts: {}: {e}", path.display()),
        }
    }
}

pub async fn keeper(d: Arc<Daemon>, store: PathBuf) {
    file_manager_menus();
    if !Path::new("/dev/fuse").exists() {
        eprintln!("mounts: no /dev/fuse here: libraries aren't mounted as folders");
        return;
    }
    // Let the local API come up first: the frontends talk to it.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut children: HashMap<String, Child> = HashMap::new();
    // Mounted by this keeper since retifsd started: one whose record is gone
    // was taken down with `retifs unmount`, and stays down.
    let mut mounted: HashSet<String> = HashSet::new();
    let mut failed: HashMap<String, Instant> = HashMap::new();
    // Frontends that exited, and when: `retifs unmount` removes the record
    // only after its frontend is gone, so one is started again only if its
    // record is still there a while later (it stopped by itself).
    let mut exited: HashMap<String, Instant> = HashMap::new();
    loop {
        let names = visible_namespaces(&d).unwrap_or_default();
        // Frontends that have exited: reaped, so they don't linger as zombies.
        children.retain(|ns, c| {
            let running = matches!(c.try_wait(), Ok(None));
            if !running {
                exited.insert(ns.clone(), Instant::now());
            }
            running
        });
        for ns in &names {
            let dir = dir_of(ns);
            let recorded = record_of(&store, ns).exists();
            if is_mounted(&dir)
                || (mounted.contains(ns) && !recorded)
                || failed.get(ns).is_some_and(|at| at.elapsed() < RETRY)
                || exited.get(ns).is_some_and(|at| at.elapsed() < EXIT_GRACE)
            {
                continue;
            }
            // A frontend still starting (recorded, running, not mounted yet).
            if recorded && recorded_pid(&store, ns).is_some() {
                continue;
            }
            match mount(&store, ns) {
                Ok(child) => {
                    println!("mounts: {ns} at {}", dir.display());
                    children.insert(ns.clone(), child);
                    mounted.insert(ns.clone());
                    failed.remove(ns);
                }
                Err(e) => {
                    eprintln!("mounts: {ns}: {e}");
                    failed.insert(ns.clone(), Instant::now());
                }
            }
        }
        // Left: no longer a library here.
        for ns in mounted.clone() {
            if !names.contains(&ns) {
                unmount(&store, &ns);
                mounted.remove(&ns);
            }
        }
        tokio::time::sleep(EVERY).await;
    }
}
