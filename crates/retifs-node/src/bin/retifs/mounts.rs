//! `retifs mount` and `retifs unmount` (ADR-0002): a library's file tree
//! through this platform's frontend, `retifs-mount` (FUSE) on Linux and
//! `retifs-cloudfiles` (a Cloud Files sync root) on Windows, started in the
//! background. Which libraries are mounted where, and by which process, is
//! kept under the store (`mounts/<namespace>`); the frontend's log is next
//! to it.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[cfg(windows)]
const FRONTEND: &str = "retifs-cloudfiles.exe";
#[cfg(not(windows))]
const FRONTEND: &str = "retifs-mount";

fn mounts_dir(store: &Path) -> PathBuf {
    store.join("mounts")
}

/// The frontend next to this program, or on the PATH.
fn frontend() -> PathBuf {
    std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join(FRONTEND))).filter(|p| p.exists()).unwrap_or_else(|| FRONTEND.into())
}

/// Where a library is mounted unless told otherwise: `~/retifs/<ns>`.
fn default_dir(ns: &str) -> PathBuf {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap_or_else(|| ".".into());
    home.join("retifs").join(ns)
}

struct Mounted {
    ns: String,
    pid: u32,
    dir: PathBuf,
    /// The node holding the library, when it isn't this one.
    via: Option<String>,
}

fn read(store: &Path, ns: &str) -> Option<Mounted> {
    let text = std::fs::read_to_string(mounts_dir(store).join(ns)).ok()?;
    let mut lines = text.lines();
    let pid = lines.next()?.parse().ok()?;
    let dir = PathBuf::from(lines.next()?);
    let via = lines.next().filter(|v| !v.is_empty()).map(String::from);
    Some(Mounted { ns: ns.to_string(), pid, dir, via })
}

/// The library a path is in, among those mounted from this store: its name,
/// and the path inside it as the file tree names it (`/a/b.jpg`).
pub fn library_of(store: &Path, path: &Path) -> Option<(String, String)> {
    let path = std::fs::canonicalize(path).ok()?;
    let mut best: Option<(String, String, usize)> = None;
    for m in all(store) {
        let dir = std::fs::canonicalize(&m.dir).unwrap_or(m.dir.clone());
        if let Ok(rel) = path.strip_prefix(&dir) {
            let depth = dir.components().count();
            if best.as_ref().is_none_or(|b| depth > b.2) {
                let parts: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
                best = Some((m.ns.clone(), format!("/{}", parts.join("/")), depth));
            }
        }
    }
    best.map(|(ns, p, _)| (ns, p))
}

fn all(store: &Path) -> Vec<Mounted> {
    let Ok(entries) = std::fs::read_dir(mounts_dir(store)) else { return Vec::new() };
    let mut out: Vec<Mounted> = entries
        .flatten()
        .filter(|e| e.path().extension().is_none())
        .filter_map(|e| read(store, &e.file_name().to_string_lossy()))
        .collect();
    out.sort_by(|a, b| a.ns.cmp(&b.ns));
    out
}

/// Whether process `pid` is running and is the frontend.
#[cfg(windows)]
fn alive(pid: u32) -> bool {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, STILL_ACTIVE},
        System::Threading::{GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let running = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let named = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0
            && String::from_utf16_lossy(&buf[..len as usize]).to_lowercase().ends_with(FRONTEND);
        CloseHandle(h);
        running && named
    }
}

#[cfg(not(windows))]
fn alive(pid: u32) -> bool {
    // /proc/<pid>/comm is cut to 15 characters.
    std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| FRONTEND.starts_with(c.trim()) && !c.trim().is_empty())
}

/// Keeps this program's own standard handles out of the frontend: inherited,
/// a pipe the caller reads (`$(retifs mount …)`) would stay open as long as
/// the frontend runs.
#[cfg(windows)]
fn dont_inherit_std_handles() {
    use windows_sys::Win32::{
        Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT},
        System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
    };
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        unsafe {
            let h = GetStdHandle(which);
            if !h.is_null() {
                SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

fn log_tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

/// `retifs mount`: with no library, lists the mounts. `via`: the
/// library is on another of the user's nodes (ADR-0019).
pub fn mount(store: &Path, args: &[String], via: Option<&str>) {
    #[cfg(target_os = "haiku")]
    {
        let _ = via;
        return haiku::mount(store, args);
    }
    #[allow(unreachable_code)]
    let foreground = args.iter().any(|a| a == "--foreground");
    let rest: Vec<&String> = args.iter().filter(|a| *a != "--foreground").collect();
    let Some(ns) = rest.first() else {
        let mounts = all(store);
        for m in &mounts {
            let state = if alive(m.pid) { "" } else { "  (not running: retifs unmount to clean up)" };
            let on = m.via.as_deref().map(|v| format!("  (on node {v})")).unwrap_or_default();
            println!("{:<16} {}{on}{state}", m.ns, m.dir.display());
        }
        println!("{} mount(s)", mounts.len());
        return;
    };
    let dir = rest.get(1).map(PathBuf::from).unwrap_or_else(|| default_dir(ns));
    if let Some(m) = read(store, ns) {
        if alive(m.pid) {
            super::fail(format!("{ns} is mounted already, at {}", m.dir.display()));
        }
        let _ = std::fs::remove_file(mounts_dir(store).join(ns.as_str()));
    }
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| super::fail(format!("{}: {e}", dir.display())));
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    let dir = PathBuf::from(dir.to_string_lossy().trim_start_matches(r"\\?\"));
    let mut cmd = Command::new(frontend());
    cmd.arg("--store").arg(store);
    if let Some(v) = via {
        cmd.arg("--via").arg(v);
    }
    cmd.arg(ns.as_str()).arg(&dir);
    if foreground {
        let status = cmd.status().unwrap_or_else(|e| super::fail(format!("{FRONTEND}: {e}")));
        std::process::exit(status.code().unwrap_or(1));
    }
    std::fs::create_dir_all(mounts_dir(store)).unwrap_or_else(|e| super::fail(e));
    let log = mounts_dir(store).join(format!("{ns}.log"));
    let out = std::fs::File::create(&log).unwrap_or_else(|e| super::fail(format!("{}: {e}", log.display())));
    cmd.stdin(Stdio::null()).stdout(out.try_clone().unwrap_or_else(|e| super::fail(e))).stderr(out);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        dont_inherit_std_handles();
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // not stopped by the terminal's Ctrl+C
    }
    // Left running on purpose once it's up: it serves the mount after this
    // command returns (`retifs unmount` stops it).
    #[allow(clippy::zombie_processes)]
    let mut child = cmd.spawn().unwrap_or_else(|e| super::fail(format!("{}: {e}", frontend().display())));
    let pid = child.id();
    std::fs::write(mounts_dir(store).join(ns.as_str()), format!("{pid}\n{}\n{}\n", dir.display(), via.unwrap_or(""))).unwrap_or_else(|e| super::fail(e));
    // Up once the frontend says so; a frontend that stops has failed.
    let ready = if cfg!(windows) { "retifs-cloudfiles: library" } else { "retifs-mount: library" };
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        std::thread::sleep(Duration::from_millis(300));
        // try_wait, not alive(): it also reaps a frontend that has exited,
        // which would otherwise linger as a zombie that looks alive.
        if !matches!(child.try_wait(), Ok(None)) {
            let _ = std::fs::remove_file(mounts_dir(store).join(ns.as_str()));
            super::fail(format!("mounting {ns} failed:\n{}", log_tail(&log, 10)));
        }
        if std::fs::read_to_string(&log).is_ok_and(|l| l.contains(ready)) && started.elapsed() > Duration::from_secs(1) {
            break;
        }
    }
    let on = via.map(|v| format!(" (on node {v})")).unwrap_or_default();
    println!("{ns}{on} mounted at {}", dir.display());
    println!("  log {}; retifs unmount {ns} to stop", log.display());
}

/// `retifs unmount NS [--forget]`.
pub fn unmount(store: &Path, args: &[String]) {
    #[cfg(target_os = "haiku")]
    return haiku::unmount(store, args);
    #[allow(unreachable_code)]
    let forget = args.iter().any(|a| a == "--forget");
    let Some(ns) = args.iter().find(|a| *a != "--forget") else { super::usage() };
    let Some(m) = read(store, ns) else { super::fail(format!("{ns} isn't mounted (retifs mount lists the mounts)")) };
    if alive(m.pid) {
        stop(&m);
    }
    let _ = std::fs::remove_file(mounts_dir(store).join(ns.as_str()));
    #[cfg(windows)]
    if forget {
        // The sync root's registration too; the folder's files stay as they are.
        let _ = Command::new(frontend()).arg("--unregister").arg(ns.as_str()).status();
    }
    #[cfg(not(windows))]
    let _ = forget;
    println!("{ns} unmounted from {}", m.dir.display());
}

#[cfg(windows)]
fn stop(m: &Mounted) {
    use std::os::windows::process::CommandExt;
    let _ = Command::new("taskkill").args(["/PID", &m.pid.to_string(), "/F"]).creation_flags(0x0800_0000).stdout(Stdio::null()).status();
}

#[cfg(not(windows))]
fn stop(m: &Mounted) {
    // Unmounting ends the FUSE session, and the frontend exits on its own.
    let unmounted = Command::new("fusermount3").arg("-u").arg(&m.dir).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
        || Command::new("umount").arg(&m.dir).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !unmounted {
        eprintln!("retifs: couldn't unmount {} (fusermount3 -u or umount); stopping the frontend", m.dir.display());
    }
    let started = Instant::now();
    while alive(m.pid) && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(100));
    }
    if alive(m.pid) {
        unsafe { libc::kill(m.pid as i32, libc::SIGTERM) };
    }
}

/// On Haiku a library is a volume of the `retifs` userlandfs module
/// (`retifs-haikufs`): mounted by the kernel, no frontend process to keep.
/// `retifs mount --all` mounts every library this node has (at login: it
/// waits for retifsd first); the record under the store says where.
#[cfg(target_os = "haiku")]
mod haiku {
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use libretifs::{Client, Request, Response};

    use super::{default_dir, mounts_dir};

    /// Whether a volume is mounted at `dir`: it is on another device than
    /// the folder it's in.
    fn is_mounted(dir: &Path) -> bool {
        let (Ok(d), Some(Ok(p))) = (std::fs::metadata(dir), dir.parent().map(std::fs::metadata)) else { return false };
        d.dev() != p.dev()
    }

    /// Every library this node has, waiting up to a minute for retifsd.
    fn namespaces(store: &Path) -> Vec<String> {
        let store = store.to_path_buf();
        // A runtime of its own: the CLI's is busy running this command.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().ok()?;
            rt.block_on(async {
                for _ in 0..60 {
                    if let Ok(mut c) = Client::connect(&store).await
                        && let Ok(Response::Names { names }) = c.call(Request::Namespaces).await
                    {
                        return Some(names);
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                None
            })
        })
        .join()
        .ok()
        .flatten()
        .unwrap_or_default()
    }

    fn recorded(store: &Path) -> Vec<(String, PathBuf)> {
        let Ok(entries) = std::fs::read_dir(mounts_dir(store)) else { return Vec::new() };
        let mut out: Vec<(String, PathBuf)> = entries
            .flatten()
            .filter(|e| e.path().extension().is_none())
            .filter_map(|e| {
                let text = std::fs::read_to_string(e.path()).ok()?;
                let dir = text.lines().nth(1)?;
                Some((e.file_name().to_string_lossy().into_owned(), PathBuf::from(dir)))
            })
            .collect();
        out.sort();
        out
    }

    pub fn mount(store: &Path, args: &[String]) {
        let all = args.iter().any(|a| a == "--all");
        let plain: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
        let names: Vec<String> = if all { namespaces(store) } else { plain.first().map(|n| vec![n.to_string()]).unwrap_or_default() };
        if names.is_empty() {
            let mounts = recorded(store);
            for (ns, dir) in &mounts {
                let state = if is_mounted(dir) { "" } else { "  (not mounted: retifs unmount to clean up)" };
                println!("{ns:<16} {}{state}", dir.display());
            }
            println!("{} mount(s)", mounts.len());
            return;
        }
        let mut failed = false;
        for ns in names {
            let dir = if all { default_dir(&ns) } else { plain.get(1).map(PathBuf::from).unwrap_or_else(|| default_dir(&ns)) };
            if is_mounted(&dir) {
                println!("{ns} is mounted at {}", dir.display());
                continue;
            }
            if let Err(e) = std::fs::create_dir_all(&dir) {
                eprintln!("retifs: {}: {e}", dir.display());
                failed = true;
                continue;
            }
            // The module takes its parameters split at spaces.
            let params = format!("retifs ns={ns} store={}", store.display());
            let ok = Command::new("mount").args(["-t", "userlandfs", "-p", &params]).arg(&dir).status().is_ok_and(|s| s.success());
            if !ok {
                eprintln!("retifs: mounting {ns} at {} failed (/boot/system/var/log/retifs-haikufs.log says why)", dir.display());
                failed = true;
                continue;
            }
            let _ = std::fs::create_dir_all(mounts_dir(store));
            let _ = std::fs::write(mounts_dir(store).join(&ns), format!("0\n{}\n\n", dir.display()));
            println!("{ns} mounted at {}", dir.display());
        }
        if failed && !all {
            std::process::exit(1);
        }
    }

    pub fn unmount(store: &Path, args: &[String]) {
        let Some(ns) = args.iter().find(|a| !a.starts_with("--")) else { super::super::usage() };
        let dir = recorded(store).into_iter().find(|(n, _)| n == ns).map(|(_, d)| d).unwrap_or_else(|| default_dir(ns));
        if is_mounted(&dir) && !Command::new("unmount").arg(&dir).status().is_ok_and(|s| s.success()) {
            super::super::fail(format!("couldn't unmount {}", dir.display()));
        }
        let _ = std::fs::remove_file(mounts_dir(store).join(ns));
        println!("{ns} unmounted from {}", dir.display());
    }
}
