//! `retifs mount` and `retifs unmount` (ADR-0002): a namespace's file tree
//! through this platform's frontend, `retifs-mount` (FUSE) on Linux and
//! `retifs-cloudfiles` (a Cloud Files sync root) on Windows, started in the
//! background. Which namespaces are mounted where, and by which process, is
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

/// Where a namespace is mounted unless told otherwise: `~/retifs/<ns>`.
fn default_dir(ns: &str) -> PathBuf {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap_or_else(|| ".".into());
    home.join("retifs").join(ns)
}

struct Mounted {
    ns: String,
    pid: u32,
    dir: PathBuf,
}

fn read(store: &Path, ns: &str) -> Option<Mounted> {
    let text = std::fs::read_to_string(mounts_dir(store).join(ns)).ok()?;
    let mut lines = text.lines();
    let pid = lines.next()?.parse().ok()?;
    let dir = PathBuf::from(lines.next()?);
    Some(Mounted { ns: ns.to_string(), pid, dir })
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

/// `retifs mount`: with no namespace, lists the mounts.
pub fn mount(store: &Path, args: &[String]) {
    let foreground = args.iter().any(|a| a == "--foreground");
    let rest: Vec<&String> = args.iter().filter(|a| *a != "--foreground").collect();
    let Some(ns) = rest.first() else {
        let mounts = all(store);
        for m in &mounts {
            let state = if alive(m.pid) { "" } else { "  (not running: retifs unmount to clean up)" };
            println!("{:<16} {}{state}", m.ns, m.dir.display());
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
    cmd.arg("--store").arg(store).arg(ns.as_str()).arg(&dir);
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
    std::fs::write(mounts_dir(store).join(ns.as_str()), format!("{pid}\n{}\n", dir.display())).unwrap_or_else(|e| super::fail(e));
    // Up once the frontend says so; a frontend that stops has failed.
    let ready = if cfg!(windows) { "retifs-cloudfiles: namespace" } else { "retifs-mount: namespace" };
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
    println!("{ns} mounted at {}", dir.display());
    println!("  log {}; retifs unmount {ns} to stop", log.display());
}

/// `retifs unmount NS [--forget]`.
pub fn unmount(store: &Path, args: &[String]) {
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
