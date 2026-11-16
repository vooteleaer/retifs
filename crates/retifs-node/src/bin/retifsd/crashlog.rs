//! Crash and trouble reports (ADR-0036): what went wrong on this node, kept
//! until it can go into a library its owner reads (by default
//! `retifs-crashlogs`, once this node has joined it with a write grant).
//!
//! - The daemon's output (stdout and stderr) goes through a pipe: passed on
//!   as before, and also kept as the last lines in memory and in
//!   `<store>/crash/log` (the previous one in `log.prev`, about 1 MB each).
//! - A panic writes a report at once, from the panic hook.
//! - A run that didn't stop cleanly (killed, out of memory, a native crash:
//!   nothing in the process could report it) is found at the next start, by
//!   the `running` marker it left, and reported with the end of its log.
//! - Other trouble (the shared instance gone for minutes) and reports from
//!   apps and the user are written the same way.
//!
//! Reports wait in `<store>/crash/pending/` as text files; the daemon moves
//! them into the library (see `retifsd::crash_reports`).

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// Lines of output kept in memory for reports.
const TAIL_LINES: usize = 400;
/// The log file is started again (the old one kept as `log.prev`) beyond this.
const LOG_MAX: u64 = 1 << 20;
/// Reports one run may write from panics (a panic in a loop doesn't fill the disk).
const PANIC_REPORTS_MAX: usize = 10;
/// Pending reports kept at most (the oldest dropped): a node that can't
/// deliver them doesn't fill its disk.
const PENDING_MAX: usize = 100;
/// A report's text at most (an app's report included).
pub const REPORT_MAX: usize = 256 << 10;

static TAIL: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
static LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);
static DIR: OnceLock<PathBuf> = OnceLock::new();
static DEVICE: OnceLock<String> = OnceLock::new();
static PANICS: AtomicUsize = AtomicUsize::new(0);

/// Starts keeping the output and reporting panics; reports the previous run
/// if it didn't stop cleanly. Called once, first thing.
pub fn install(store: &Path, device: &str) {
    let dir = store.join("crash");
    let _ = std::fs::create_dir_all(dir.join("pending"));
    let _ = DIR.set(dir.clone());
    let _ = DEVICE.set(device.to_string());
    let log = dir.join("log");
    let prev = dir.join("log.prev");
    if log.exists() {
        let _ = std::fs::rename(&log, &prev);
    }
    *LOG.lock().unwrap() = std::fs::OpenOptions::new().create(true).append(true).open(&log).ok();
    capture_output();

    let running = dir.join("running");
    if let Ok(was) = std::fs::read_to_string(&running) {
        // A panic that ended the run reported itself already.
        if !was.contains("panicked") {
            let tail = last_lines(&std::fs::read_to_string(&prev).unwrap_or_default(), TAIL_LINES);
            let started = was.lines().next().unwrap_or("").trim();
            write_pending(
                "unclean_stop",
                "retifsd",
                &format!(
                    "The previous run (started {started}) didn't stop cleanly: it was killed, ran out of memory or crashed outside Rust.\n\n--- the end of its log ---\n{tail}"
                ),
                false,
            );
        }
    }
    let _ = std::fs::write(&running, format!("{}\n", stamp(now_ms())));

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        if PANICS.fetch_add(1, Ordering::Relaxed) >= PANIC_REPORTS_MAX {
            return;
        }
        let thread = std::thread::current().name().unwrap_or("unnamed").to_string();
        let trace = std::backtrace::Backtrace::force_capture();
        write_pending("panic", "retifsd", &format!("thread '{thread}' {info}\n\n--- backtrace ---\n{trace}"), true);
        if let Some(dir) = DIR.get() {
            let _ = std::fs::OpenOptions::new().append(true).open(dir.join("running")).and_then(|mut f| f.write_all(b"panicked\n"));
        }
    }));
}

/// The run stopped cleanly: nothing to report at the next start.
pub fn stopped_cleanly() {
    if let Some(dir) = DIR.get() {
        let _ = std::fs::remove_file(dir.join("running"));
    }
}

/// Writes a report to wait in `pending/`: `kind` (`panic`, `unclean_stop`,
/// `no_network`, `app_crash`, `user`), from `source` (`retifsd`, an app's
/// name), with the daemon's last output lines after `text` when `tail`.
/// Returns the file's name.
pub fn write_pending(kind: &str, source: &str, text: &str, tail: bool) -> Option<String> {
    let dir = DIR.get()?.join("pending");
    let now = now_ms();
    let kind = clean(kind);
    let source = clean(source);
    let mut body = format!(
        "kind: {kind}\nsource: {source}\ntime: {}\ndevice: {}\nversion: retifsd {}\nos: {} {}\n\n",
        stamp(now),
        DEVICE.get().map(String::as_str).unwrap_or(""),
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    body.push_str(text.get(..floor_char(text, REPORT_MAX)).unwrap_or(text));
    if tail {
        body.push_str("\n\n--- retifsd's last output ---\n");
        body.push_str(&TAIL.lock().map(|t| t.iter().cloned().collect::<Vec<_>>().join("\n")).unwrap_or_default());
    }
    body.push('\n');
    let name = format!("{now}-{kind}-{source}.txt");
    // Written whole, then renamed: a half-written report is never picked up.
    let part = dir.join(format!(".{name}.part"));
    std::fs::write(&part, body).ok()?;
    std::fs::rename(&part, dir.join(&name)).ok()?;
    prune_pending(&dir);
    Some(name)
}

/// The reports waiting, oldest first.
pub fn pending() -> Vec<PathBuf> {
    let Some(dir) = DIR.get() else { return Vec::new() };
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir.join("pending"))
        .map(|r| r.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "txt")).collect())
        .unwrap_or_default();
    files.sort();
    files
}

/// What a pending report's name says: (time in ms, kind, source).
pub fn parse_name(name: &str) -> Option<(u64, String, String)> {
    let stem = name.strip_suffix(".txt")?;
    let (ms, rest) = stem.split_once('-')?;
    let (kind, source) = rest.split_once('-').unwrap_or((rest, ""));
    Some((ms.parse().ok()?, kind.to_string(), source.to_string()))
}

fn prune_pending(dir: &Path) {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir).map(|r| r.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "txt")).collect()).unwrap_or_default();
    if files.len() <= PENDING_MAX {
        return;
    }
    files.sort();
    for old in &files[..files.len() - PENDING_MAX] {
        let _ = std::fs::remove_file(old);
    }
}

/// Names in file names: letters, digits, `.` and `_` (a `-` separates the parts).
fn clean(s: &str) -> String {
    let c: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' { c } else { '_' }).take(40).collect();
    if c.is_empty() { "unknown".into() } else { c }
}

fn floor_char(s: &str, max: usize) -> usize {
    if s.len() <= max {
        return s.len();
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// `2026-11-13 08:58:16 UTC`.
pub fn stamp(ms: u64) -> String {
    let s = ms / 1000;
    let (days, rem) = (s / 86400, s % 86400);
    // Civil date from days since 1970 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// One line of output: kept in memory and in the log file.
fn keep(line: &str) {
    if let Ok(mut t) = TAIL.lock() {
        if t.len() >= TAIL_LINES {
            t.pop_front();
        }
        t.push_back(line.to_string());
    }
    let Ok(mut log) = LOG.lock() else { return };
    let Some(f) = log.as_mut() else { return };
    let _ = writeln!(f, "{} {line}", stamp(now_ms()).trim_end_matches(" UTC"));
    if f.metadata().map(|m| m.len()).unwrap_or(0) > LOG_MAX {
        if let Some(dir) = DIR.get() {
            let _ = std::fs::rename(dir.join("log"), dir.join("log.prev"));
            *log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("log")).ok();
        }
    }
}

/// Reads `from` line by line: each passed on to `to` (where the output went
/// before) and kept.
fn tee(from: impl Read + Send + 'static, mut to: Option<std::fs::File>) {
    let _ = std::thread::Builder::new().name("output".into()).spawn(move || {
        let mut r = BufReader::new(from);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    if let Some(t) = to.as_mut() {
                        if t.write_all(&buf).is_err() {
                            to = None;
                        }
                    }
                    keep(String::from_utf8_lossy(&buf).trim_end_matches(['\n', '\r']));
                }
            }
        }
    });
}

#[cfg(unix)]
fn capture_output() {
    use std::os::fd::FromRawFd;
    for fd in [1, 2] {
        let mut ends = [0; 2];
        // SAFETY: plain descriptor calls; on any failure that output stays as it was.
        unsafe {
            if libc::pipe(ends.as_mut_ptr()) != 0 {
                continue;
            }
            let before = libc::dup(fd);
            if libc::dup2(ends[1], fd) < 0 {
                libc::close(ends[0]);
                libc::close(ends[1]);
                if before >= 0 {
                    libc::close(before);
                }
                continue;
            }
            libc::close(ends[1]);
            libc::fcntl(ends[0], libc::F_SETFD, libc::FD_CLOEXEC);
            let to = (before >= 0).then(|| {
                libc::fcntl(before, libc::F_SETFD, libc::FD_CLOEXEC);
                std::fs::File::from_raw_fd(before)
            });
            tee(std::fs::File::from_raw_fd(ends[0]), to);
        }
    }
}

#[cfg(windows)]
fn capture_output() {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{GetStdHandle, SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    use windows_sys::Win32::System::Pipes::CreatePipe;
    for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: Win32 calls on handles made here; Rust's stdout and stderr
        // look the standard handles up at every write.
        unsafe {
            let before = GetStdHandle(which);
            if CreatePipe(&mut read, &mut write, std::ptr::null(), 0) == 0 {
                continue;
            }
            if SetStdHandle(which, write) == 0 {
                continue;
            }
            // No console (started hidden): nowhere to pass it on to.
            let to = (!before.is_null() && before != INVALID_HANDLE_VALUE).then(|| std::fs::File::from_raw_handle(before as _));
            tee(std::fs::File::from_raw_handle(read as _), to);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn capture_output() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps() {
        assert_eq!(stamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(stamp(1_794_531_656_384), "2026-11-13 01:00:56 UTC");
    }

    #[test]
    fn names() {
        assert_eq!(parse_name("1794531656384-panic-retifsd.txt"), Some((1_794_531_656_384, "panic".into(), "retifsd".into())));
        assert_eq!(parse_name("1-app_crash-org.retifs.music.txt"), Some((1, "app_crash".into(), "org.retifs.music".into())));
        assert_eq!(clean("app-crash"), "app_crash");
        assert_eq!(clean(""), "unknown");
    }
}
