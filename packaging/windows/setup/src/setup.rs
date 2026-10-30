use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows::core::{w, Interface, HSTRING, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::System::Com::*;
use windows::Win32::System::Registry::*;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;

static PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.zst"));
const VERSION: &str = env!("CARGO_PKG_VERSION");
const RUN_KEY: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const UNINSTALL_KEY: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\retifs");
/// Our own programs: stopped before files are replaced or removed.
const PROGRAMS: [&str; 4] = ["retifs-desktop.exe", "retifsd.exe", "prnsd.exe", "retifs-cloudfiles.exe"];
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn install_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_default()).join("Programs").join("retifs")
}

fn shortcut_path() -> PathBuf {
    PathBuf::from(std::env::var_os("APPDATA").unwrap_or_default()).join("Microsoft\\Windows\\Start Menu\\Programs\\retifs.lnk")
}

fn ask(text: &str, flags: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    unsafe { MessageBoxW(None, &HSTRING::from(text), w!("retifs setup"), flags) }
}

pub fn run() {
    if std::env::args().any(|a| a == "--uninstall") {
        uninstall();
    } else {
        install();
    }
}

fn install() {
    let dir = install_dir();
    let quiet = std::env::args().any(|a| a == "--quiet");
    if !quiet
        && ask(
            &format!(
                "Install retifs {VERSION} for this user?\n\nIt goes to {}, starts with your login (in the notification area) and brings Reticulum (prnsd) along, used only where none runs yet.\n\nretifs is a prototype: its formats still change. Keep nothing in it you can't lose.",
                dir.display()
            ),
            MB_OKCANCEL | MB_ICONINFORMATION,
        ) != IDOK
    {
        return;
    }
    match install_files(&dir).and_then(|()| register(&dir)) {
        Ok(()) => {
            // Started now as at login, with its window.
            let _ = Command::new(dir.join("retifs-desktop.exe")).args(["--autostart", "--show"]).spawn();
            if !quiet {
                ask(
                    "retifs is installed and running: its icon is in the notification area.\n\nOn the Network tab, add a connection to a Reticulum node you trust to reach others beyond this network. The retifs command works in a new terminal.",
                    MB_OK | MB_ICONINFORMATION,
                );
            }
        }
        Err(e) => {
            ask(&format!("retifs couldn't be installed:\n\n{e}"), MB_OK | MB_ICONERROR);
        }
    }
}

/// Stops our programs (those in the install folder only by name: another
/// prnsd of the user's, under another name, is left alone).
fn stop_programs() {
    for p in PROGRAMS {
        let _ = Command::new("taskkill").args(["/IM", p, "/F"]).creation_flags_hidden().output();
    }
    std::thread::sleep(std::time::Duration::from_millis(800));
}

trait Hidden {
    fn creation_flags_hidden(&mut self) -> &mut Self;
}

impl Hidden for Command {
    fn creation_flags_hidden(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

fn install_files(dir: &Path) -> Result<(), String> {
    stop_programs();
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut packed = Vec::new();
    zstd::Decoder::new(PAYLOAD).and_then(|mut d| d.read_to_end(&mut packed)).map_err(|e| format!("the installer is damaged: {e}"))?;
    let mut at = 0;
    while at < packed.len() {
        let n = u16::from_le_bytes([packed[at], packed[at + 1]]) as usize;
        let name = String::from_utf8_lossy(&packed[at + 2..at + 2 + n]).into_owned();
        at += 2 + n;
        let len = u64::from_le_bytes(packed[at..at + 8].try_into().unwrap()) as usize;
        at += 8;
        let target = dir.join(&name);
        std::fs::write(&target, &packed[at..at + len]).map_err(|e| format!("{}: {e}", target.display()))?;
        at += len;
    }
    // The installer itself, to uninstall with.
    if let Ok(me) = std::env::current_exe() {
        let _ = std::fs::copy(me, dir.join("retifs-setup.exe"));
    }
    Ok(())
}

unsafe fn set_string(key: HKEY, name: PCWSTR, value: &str) -> Result<(), String> {
    let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
    RegSetValueExW(key, name, 0, REG_SZ, Some(bytes)).ok().map_err(|e| e.to_string())
}

unsafe fn open_key(path: PCWSTR) -> Result<HKEY, String> {
    let mut key = HKEY::default();
    RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, None, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, None, &mut key, None).ok().map_err(|e| e.to_string())?;
    Ok(key)
}

/// The user's PATH (unexpanded, as stored).
unsafe fn user_path() -> String {
    let Ok(key) = open_key(w!("Environment")) else { return String::new() };
    let mut size = 0u32;
    let mut kind = REG_VALUE_TYPE::default();
    let _ = RegQueryValueExW(key, w!("Path"), None, Some(&mut kind), None, Some(&mut size));
    let mut buf = vec![0u16; size as usize / 2 + 1];
    let r = RegQueryValueExW(key, w!("Path"), None, Some(&mut kind), Some(buf.as_mut_ptr() as *mut u8), Some(&mut size));
    let _ = RegCloseKey(key);
    if r.is_err() {
        return String::new();
    }
    String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string()
}

unsafe fn set_user_path(value: &str) -> Result<(), String> {
    let key = open_key(w!("Environment"))?;
    let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
    let r = RegSetValueExW(key, w!("Path"), 0, REG_EXPAND_SZ, Some(bytes)).ok().map_err(|e| e.to_string());
    let _ = RegCloseKey(key);
    // Running programs (Explorer) learn the new PATH.
    let mut result = 0usize;
    let _ = SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, WPARAM(0), LPARAM(w!("Environment").as_ptr() as isize), SMTO_ABORTIFHUNG, 2000, Some(&mut result));
    r
}

fn register(dir: &Path) -> Result<(), String> {
    let d = dir.display().to_string();
    unsafe {
        let run = open_key(RUN_KEY)?;
        set_string(run, w!("retifs"), &format!("\"{d}\\retifs-desktop.exe\" --autostart"))?;
        let _ = RegCloseKey(run);

        let path = user_path();
        if !path.split(';').any(|p| p.eq_ignore_ascii_case(&d)) {
            let new = if path.trim().is_empty() { d.clone() } else { format!("{};{d}", path.trim_end_matches(';')) };
            set_user_path(&new)?;
        }

        let un = open_key(UNINSTALL_KEY)?;
        set_string(un, w!("DisplayName"), "retifs")?;
        set_string(un, w!("DisplayVersion"), VERSION)?;
        set_string(un, w!("Publisher"), "retifs")?;
        set_string(un, w!("InstallLocation"), &d)?;
        set_string(un, w!("DisplayIcon"), &format!("{d}\\retifs-desktop.exe"))?;
        set_string(un, w!("UninstallString"), &format!("\"{d}\\retifs-setup.exe\" --uninstall"))?;
        set_string(un, w!("URLInfoAbout"), "https://github.com/vooteleaer/retifs")?;
        let one = 1u32.to_le_bytes();
        let _ = RegSetValueExW(un, w!("NoModify"), 0, REG_DWORD, Some(&one));
        let _ = RegSetValueExW(un, w!("NoRepair"), 0, REG_DWORD, Some(&one));
        let _ = RegCloseKey(un);

        shortcut(&dir.join("retifs-desktop.exe"), &shortcut_path())?;
    }
    Ok(())
}

/// A Start menu shortcut (a .lnk, through the shell's own IShellLink).
unsafe fn shortcut(target: &Path, at: &Path) -> Result<(), String> {
    let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(|e| e.to_string())?;
    link.SetPath(&HSTRING::from(target.as_os_str())).map_err(|e| e.to_string())?;
    link.SetDescription(w!("retifs: this device, its libraries and how they're kept")).map_err(|e| e.to_string())?;
    if let Some(parent) = target.parent() {
        let _ = link.SetWorkingDirectory(&HSTRING::from(parent.as_os_str()));
    }
    let file: IPersistFile = link.cast().map_err(|e| e.to_string())?;
    if let Some(parent) = at.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    file.Save(&HSTRING::from(at.as_os_str()), true).map_err(|e| e.to_string())
}

fn uninstall() {
    let dir = install_dir();
    if ask(
        "Uninstall retifs?\n\nIts programs are removed. Your data stays: the store in %LOCALAPPDATA%\\retifs and Reticulum's settings in %USERPROFILE%\\.reticulum (delete them yourself if you no longer want them).",
        MB_OKCANCEL | MB_ICONQUESTION,
    ) != IDOK
    {
        return;
    }
    stop_programs();
    let d = dir.display().to_string();
    unsafe {
        if let Ok(run) = open_key(RUN_KEY) {
            let _ = RegDeleteValueW(run, w!("retifs"));
            let _ = RegCloseKey(run);
        }
        let path = user_path();
        let kept: Vec<&str> = path.split(';').filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case(&d)).collect();
        if kept.len() != path.split(';').filter(|p| !p.is_empty()).count() {
            let _ = set_user_path(&kept.join(";"));
        }
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, UNINSTALL_KEY);
    }
    let _ = std::fs::remove_file(shortcut_path());
    // Every file but the running uninstaller, which a hidden shell removes
    // with the folder once this has exited.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if e.file_name() != "retifs-setup.exe" {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let _ = Command::new("cmd").args(["/C", &format!("ping -n 3 127.0.0.1 >nul & rmdir /S /Q \"{d}\"")]).creation_flags_hidden().spawn();
    ask("retifs is uninstalled. Your data is still there.", MB_OK | MB_ICONINFORMATION);
}
