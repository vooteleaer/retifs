//! "Share with retifs…" in Explorer's context menu (ADR-0021): a verb on
//! files and folders inside a retifs sync root that makes a share of them,
//! puts what the recipient needs on the clipboard and says so.
//!
//! The verb is a classic registry verb under HKCU (Windows 11 shows it under
//! "Show more options"), limited to the sync root with `AppliesTo`. A dialog
//! asking who, for how long and which attributes to leave out comes with the
//! desktop utility.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use cloud_filter::{placeholder::Placeholder, root::SyncRootId};
use libretifs::{Client, Request, Response};
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::{
        Foundation::ERROR_FILE_NOT_FOUND,
        System::{
            Console::FreeConsole,
            Registry::{RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ},
        },
        UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK},
    },
};

use crate::names;

const VERB: &str = "Share with retifs\u{2026}";

fn verb_keys(ns: &str) -> [String; 2] {
    let id = format!("retifs.share.{}", ns.replace(['\\', '/'], "_"));
    [format!(r"Software\Classes\*\shell\{id}"), format!(r"Software\Classes\Directory\shell\{id}")]
}

fn set(key: HKEY, name: Option<&str>, value: &str) -> windows::core::Result<()> {
    let wide: Vec<u16> = value.encode_utf16().chain([0]).collect();
    let bytes = unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
    let name = name.map(HSTRING::from);
    unsafe { RegSetValueExW(key, name.as_ref().map_or(PCWSTR::null(), |n| PCWSTR(n.as_ptr())), 0, REG_SZ, Some(bytes)) }.ok()
}

fn create(path: &str) -> windows::core::Result<HKEY> {
    let mut key = HKEY::default();
    unsafe { RegCreateKeyExW(HKEY_CURRENT_USER, &HSTRING::from(path), 0, None, REG_OPTION_NON_VOLATILE, KEY_WRITE, None, &mut key, None) }.ok()?;
    Ok(key)
}

/// Adds the verb for files and folders under `root` (namespace `ns`).
pub fn register(ns: &str, root: &Path, via: Option<&str>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.to_string_lossy().trim_start_matches(r"\\?\").to_string();
    let root = root.to_string_lossy();
    let applies = format!("System.ItemPathDisplay:~<\"{root}\"");
    for path in verb_keys(ns) {
        let result = (|| {
            let key = create(&path)?;
            set(key, Some("MUIVerb"), VERB)?;
            set(key, Some("Icon"), &format!("\"{exe}\",0"))?;
            set(key, Some("AppliesTo"), &applies)?;
            let cmd = create(&format!(r"{path}\command"))?;
            let via = via.map(|v| format!(" --via {v}")).unwrap_or_default();
            set(cmd, None, &format!("\"{exe}\"{via} --share-in \"{ns}\" \"{root}\" \"%1\""))
        })();
        result.map_err(|e| format!("adding {VERB} to Explorer: {e}"))?;
    }
    Ok(())
}

/// Removes the verb for namespace `ns`.
pub fn unregister(ns: &str) {
    for path in verb_keys(ns) {
        let r = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, &HSTRING::from(path.as_str())) };
        if r.is_err() && r != ERROR_FILE_NOT_FOUND {
            eprintln!("retifs-cloudfiles: removing {VERB} from Explorer: {r:?}");
        }
    }
}

/// The retifs sync root `path` is in: (namespace, root). (Asked of the
/// folder: `GetCurrentSyncRoots` lists only the calling package's roots, and
/// this program has no package.)
fn sync_root_of(path: &Path) -> Option<(String, PathBuf)> {
    let dir = if path.is_dir() { path } else { path.parent()? };
    let id = SyncRootId::from_path(dir).ok()?;
    let (provider, _, account) = id.to_components();
    if provider.to_string_lossy() != "retifs" {
        return None;
    }
    let root = id.info().ok()?.path();
    Some((account.to_string_lossy(), root))
}

/// Shares the file or folder at `path`: what "Share with retifs…" runs.
/// Shows the outcome in a message box (or prints it, with
/// `RETIFS_NO_DIALOG` set).
/// `within`: the namespace and sync root, as the verb passes them; None
/// asks the folder (which fails for folders Windows' storage API won't
/// open, e.g. under the hidden AppData).
pub fn share(store: &Path, path: &Path, within: Option<(String, PathBuf)>, via: Option<String>) -> Result<(), String> {
    let quiet = std::env::var_os("RETIFS_NO_DIALOG").is_some();
    if !quiet {
        unsafe { _ = FreeConsole() }; // started by Explorer: no console window
    }
    let result = make_share(store, path, within, via);
    let (title, text, icon) = match &result {
        Ok(text) => ("Shared with retifs", text.clone(), MB_ICONINFORMATION),
        Err(e) => ("Not shared", e.clone(), MB_ICONERROR),
    };
    if quiet {
        println!("{text}");
    } else {
        unsafe { MessageBoxW(None, &HSTRING::from(text), &HSTRING::from(title), MB_OK | icon) };
    }
    result.map(|_| ())
}

fn make_share(store: &Path, path: &Path, within: Option<(String, PathBuf)>, via: Option<String>) -> Result<String, String> {
    let path = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let path = PathBuf::from(path.to_string_lossy().trim_start_matches(r"\\?\"));
    let (ns, root) = match within {
        Some((ns, root)) => (ns, root),
        None => sync_root_of(&path).ok_or_else(|| format!("{} isn't in a retifs folder", path.display()))?,
    };
    if !path.to_string_lossy().to_lowercase().starts_with(&root.to_string_lossy().to_lowercase()) {
        return Err(format!("{} isn't in the retifs folder {}", path.display(), root.display()));
    }
    let rel = path.strip_prefix(&root).map_err(|e| e.to_string())?;
    let tree = names::tree_path(&rel.to_string_lossy());
    let base = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| ns.clone());
    let (terms, ids) = if path.is_dir() {
        let prefix = if tree == "/" { "/".to_string() } else { format!("{tree}/") };
        (vec![format!("path^={prefix}")], vec![])
    } else {
        let info = Placeholder::open(&path).ok().and_then(|ph| crate::provider::identity_of(&ph));
        let id = info.and_then(|blob| names::parse_identity(&blob).map(|(id, _)| id.to_string())).filter(|id| !id.is_empty());
        (vec![], vec![id.ok_or_else(|| format!("{base} isn't in retifs yet (the folder hasn't written it); try again in a moment"))?])
    };

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let mut client = Client::connect(store).await.map_err(|e| format!("retifsd isn't running ({e})"))?.via(via);
        let taken = match client.call(Request::Namespaces).await.map_err(|e| e.to_string())? {
            Response::Names { names } => names,
            _ => Vec::new(),
        };
        let wanted = libretifs::link::suggest_name(&base);
        let name = (1..).map(|i| if i == 1 { wanted.clone() } else { format!("{wanted}-{i}") }).find(|n| !taken.contains(n)).unwrap();
        let req = Request::ShareCreate { source: ns.clone(), name: name.clone(), terms, ids, omit: vec![] };
        let view = match client.call(req).await.map_err(|e| e.to_string())? {
            Response::Namespace(v) => v,
            Response::Error { message } => return Err(message),
            _ => return Err("unexpected answer".into()),
        };
        let node = match client.call(Request::Ping).await.map_err(|e| e.to_string())? {
            Response::Pong { node, .. } => node,
            _ => String::new(),
        };
        let link = libretifs::link::Link::namespace(&view.address, &[node], Some(&base)).to_string();
        let copied = copy_to_clipboard(&link).is_ok();
        Ok(format!(
            "\u{201c}{base}\u{201d} is shared as {name} ({} record{}), kept up to date while it changes.\n\n\
             To give it to someone, send them this link{}:\n\n{link}\n\n\
             They open it with retifs (retifs open LINK). They can read it; nothing else of {ns} is in it.",
            view.records,
            if view.records == 1 { "" } else { "s" },
            if copied { " (it's on the clipboard)" } else { "" },
        ))
    })
}

fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut clip = Command::new("clip.exe").stdin(Stdio::piped()).creation_flags(CREATE_NO_WINDOW).spawn()?;
    clip.stdin.take().unwrap().write_all(text.as_bytes())?;
    clip.wait()?;
    Ok(())
}
