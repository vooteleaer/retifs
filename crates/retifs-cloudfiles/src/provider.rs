//! The Cloud Files provider (ADR-0002): a namespace as a sync root. Records
//! are placeholders; opening one reads its content from the daemon
//! (`ReadRange`); Explorer's "Always keep on this device" and "Free up space"
//! set and clear this device's keep tag. Read-only for now: changes made in
//! the folder aren't written back yet, and deleting or renaming is refused.
//!
//! Like the FUSE mount it holds no keys and no store; `retifsd` does.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

use cloud_filter::{
    error::{CResult, CloudErrorKind},
    filter::{info, ticket, Request as CfRequest, SyncFilter},
    metadata::Metadata,
    placeholder::{PinOptions, PinState, Placeholder, UpdateOptions},
    placeholder_file::PlaceholderFile,
    root::{HydrationType, PopulationType, ProtectionMode, SecurityId, Session, SyncRootIdBuilder, SyncRootId, SyncRootInfo},
    utility::WriteAt,
};
use libretifs::{AttrValue, Client, RecordView, Request, Response};
use retifs_tree::Tree;

use crate::names::{self, Want};

const PROVIDER: &str = "retifs";
/// Content is read from the daemon in pieces this large (a multiple of 4 KiB,
/// as Cloud Files wants every piece but the last).
const PIECE: u64 = 4 << 20;
/// Without a change notice, the namespace is re-read at least this often.
const RESYNC: Duration = Duration::from_secs(60);

/// A blocking client of the local API that reconnects after errors.
struct Daemon {
    store: PathBuf,
    rt: tokio::runtime::Runtime,
    client: Option<Client>,
}

impl Daemon {
    fn new(store: &Path) -> Result<Daemon, String> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        Ok(Daemon { store: store.to_path_buf(), rt, client: None })
    }

    fn call(&mut self, req: Request) -> Result<Response, String> {
        if self.client.is_none() {
            let c = self.rt.block_on(Client::connect(&self.store)).map_err(|e| format!("can't reach retifsd at {}: {e}", self.store.display()))?;
            self.client = Some(c);
        }
        match self.rt.block_on(self.client.as_mut().unwrap().call(req)) {
            Ok(Response::Error { message }) => Err(message),
            Ok(r) => Ok(r),
            Err(e) => {
                self.client = None;
                Err(format!("retifsd: {e}"))
            }
        }
    }

    fn records(&mut self, ns: &str) -> Result<Vec<RecordView>, String> {
        match self.call(Request::Query { ns: ns.to_string(), terms: Vec::new(), at: None })? {
            Response::Records { records } => Ok(records),
            _ => Err("unexpected answer to Query".into()),
        }
    }

    fn device(&mut self, ns: &str) -> Result<String, String> {
        match self.call(Request::NsInfo { ns: ns.to_string() })? {
            Response::Namespace(v) => Ok(v.device),
            _ => Err("unexpected answer to NsInfo".into()),
        }
    }
}

/// The callbacks Windows makes into the provider, on threads of its own.
struct Filter {
    ns: String,
    device: String,
    wait: Duration,
    daemon: Mutex<Daemon>,
    /// Which records this device keeps (`keep:<device>`), as last read.
    kept: Arc<Mutex<HashMap<String, bool>>>,
    hydrate: Mutex<mpsc::Sender<PathBuf>>,
}

fn own_process(req: &CfRequest) -> bool {
    req.process().id() == std::process::id()
}

impl SyncFilter for Filter {
    fn fetch_data(&self, req: CfRequest, ticket: ticket::FetchData, info: info::FetchData) -> CResult<()> {
        let (_, cap) = names::parse_identity(req.file_blob()).ok_or(CloudErrorKind::InvalidRequest)?;
        let cap = cap.ok_or(CloudErrorKind::Unsuccessful)?;
        let size = req.file_size();
        let range = info.required_file_range();
        eprintln!("retifs-cloudfiles: {}: fetching {}..{} of {size} for process {}", req.path().display(), range.start, range.end, req.process().id());
        let end = (range.end.div_ceil(4096) * 4096).min(size);
        let mut pos = range.start;
        while pos < end {
            let len = PIECE.min(end - pos);
            let read = Request::ReadRange { cap: cap.to_string(), ns: Some(self.ns.clone()), offset: pos, len, wait_ms: self.wait.as_millis() as u64 };
            let data = match self.daemon.lock().unwrap().call(read) {
                Ok(Response::Range { data }) if data.len() as u64 == len => data,
                Ok(_) => {
                    eprintln!("retifs-cloudfiles: {}: short read at {pos}", req.path().display());
                    return Err(CloudErrorKind::Unsuccessful);
                }
                Err(e) => {
                    eprintln!("retifs-cloudfiles: {}: {e}", req.path().display());
                    return Err(CloudErrorKind::NetworkUnavailable);
                }
            };
            ticket.write_at(&data, pos).map_err(|e| {
                eprintln!("retifs-cloudfiles: {}: {e}", req.path().display());
                CloudErrorKind::Unsuccessful
            })?;
            pos += len;
            _ = ticket.report_progress(size, pos);
        }
        Ok(())
    }

    fn dehydrate(&self, _req: CfRequest, ticket: ticket::Dehydrate, _info: info::Dehydrate) -> CResult<()> {
        // The content stays in the daemon (and on other nodes), so freeing
        // this copy loses nothing.
        ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful)
    }

    fn delete(&self, req: CfRequest, ticket: ticket::Delete, _info: info::Delete) -> CResult<()> {
        if own_process(&req) {
            return ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful);
        }
        eprintln!("retifs-cloudfiles: refused deleting {} (the folder is read-only for now)", req.path().display());
        Err(CloudErrorKind::AccessDenied)
    }

    fn rename(&self, req: CfRequest, ticket: ticket::Rename, _info: info::Rename) -> CResult<()> {
        if own_process(&req) {
            return ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful);
        }
        eprintln!("retifs-cloudfiles: refused renaming {} (the folder is read-only for now)", req.path().display());
        Err(CloudErrorKind::AccessDenied)
    }

    /// Pin states changed: "Always keep on this device" pins, "Free up
    /// space" unpins. They become this device's keep tag.
    fn state_changed(&self, changes: Vec<PathBuf>) {
        for path in changes {
            if path.is_dir() {
                continue;
            }
            let Some(info) = Placeholder::open(&path).ok().and_then(|ph| info(&ph)) else { continue };
            let Some((id, _)) = names::parse_identity(&info.blob) else { continue };
            let id = id.to_string();
            let want = match info.pin {
                PinState::Pinned => true,
                PinState::Unpinned => false,
                _ => continue,
            };
            let hydrated = info.on_disk > 0;
            let has = self.kept.lock().unwrap().get(&id).copied().unwrap_or(false);
            if want != has {
                let key = format!("keep:{}", self.device);
                let (attrs, unset) = if want { (vec![(key, AttrValue::Bool(true))], vec![]) } else { (vec![], vec![key]) };
                match self.daemon.lock().unwrap().call(Request::RecordSet { ns: self.ns.clone(), id: id.clone(), attrs, unset, data: None }) {
                    Ok(_) => {
                        self.kept.lock().unwrap().insert(id, want);
                    }
                    Err(e) => eprintln!("retifs-cloudfiles: {}: keep: {e}", path.display()),
                }
            }
            if want {
                _ = self.hydrate.lock().unwrap().send(path);
            } else if hydrated
                && let Err(e) = open_rw(&path).and_then(|mut ph| ph.update(UpdateOptions::default().dehydrate(), None).map(|_| ()))
            {
                eprintln!("retifs-cloudfiles: {}: free up space: {e}", path.display());
            }
        }
    }
}

fn root_id(ns: &str) -> Result<SyncRootId, String> {
    let sid = SecurityId::current_user().map_err(|e| e.to_string())?;
    Ok(SyncRootIdBuilder::new(PROVIDER).user_security_id(sid).account_name(ns.replace('!', "_")).build())
}

fn register(id: &SyncRootId, ns: &str, folder: &Path) -> Result<(), String> {
    if id.is_registered().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let info = SyncRootInfo::default()
        .with_display_name(format!("retifs {ns}"))
        .with_path(folder)
        .map_err(|e| format!("{}: {e}", folder.display()))?
        .with_population_type(PopulationType::AlwaysFull)
        .with_hydration_type(HydrationType::Full)
        .with_protection_mode(ProtectionMode::Personal)
        .with_allow_pinning(true)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_icon("%SystemRoot%\\system32\\imageres.dll,-1043");
    id.register(info).map_err(|e| format!("registering the sync root: {e}"))
}

/// Unregisters namespace `ns`'s sync root. Its placeholders stay as they
/// are (Windows leaves them); hydrated files keep their content.
pub fn unregister(ns: &str) -> Result<(), String> {
    // Not `is_registered` first: it says no once the folder is gone, though
    // the registration is still there.
    root_id(ns)?.unregister().map_err(|e| format!("no sync root for namespace {ns}? {e}"))?;
    eprintln!("retifs-cloudfiles: unregistered namespace {ns}");
    Ok(())
}

fn filetime(ms: i64) -> nt_time::FileTime {
    // 100 ns ticks since 1601-01-01.
    let ticks = (ms.max(0) as u64 + 11_644_473_600_000) * 10_000;
    nt_time::FileTime::new(ticks)
}

/// Size and times.
fn metadata(w: &Want) -> Metadata {
    let base = if w.dir { Metadata::directory() } else { Metadata::file().size(w.size) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    let t = filetime(w.mtime_ms.unwrap_or(now));
    base.written(t).changed(t).created(t).accessed(t)
}

pub fn run(store: &Path, ns: &str, folder: &Path, wait: Duration) -> Result<(), String> {
    if !cloud_filter::root::is_supported().unwrap_or(false) {
        return Err("Cloud Files isn't supported on this Windows".into());
    }
    fs::create_dir_all(folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    let folder = fs::canonicalize(folder).map_err(|e| e.to_string())?;
    let folder = PathBuf::from(folder.to_string_lossy().trim_start_matches(r"\\?\"));
    let mut daemon = Daemon::new(store)?;
    let device = daemon.device(ns)?;
    let id = root_id(ns)?;
    register(&id, ns, &folder)?;

    let kept = Arc::new(Mutex::new(HashMap::new()));
    let (hydrate_tx, hydrate_rx) = mpsc::channel::<PathBuf>();
    let filter = Filter { ns: ns.to_string(), device: device.clone(), wait, daemon: Mutex::new(Daemon::new(store)?), kept: kept.clone(), hydrate: Mutex::new(hydrate_tx.clone()) };
    let _connection = Session::new().connect(&folder, filter).map_err(|e| format!("connecting the sync root: {e}"))?;
    // Pinned files are hydrated one at a time, off the callback threads.
    std::thread::spawn(move || {
        for path in hydrate_rx {
            if let Ok(mut ph) = Placeholder::open(&path)
                && let Err(e) = ph.hydrate(..)
            {
                eprintln!("retifs-cloudfiles: {}: keeping: {e}", path.display());
            }
        }
    });
    eprintln!("retifs-cloudfiles: namespace {ns} in {} (device {device}; Ctrl+C stops it, --unregister removes it)", folder.display());

    let changed = watch(store, ns);
    let sync = Sync { root: folder, hydrate: hydrate_tx };
    loop {
        match daemon.records(ns) {
            Ok(records) => {
                *kept.lock().unwrap() = records.iter().map(|r| (r.id.clone(), is_kept(r, &device))).collect();
                let plan = names::plan(&Tree::build(&records), &records, &device);
                for p in &plan.skipped {
                    eprintln!("retifs-cloudfiles: {p}: not a Windows name, or another entry has it in other case; not shown");
                }
                sync.reconcile(&plan);
            }
            Err(e) => eprintln!("retifs-cloudfiles: {e}"),
        }
        _ = changed.recv_timeout(RESYNC);
        while changed.try_recv().is_ok() {}
    }
}

fn is_kept(r: &RecordView, device: &str) -> bool {
    let own = format!("keep:{device}");
    r.attrs.iter().any(|(k, v)| *k == own && *v == AttrValue::Bool(true))
}

/// Watches namespace `ns` on a thread of its own (a long poll on the local
/// API) and sends on every change.
fn watch(store: &Path, ns: &str) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    let (store, ns) = (store.to_path_buf(), ns.to_string());
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
        let mut since = 0;
        loop {
            let Ok(mut client) = rt.block_on(Client::connect(&store)) else {
                std::thread::sleep(Duration::from_secs(5)); // the daemon restarting
                continue;
            };
            while let Ok(Response::Changed { count }) = rt.block_on(client.call(Request::Watch { ns: ns.clone(), since, timeout_ms: 30_000 })) {
                if count != since {
                    since = count;
                    if tx.send(()).is_err() {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    rx
}

/// Makes the folder match a plan.
struct Sync {
    root: PathBuf,
    hydrate: mpsc::Sender<PathBuf>,
}

impl Sync {
    fn reconcile(&self, plan: &names::Plan) {
        self.sweep(Path::new(""), plan);
        for w in &plan.wants {
            let abs = self.root.join(&w.rel);
            if fs::symlink_metadata(&abs).is_err() {
                self.create(&abs, w, false);
            }
        }
    }

    /// Creates `w`'s placeholder at `abs`, or replaces the one there
    /// (`replace`). New content is a new placeholder: `CfUpdatePlaceholder`
    /// keeps the old size, and a superseding create reads back zeros where
    /// the old content was hydrated.
    fn create(&self, abs: &Path, w: &Want, replace: bool) {
        if replace && let Err(e) = fs::remove_file(abs) {
            eprintln!("retifs-cloudfiles: {}: replacing: {e}", abs.display());
            return;
        }
        let parent = abs.parent().unwrap_or(&self.root);
        let name = abs.file_name().unwrap_or_default();
        let mut ph = PlaceholderFile::new(name).metadata(metadata(w)).blob(w.blob.clone()).mark_in_sync();
        if w.dir {
            ph = ph.has_no_children(); // all placeholders are made up front
        }
        match ph.create::<&Path>(parent) {
            Ok(_) => self.pin(abs, w),
            Err(e) => eprintln!("retifs-cloudfiles: {}: {e}", abs.display()),
        }
    }

    /// Walks what's on disk under `rel`: updates placeholders whose record
    /// changed, removes those whose record is gone (directories once empty),
    /// leaves files that aren't placeholders alone. True if `rel` is now empty.
    fn sweep(&self, rel: &Path, plan: &names::Plan) -> bool {
        let Ok(entries) = fs::read_dir(self.root.join(rel)) else { return false };
        let mut empty = true;
        for e in entries.flatten() {
            let r = rel.join(e.file_name());
            let abs = self.root.join(&r);
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let key = r.to_string_lossy().to_lowercase();
            match plan.index.get(&key).map(|&i| &plan.wants[i]) {
                Some(w) if w.dir == is_dir => {
                    empty = false;
                    if is_dir {
                        self.sweep(&r, plan);
                    } else {
                        self.refresh(&abs, w);
                    }
                }
                Some(_) => {
                    empty = false;
                    eprintln!("retifs-cloudfiles: {}: a file where a folder should be (or the other way); left alone", abs.display());
                }
                None if is_dir => {
                    if self.sweep(&r, plan) && is_placeholder(&abs) {
                        if let Err(err) = fs::remove_dir(&abs) {
                            empty = false;
                            eprintln!("retifs-cloudfiles: {}: {err}", abs.display());
                        }
                    } else {
                        empty = false;
                    }
                }
                None => match placeholder_state(&abs) {
                    Some((true, _)) => {
                        if let Err(err) = fs::remove_file(&abs) {
                            empty = false;
                            eprintln!("retifs-cloudfiles: {}: {err}", abs.display());
                        }
                    }
                    Some((false, _)) => {
                        empty = false;
                        eprintln!("retifs-cloudfiles: {}: its record is gone, but it has local changes; left alone", abs.display());
                    }
                    None => empty = false,
                },
            }
        }
        empty
    }

    /// A placeholder whose record may have changed: new content or times.
    fn refresh(&self, abs: &Path, w: &Want) {
        let Some((in_sync, blob)) = placeholder_state(abs) else {
            eprintln!("retifs-cloudfiles: {}: a local file at a path retifs has; left alone", abs.display());
            return;
        };
        if blob != w.blob {
            if !in_sync {
                eprintln!("retifs-cloudfiles: {}: changed here and in retifs; left alone (writing back comes later)", abs.display());
                return;
            }
            self.create(abs, w, true);
            return;
        }
        self.pin(abs, w);
    }

    /// Kept here: pinned and hydrated. No longer kept: no longer pinned
    /// (the content stays until Windows or the user frees it).
    fn pin(&self, abs: &Path, w: &Want) {
        if w.dir {
            return;
        }
        // Read-only first: a handle with write access would make others'
        // opens fail while it's open.
        let pinned = matches!(Placeholder::open(abs).ok().and_then(|ph| info(&ph)), Some(i) if i.pin == PinState::Pinned);
        if w.keep == pinned {
            return;
        }
        let Ok(mut ph) = open_rw(abs) else { return };
        if w.keep {
            if ph.mark_pin(PinState::Pinned, PinOptions::default()).is_ok() {
                _ = self.hydrate.send(abs.to_path_buf());
            }
        } else {
            _ = ph.mark_pin(PinState::Unspecified, PinOptions::default());
        }
    }
}

/// A placeholder opened for changing it: an ordinary Win32 handle with write
/// access (`CfUpdatePlaceholder` refuses the protected handles of
/// `Placeholder::options().write_access()`). Opening doesn't hydrate it.
fn open_rw(abs: &Path) -> windows::core::Result<Placeholder> {
    fs::OpenOptions::new().write(true).open(abs).map(Placeholder::from).map_err(|e| {
        windows::core::Error::from(windows::core::HRESULT::from_win32(e.raw_os_error().unwrap_or(0) as u32))
    })
}

struct Info {
    in_sync: bool,
    pin: PinState,
    on_disk: i64,
    blob: Vec<u8>,
}

/// A placeholder's state and identity; None for an ordinary file. (Read
/// here rather than through `Placeholder::info`, whose blob starts at the
/// struct's size instead of its `FileIdentity` field.)
fn info(ph: &Placeholder) -> Option<Info> {
    use windows::Win32::Storage::CloudFilters::{CfGetPlaceholderInfo, CF_IN_SYNC_STATE_IN_SYNC, CF_PLACEHOLDER_INFO_STANDARD, CF_PLACEHOLDER_STANDARD_INFO};
    let handle = ph.win32_handle().ok()?;
    let mut buf = vec![0u64; (std::mem::size_of::<CF_PLACEHOLDER_STANDARD_INFO>() + 4096).div_ceil(8)];
    let mut len = 0u32;
    unsafe { CfGetPlaceholderInfo(handle.handle(), CF_PLACEHOLDER_INFO_STANDARD, buf.as_mut_ptr() as *mut _, (buf.len() * 8) as u32, Some(&mut len)) }.ok()?;
    let std_info = unsafe { &*(buf.as_ptr() as *const CF_PLACEHOLDER_STANDARD_INFO) };
    let at = std::mem::offset_of!(CF_PLACEHOLDER_STANDARD_INFO, FileIdentity);
    let n = (std_info.FileIdentityLength as usize).min(len as usize - at);
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 8) };
    Some(Info {
        in_sync: std_info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC,
        pin: std_info.PinState.into(),
        on_disk: std_info.OnDiskDataSize,
        blob: bytes[at..at + n].to_vec(),
    })
}

fn is_placeholder(abs: &Path) -> bool {
    Placeholder::open(abs).ok().and_then(|ph| info(&ph)).is_some()
}

/// (in sync, identity) of a placeholder; None for an ordinary file.
fn placeholder_state(abs: &Path) -> Option<(bool, Vec<u8>)> {
    let i = info(&Placeholder::open(abs).ok()?)?;
    Some((i.in_sync, i.blob))
}
