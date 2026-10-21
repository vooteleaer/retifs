//! The Cloud Files provider (ADR-0002): a namespace as a sync root. Records
//! are placeholders; opening one reads its content from the daemon
//! (`ReadRange`). Files added or changed in the folder are written back as
//! records and versions, deletes and renames as record deletes and path
//! changes. Explorer's "Always keep on this device" and "Free up space" set
//! and clear this device's keep tag.
//!
//! Like the FUSE mount it holds no keys and no store; `retifsd` does.

use std::{
    collections::HashMap,
    fs,
    io::Read,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cloud_filter::{
    error::{CResult, CloudErrorKind},
    filter::{info, ticket, Request as CfRequest, SyncFilter},
    metadata::Metadata,
    placeholder::{ConvertOptions, PinOptions, PinState, Placeholder, UpdateOptions},
    placeholder_file::PlaceholderFile,
    root::{HydrationType, PopulationType, ProtectionMode, SecurityId, Session, SyncRootIdBuilder, SyncRootId, SyncRootInfo},
    utility::WriteAt,
};
use libretifs::{AttrValue, Client, RecordView, Request, Response, TxStep};
use retifs_tree::Tree;

use crate::names::{self, Want};

const PROVIDER: &str = "retifs";
/// Content moves in pieces this large (a multiple of 4 KiB, as Cloud Files
/// wants every piece but the last).
const PIECE: u64 = 4 << 20;
/// Without a change notice, the namespace is re-read at least this often.
const RESYNC: Duration = Duration::from_secs(60);
/// After a delete or rename in the folder, its records are left alone this
/// long, so the folder isn't put back the way it was before the daemon has
/// the change.
const SETTLE: Duration = Duration::from_secs(30);

const FILE_SHARE_READ: u32 = 0x1;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const GENERIC_READ_WRITE: u32 = 0x8000_0000 | 0x4000_0000;

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

    /// A request answered with records.
    fn records_of(&mut self, req: Request) -> Result<Vec<RecordView>, String> {
        match self.call(req)? {
            Response::Records { records } => Ok(records),
            _ => Err("unexpected answer".into()),
        }
    }

    fn query(&mut self, ns: &str, terms: Vec<String>) -> Result<Vec<RecordView>, String> {
        self.records_of(Request::Query { ns: ns.to_string(), terms, at: None })
    }

    fn device(&mut self, ns: &str) -> Result<String, String> {
        match self.call(Request::NsInfo { ns: ns.to_string() })? {
            Response::Namespace(v) => Ok(v.device),
            _ => Err("unexpected answer to NsInfo".into()),
        }
    }

    /// The record at tree path `path` and every record below it.
    fn records_under(&mut self, ns: &str, path: &str) -> Result<Vec<RecordView>, String> {
        let mut out = self.query(ns, vec![format!("path={path}")])?;
        out.extend(self.query(ns, vec![format!("path^={path}/")])?);
        Ok(out)
    }
}

fn str_attr<'a>(r: &'a RecordView, key: &str) -> Option<&'a str> {
    r.attrs.iter().find_map(|(k, v)| match v {
        AttrValue::Str(s) if k == key => Some(s.as_str()),
        _ => None,
    })
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// What the callbacks and the sync loop share.
struct Shared {
    ns: String,
    device: String,
    root: PathBuf,
    /// Which records this device keeps (`keep:<device>`), as last read.
    kept: Mutex<HashMap<String, bool>>,
    /// Records just deleted or moved in the folder, and when.
    settling: Mutex<HashMap<String, Instant>>,
    /// Records just pinned or unpinned in the folder, and when.
    pinning: Mutex<HashMap<String, Instant>>,
    hydrate: Mutex<mpsc::Sender<PathBuf>>,
}

impl Shared {
    fn tree_path(&self, abs: &Path) -> Option<String> {
        let rel = abs.strip_prefix(&self.root).ok()?;
        Some(names::tree_path(&rel.to_string_lossy()))
    }

    /// Marks the records of the placeholders at and below `abs` as settling.
    fn settle(&self, abs: &Path) {
        let mut ids = Vec::new();
        collect_ids(abs, &mut ids);
        let now = Instant::now();
        let mut s = self.settling.lock().unwrap();
        s.retain(|_, t| t.elapsed() < SETTLE);
        for id in ids {
            s.insert(id, now);
        }
    }

    fn is_settling(&self, id: &str) -> bool {
        self.settling.lock().unwrap().get(id).is_some_and(|t| t.elapsed() < SETTLE)
    }

    fn pinned_here(&self, id: &str) {
        let mut p = self.pinning.lock().unwrap();
        p.retain(|_, t| t.elapsed() < SETTLE);
        p.insert(id.to_string(), Instant::now());
    }

    fn is_pinning(&self, id: &str) -> bool {
        self.pinning.lock().unwrap().get(id).is_some_and(|t| t.elapsed() < SETTLE)
    }
}

fn is_scratch(abs: &Path) -> bool {
    abs.file_name().is_some_and(|n| names::is_scratch(&n.to_string_lossy()))
}

/// The record IDs of the placeholders at and below `abs`.
fn collect_ids(abs: &Path, out: &mut Vec<String>) {
    if let Some(i) = Placeholder::open(abs).ok().and_then(|ph| info(&ph))
        && let Some((id, _)) = names::parse_identity(&i.blob)
        && !id.is_empty()
    {
        out.push(id.to_string());
    }
    if abs.is_dir()
        && let Ok(entries) = fs::read_dir(abs)
    {
        for e in entries.flatten() {
            collect_ids(&e.path(), out);
        }
    }
}

/// The callbacks Windows makes into the provider, on threads of its own.
struct Filter {
    shared: Arc<Shared>,
    wait: Duration,
    daemon: Mutex<Daemon>,
}

fn own_process(req: &CfRequest) -> bool {
    req.process().id() == std::process::id()
}

impl Filter {
    /// Deletes the records at and below `abs` (a delete in the folder, or a
    /// move out of it, e.g. to the Recycle Bin).
    fn delete_records(&self, abs: &Path, blob: &[u8]) {
        if is_scratch(abs) {
            return; // the old version, put aside during a save (below)
        }
        let Some(path) = self.shared.tree_path(abs) else { return };
        let ns = &self.shared.ns;
        let mut d = self.daemon.lock().unwrap();
        let mut ids: Vec<String> = match d.records_under(ns, &path) {
            Ok(rs) => rs.into_iter().map(|r| r.id).collect(),
            Err(e) => {
                eprintln!("retifs-cloudfiles: {}: {e}", abs.display());
                return;
            }
        };
        // A record without a path (under .records) is found by its identity.
        if let Some((id, _)) = names::parse_identity(blob)
            && !id.is_empty()
            && !ids.iter().any(|i| i == id)
        {
            ids.push(id.to_string());
        }
        if ids.is_empty() {
            return;
        }
        let n = ids.len();
        let steps = ids.into_iter().map(|id| TxStep::Delete { id }).collect();
        match d.call(Request::Transaction { ns: ns.clone(), steps }) {
            Ok(_) => eprintln!("retifs-cloudfiles: {path}: deleted ({n} record{})", if n == 1 { "" } else { "s" }),
            // A move to the Recycle Bin is heard as a rename and a delete.
            Err(e) if e.contains("no such record") => {}
            Err(e) => eprintln!("retifs-cloudfiles: {path}: deleting: {e}"),
        }
    }

    /// Moves the records at and below `from` to `to`, in one commit.
    fn move_records(&self, from: &Path, to: &Path) {
        if is_scratch(to) {
            // How Office and many editors save: the file is renamed aside, the
            // new one written under its name, the old one deleted. The record
            // stays where it is, so the new file becomes its next version,
            // with its ID, history and attributes.
            return;
        }
        let (Some(old), Some(new)) = (self.shared.tree_path(from), self.shared.tree_path(to)) else { return };
        let ns = &self.shared.ns;
        let mut d = self.daemon.lock().unwrap();
        let records = match d.records_under(ns, &old) {
            Ok(rs) => rs,
            Err(e) => {
                eprintln!("retifs-cloudfiles: {old}: {e}");
                return;
            }
        };
        let new_name = names::tree_path(&new).rsplit('/').next().unwrap_or("").to_string();
        let steps: Vec<TxStep> = records
            .iter()
            .filter_map(|r| {
                let p = str_attr(r, "path")?;
                let moved = format!("{new}{}", &p[old.len()..]);
                let mut attrs = vec![("path".to_string(), AttrValue::Str(moved))];
                if p == old && str_attr(r, "name").is_some() {
                    attrs.push(("name".to_string(), AttrValue::Str(new_name.clone())));
                }
                Some(TxStep::Set { id: r.id.clone(), attrs, unset: vec![], data: None, blocks: None })
            })
            .collect();
        if steps.is_empty() {
            return; // e.g. a file not written to retifs yet: the sync loop finds it
        }
        let n = steps.len();
        match d.call(Request::Transaction { ns: ns.clone(), steps }) {
            Ok(_) => eprintln!("retifs-cloudfiles: {old} -> {new} ({n} record{})", if n == 1 { "" } else { "s" }),
            Err(e) => eprintln!("retifs-cloudfiles: {old} -> {new}: {e}"),
        }
    }
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
            let read = Request::ReadRange { cap: cap.to_string(), ns: Some(self.shared.ns.clone()), offset: pos, len, wait_ms: self.wait.as_millis() as u64 };
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
        if !own_process(&req) {
            self.shared.settle(&req.path());
        }
        ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful)
    }

    fn deleted(&self, req: CfRequest, _info: info::Deleted) {
        if !own_process(&req) {
            self.delete_records(&req.path(), req.file_blob());
        }
    }

    fn rename(&self, req: CfRequest, ticket: ticket::Rename, info: info::Rename) -> CResult<()> {
        if !own_process(&req) {
            let path = req.path();
            self.shared.settle(&path);
            if !info.target_in_scope() {
                // Out of the folder (the Recycle Bin, another drive): gone from
                // retifs. Done now; nothing is heard of it afterwards.
                self.delete_records(&path, req.file_blob());
            }
        }
        ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful)
    }

    fn renamed(&self, req: CfRequest, info: info::Renamed) {
        if own_process(&req) {
            return;
        }
        let (from, to) = (info.source_path(), req.path());
        if from.starts_with(&self.shared.root) && to.starts_with(&self.shared.root) {
            self.move_records(&from, &to);
        }
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
            let has = self.shared.kept.lock().unwrap().get(&id).copied().unwrap_or(false);
            if want != has {
                // The user's choice (the sync loop's own pins match the tag).
                // Until the daemon has the new tag, the loop would put the old
                // pin state back.
                self.shared.pinned_here(&id);
                let key = format!("keep:{}", self.shared.device);
                let (attrs, unset) = if want { (vec![(key, AttrValue::Bool(true))], vec![]) } else { (vec![], vec![key]) };
                match self.daemon.lock().unwrap().call(Request::RecordSet { ns: self.shared.ns.clone(), id: id.clone(), attrs, unset, data: None }) {
                    Ok(_) => {
                        self.shared.kept.lock().unwrap().insert(id, want);
                    }
                    Err(e) => eprintln!("retifs-cloudfiles: {}: keep: {e}", path.display()),
                }
            }
            if want {
                _ = self.shared.hydrate.lock().unwrap().send(path);
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
    let t = filetime(w.mtime_ms.unwrap_or_else(now_ms));
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

    let (hydrate_tx, hydrate_rx) = mpsc::channel::<PathBuf>();
    let shared = Arc::new(Shared {
        ns: ns.to_string(),
        device: device.clone(),
        root: folder.clone(),
        kept: Mutex::new(HashMap::new()),
        settling: Mutex::new(HashMap::new()),
        pinning: Mutex::new(HashMap::new()),
        hydrate: Mutex::new(hydrate_tx.clone()),
    });
    let filter = Filter { shared: shared.clone(), wait, daemon: Mutex::new(Daemon::new(store)?) };
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

    let (wake_tx, wake) = mpsc::channel();
    watch(store, ns, wake_tx.clone());
    watch_folder(&folder, wake_tx);
    let sync = Sync { shared: shared.clone(), hydrate: hydrate_tx };
    loop {
        match daemon.query(ns, Vec::new()) {
            Ok(records) => {
                *shared.kept.lock().unwrap() = records.iter().map(|r| (r.id.clone(), is_kept(r, &device))).collect();
                let plan = names::plan(&Tree::build(&records), &records, &device);
                for p in &plan.skipped {
                    eprintln!("retifs-cloudfiles: {p}: not a Windows name, or another entry has it in other case; not shown");
                }
                sync.reconcile(&plan, &mut daemon);
            }
            Err(e) => eprintln!("retifs-cloudfiles: {e}"),
        }
        _ = wake.recv_timeout(RESYNC);
        // Let a burst of changes (a copy of many files) end first.
        std::thread::sleep(Duration::from_millis(500));
        while wake.try_recv().is_ok() {}
    }
}

fn is_kept(r: &RecordView, device: &str) -> bool {
    let own = format!("keep:{device}");
    r.attrs.iter().any(|(k, v)| *k == own && *v == AttrValue::Bool(true))
}

/// Watches namespace `ns` on a thread of its own (a long poll on the local
/// API) and wakes the sync loop on every change.
fn watch(store: &Path, ns: &str, wake: mpsc::Sender<()>) {
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
                    if wake.send(()).is_err() {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

/// Wakes the sync loop when files in the folder are added, written, renamed
/// or deleted (`ReadDirectoryChangesW`, on a thread of its own).
fn watch_folder(root: &Path, wake: mpsc::Sender<()>) {
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            ReadDirectoryChangesW, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
        },
    };
    let root = root.to_path_buf();
    std::thread::spawn(move || {
        let Ok(dir) = fs::OpenOptions::new().read(true).access_mode(0x1 /* FILE_LIST_DIRECTORY */).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(&root) else {
            eprintln!("retifs-cloudfiles: can't watch {}; changes there are picked up every {} s", root.display(), RESYNC.as_secs());
            return;
        };
        let mut buf = vec![0u64; 8192];
        loop {
            let mut n = 0u32;
            let filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE;
            let ok = unsafe { ReadDirectoryChangesW(HANDLE(dir.as_raw_handle() as _), buf.as_mut_ptr() as *mut _, (buf.len() * 8) as u32, true, filter, Some(&mut n), None, None) };
            if ok.is_err() || wake.send(()).is_err() {
                return;
            }
        }
    });
}

/// Makes the folder match a plan, and writes what changed in the folder to
/// retifs.
struct Sync {
    shared: Arc<Shared>,
    hydrate: mpsc::Sender<PathBuf>,
}

impl Sync {
    fn root(&self) -> &Path {
        &self.shared.root
    }

    fn reconcile(&self, plan: &names::Plan, d: &mut Daemon) {
        self.sweep(Path::new(""), plan, d);
        for w in &plan.wants {
            let abs = self.root().join(&w.rel);
            if fs::symlink_metadata(&abs).is_err() && !names::parse_identity(&w.blob).is_some_and(|(id, _)| self.shared.is_settling(id)) {
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
        let parent = abs.parent().unwrap_or(self.root());
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
    /// writes new and changed files to retifs. True if `rel` is now empty.
    fn sweep(&self, rel: &Path, plan: &names::Plan, d: &mut Daemon) -> bool {
        let Ok(entries) = fs::read_dir(self.root().join(rel)) else { return false };
        let mut empty = true;
        for e in entries.flatten() {
            let r = rel.join(e.file_name());
            let abs = self.root().join(&r);
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let key = r.to_string_lossy().to_lowercase();
            let state = Placeholder::open(&abs).ok().and_then(|ph| info(&ph));
            let id = state.as_ref().and_then(|i| names::parse_identity(&i.blob)).map(|(id, _)| id.to_string()).filter(|id| !id.is_empty());
            if id.as_deref().is_some_and(|id| self.shared.is_settling(id)) {
                empty = false;
                continue; // just deleted or moved here: the daemon is catching up
            }
            match plan.index.get(&key).map(|&i| &plan.wants[i]) {
                Some(w) if w.dir == is_dir => {
                    empty = false;
                    if is_dir {
                        self.sweep(&r, plan, d);
                    } else {
                        self.refresh(&abs, w, state, d);
                    }
                }
                Some(_) => {
                    empty = false;
                    eprintln!("retifs-cloudfiles: {}: a file where a folder should be (or the other way); left alone", abs.display());
                }
                None if names::is_scratch(&e.file_name().to_string_lossy()) => empty = false,
                None if is_dir => match state {
                    Some(_) => {
                        // Its record is gone (or it was implied by files
                        // that are gone): removed once empty.
                        if self.sweep(&r, plan, d) {
                            if let Err(err) = fs::remove_dir(&abs) {
                                empty = false;
                                eprintln!("retifs-cloudfiles: {}: {err}", abs.display());
                            }
                        } else {
                            empty = false;
                        }
                    }
                    None => {
                        empty = false;
                        self.add_dir(&abs, d);
                        self.sweep(&r, plan, d);
                    }
                },
                None => match state {
                    Some(i) if i.in_sync => {
                        if let Err(err) = fs::remove_file(&abs) {
                            empty = false;
                            eprintln!("retifs-cloudfiles: {}: {err}", abs.display());
                        }
                    }
                    // Changed here after its record was deleted elsewhere:
                    // this device's version comes back as a new record.
                    Some(_) => {
                        empty = false;
                        self.upload(&abs, None, true, d);
                    }
                    None => {
                        empty = false;
                        self.upload(&abs, None, false, d);
                    }
                },
            }
        }
        empty
    }

    /// A file at a path a record has: the record may have changed, or the
    /// file may have been changed here.
    fn refresh(&self, abs: &Path, w: &Want, state: Option<Info>, d: &mut Daemon) {
        let (id, _) = names::parse_identity(&w.blob).unwrap_or(("", None));
        let Some(state) = state else {
            // An ordinary file where a placeholder was (saved by writing a
            // new file): a new version of the record.
            self.upload(abs, Some(id), false, d);
            return;
        };
        if !state.in_sync {
            if is_local(abs) {
                if state.blob != w.blob {
                    eprintln!("retifs-cloudfiles: {}: changed here and elsewhere; this device's version is written as the newest", abs.display());
                }
                self.upload(abs, Some(id), true, d);
            } else if let Ok(mut ph) = open_rw(abs) {
                // Only times or attributes changed; the content isn't here.
                _ = ph.mark_in_sync(true, None);
            }
            return;
        }
        if state.blob != w.blob {
            self.create(abs, w, true);
            return;
        }
        self.pin(abs, w);
    }

    /// Writes the file at `abs` to retifs: a new version of record `id`, or
    /// a new record; then makes it an in-sync placeholder of that version.
    /// A file another program is still writing is left for the next round.
    fn upload(&self, abs: &Path, id: Option<&str>, placeholder: bool, d: &mut Daemon) {
        let Some(path) = self.shared.tree_path(abs) else { return };
        let ns = self.shared.ns.clone();
        // Others may read meanwhile, not write.
        let Ok(mut file) = fs::OpenOptions::new().read(true).write(true).share_mode(FILE_SHARE_READ).open(abs) else { return };
        let (size, mtime) = match file.metadata() {
            Ok(m) => (m.len(), m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or_else(now_ms)),
            Err(_) => return,
        };
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        let result: Result<RecordView, String> = (|| {
            let first = |rs: Vec<RecordView>| rs.into_iter().next().ok_or_else(|| "no record in the answer".to_string());
            if size <= PIECE {
                let mut data = Vec::with_capacity(size as usize);
                file.read_to_end(&mut data).map_err(|e| e.to_string())?;
                let mtime = ("mtime".to_string(), AttrValue::Int(mtime));
                return match id {
                    Some(id) => first(d.records_of(Request::RecordSet { ns: ns.clone(), id: id.to_string(), attrs: vec![mtime], unset: vec![], data: Some(data) })?),
                    None => {
                        let attrs = vec![("path".into(), AttrValue::Str(path.clone())), ("name".into(), AttrValue::Str(name.clone())), mtime];
                        first(d.records_of(Request::RecordCreate { ns: ns.clone(), attrs, data: Some(data) })?)
                    }
                };
            }
            // Large: through a write session, a piece at a time.
            let id = match id {
                Some(id) => id.to_string(),
                None => {
                    let attrs = vec![("path".into(), AttrValue::Str(path.clone())), ("name".into(), AttrValue::Str(name.clone()))];
                    first(d.records_of(Request::RecordCreate { ns: ns.clone(), attrs, data: None })?)?.id
                }
            };
            let session = match d.call(Request::WriteBegin { ns: ns.clone(), id, truncate: true })? {
                Response::Session { session, .. } => session,
                _ => return Err("unexpected answer to WriteBegin".into()),
            };
            let mut offset = 0;
            let mut piece = vec![0u8; PIECE as usize];
            loop {
                let n = file.read(&mut piece).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                if let Err(e) = d.call(Request::WriteAt { session, offset, data: piece[..n].to_vec() }) {
                    _ = d.call(Request::WriteAbort { session });
                    return Err(e);
                }
                offset += n as u64;
            }
            first(d.records_of(Request::WriteCommit { session, attrs: vec![("mtime".into(), AttrValue::Int(mtime))] })?)
        })();
        let record = match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("retifs-cloudfiles: {path}: writing to retifs: {e}");
                return;
            }
        };
        let identity = names::identity(&record.id, record.blocks.first().map(String::as_str));
        let mut ph = Placeholder::from(file);
        let done = if placeholder {
            ph.update(UpdateOptions::default().blob(&identity).mark_in_sync(), None).map(|_| ())
        } else {
            ph.convert_to_placeholder(ConvertOptions::default().blob(identity).mark_in_sync(), None).map(|_| ())
        };
        match done {
            Ok(()) => eprintln!("retifs-cloudfiles: {path}: written ({size} bytes)"),
            Err(e) => eprintln!("retifs-cloudfiles: {path}: written, but marking it in sync: {e}"),
        }
    }

    /// A folder made here: a directory record, and the folder becomes its
    /// placeholder.
    fn add_dir(&self, abs: &Path, d: &mut Daemon) {
        let Some(path) = self.shared.tree_path(abs) else { return };
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        let attrs = vec![("path".into(), AttrValue::Str(path.clone())), ("type".into(), AttrValue::Str("directory".into())), ("name".into(), AttrValue::Str(name))];
        let record = match d.records_of(Request::RecordCreate { ns: self.shared.ns.clone(), attrs, data: None }) {
            Ok(rs) if !rs.is_empty() => rs.into_iter().next().unwrap(),
            Ok(_) => return,
            Err(e) => {
                eprintln!("retifs-cloudfiles: {path}: {e}");
                return;
            }
        };
        let opened = fs::OpenOptions::new().read(true).access_mode(GENERIC_READ_WRITE).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(abs);
        let done = opened
            .map_err(|e| e.to_string())
            .and_then(|f| Placeholder::from(f).convert_to_placeholder(ConvertOptions::default().blob(names::identity(&record.id, None)).mark_in_sync(), None).map(|_| ()).map_err(|e| e.to_string()));
        match done {
            Ok(()) => eprintln!("retifs-cloudfiles: {path}: folder written"),
            Err(e) => eprintln!("retifs-cloudfiles: {path}: folder written, but marking it in sync: {e}"),
        }
    }

    /// Kept here: pinned and hydrated. No longer kept: no longer pinned
    /// (the content stays until Windows or the user frees it).
    fn pin(&self, abs: &Path, w: &Want) {
        if w.dir || names::parse_identity(&w.blob).is_some_and(|(id, _)| self.shared.is_pinning(id)) {
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

/// All of the file's content is here (no `RECALL_ON_DATA_ACCESS`): written
/// to, or hydrated. (`OnDiskDataSize` doesn't count what was written here.)
fn is_local(abs: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    fs::metadata(abs).is_ok_and(|m| m.file_attributes() & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS == 0)
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
