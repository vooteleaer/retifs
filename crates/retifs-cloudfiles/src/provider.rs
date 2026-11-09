//! The Cloud Files provider (ADR-0002): a namespace as a sync root. Records
//! are placeholders; opening one reads its content from the daemon
//! (`ReadRange`). Files added or changed in the folder are written back as
//! records and versions, deletes and renames as record deletes and path
//! changes. Explorer's "Always keep on this device" and "Free up space" set
//! and clear this device's keep tag.
//!
//! Like the FUSE mount it holds no keys and no store; `retifsd` does.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Read,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
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
use retifs_tree::{self as tree, Tree};

use crate::names::{self, Want};

const PROVIDER: &str = "retifs";
/// Content moves in pieces this large (a multiple of 4 KiB, as Cloud Files
/// wants every piece but the last).
const PIECE: u64 = 4 << 20;
/// Through another node (`--via`): a request or answer is one RNS Resource,
/// at most 1 MiB with its envelope, so content moves in half that.
const PIECE_VIA: u64 = 512 << 10;
/// Without a change notice, the namespace is re-read at least this often.
const RESYNC: Duration = Duration::from_secs(60);
/// How long a read waits for content that keeps arriving (one wait each
/// time; it gives up sooner once nothing more comes).
const MAX_FETCH: Duration = Duration::from_secs(600);
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
    /// Another of the user's nodes that holds the namespace (ADR-0019).
    via: Option<String>,
    rt: tokio::runtime::Runtime,
    client: Option<Client>,
}

impl Daemon {
    fn new(store: &Path, via: Option<String>) -> Result<Daemon, String> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        Ok(Daemon { store: store.to_path_buf(), via, rt, client: None })
    }

    fn piece(&self) -> u64 {
        if self.via.is_some() { PIECE_VIA } else { PIECE }
    }

    fn call(&mut self, req: Request) -> Result<Response, String> {
        if self.client.is_none() {
            let c = self.rt.block_on(Client::connect(&self.store)).map_err(|e| format!("can't reach retifsd at {}: {e}", self.store.display()))?;
            self.client = Some(c.via(self.via.clone()));
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

    /// This device's name in `ns`; makes `ns` if there's none of that name
    /// yet (a new, empty folder to fill).
    fn device(&mut self, ns: &str) -> Result<String, String> {
        let info = match self.call(Request::NsInfo { ns: ns.to_string() }) {
            Err(e) if e.starts_with("no namespace") => {
                self.call(Request::NsAddress { ns: ns.to_string() })?;
                eprintln!("retifs-cloudfiles: made a new namespace {ns}");
                self.call(Request::NsInfo { ns: ns.to_string() })?
            }
            r => r?,
        };
        match info {
            Response::Namespace(v) => Ok(v.device),
            _ => Err("unexpected answer to NsInfo".into()),
        }
    }

    /// Whether this node may write to `ns` (through `--via`: whether that node may).
    fn may_write(&mut self, ns: &str) -> Result<bool, String> {
        match self.call(Request::NsInfo { ns: ns.to_string() })? {
            Response::Namespace(v) => Ok(v.writers.iter().any(|(w, rights)| *w == v.own_writer && rights.iter().any(|r| r == "write"))),
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
    /// This node may only read: the folder is read-only (below).
    read_only: AtomicBool,
    /// Local files already reported as not written (read-only).
    refused: Mutex<HashSet<PathBuf>>,
    /// The folder as the last round planned it: what a folder opened for
    /// the first time is filled from (`fetch_placeholders`).
    plan: Mutex<Option<Arc<names::Plan>>>,
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

    /// The album `abs` is (in) under `/Albums`, as the last round planned it.
    fn album_at(&self, abs: &Path) -> Option<String> {
        let rel = abs.strip_prefix(&self.root).ok()?.to_string_lossy().to_lowercase();
        let plan = self.plan.lock().unwrap().clone()?;
        plan.index.get(&rel).and_then(|&i| plan.wants[i].album.clone())
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

/// Makes the folder read-only for the user, or writable again: a deny ACE
/// on creating and changing files and folders, inherited by everything in
/// it. Windows ignores a folder's read-only attribute, and a file's is one
/// click away; the ACE holds in Explorer and every program. Cloud Files
/// itself still makes, updates and removes placeholders under it, so the
/// folder keeps following the namespace. Deleting and renaming are refused
/// in the callbacks.
fn set_read_only(root: &Path, read_only: bool) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let user = match std::env::var("USERDOMAIN") {
        Ok(d) => format!("{d}\\{}", std::env::var("USERNAME").unwrap_or_default()),
        Err(_) => std::env::var("USERNAME").map_err(|e| e.to_string())?,
    };
    let icacls = |args: &[&str]| {
        let out = std::process::Command::new("icacls").arg(root).args(args).creation_flags(CREATE_NO_WINDOW).output().map_err(|e| e.to_string())?;
        if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stdout).trim().to_string()) }
    };
    // Ours is the only deny ACE for the user there: off first, then on if asked.
    icacls(&["/remove:d", &user, "/Q"])?;
    if read_only {
        icacls(&["/deny", &format!("{user}:(OI)(CI)(WD,AD)"), "/Q"])?;
    }
    Ok(())
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
        && !is_partial(abs)
        && let Ok(entries) = fs::read_dir(abs)
    {
        for e in entries.flatten() {
            collect_ids(&e.path(), out);
        }
    }
}

/// Whether `dir` is a placeholder folder Windows hasn't asked the contents
/// of yet (it will, when the folder is first opened). Read from the folder's
/// own directory entry, so asking doesn't open it.
fn is_partial(dir: &Path) -> bool {
    use windows::Win32::Storage::CloudFilters::{CfGetPlaceholderStateFromAttributeTag, CF_PLACEHOLDER_STATE_PARTIAL};
    use windows::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};
    let mut data = WIN32_FIND_DATAW::default();
    let Ok(found) = (unsafe { FindFirstFileW(&windows::core::HSTRING::from(dir.as_os_str()), &mut data) }) else { return false };
    unsafe { _ = FindClose(found) };
    // dwReserved0 is the reparse tag when the entry is a reparse point.
    let state = unsafe { CfGetPlaceholderStateFromAttributeTag(data.dwFileAttributes, data.dwReserved0) };
    state.0 & CF_PLACEHOLDER_STATE_PARTIAL.0 != 0
}

/// `w`'s placeholder: a file, or a folder whose contents come when it's opened.
fn placeholder(w: &Want) -> PlaceholderFile {
    let name = Path::new(&w.rel).file_name().unwrap_or_default().to_os_string();
    PlaceholderFile::new(name).metadata(metadata(w)).blob(w.blob.clone()).mark_in_sync()
}

/// A new file's place: its path and name, or in Unfiled only its name (a
/// record there has no path). One put in an album's folder is in that album.
fn place(path: &str, name: &str) -> Vec<(String, AttrValue)> {
    let name = ("name".to_string(), AttrValue::Str(name.to_string()));
    if let Some(album) = path.strip_prefix(&format!("{}/", tree::ALBUMS_DIR)).and_then(|rest| rest.split_once('/')).map(|(album, _)| album) {
        return vec![name, (tree::ALBUM.to_string(), AttrValue::Str(album.to_string()))];
    }
    if tree::is_virtual(path) { vec![name] } else { vec![("path".to_string(), AttrValue::Str(path.to_string())), name] }
}

/// The libraries a sync root holds: one (a namespace's own root), or every
/// library of this node's, each a folder of the root (`--all`).
struct Libraries {
    root: PathBuf,
    all: bool,
    by_name: Mutex<HashMap<String, Arc<Shared>>>,
}

impl Libraries {
    /// The library `abs` is in.
    fn of(&self, abs: &Path) -> Option<Arc<Shared>> {
        self.by_name.lock().unwrap().values().find(|s| abs.starts_with(&s.root)).cloned()
    }

    /// A library's own folder (`--all`), which only the libraries decide.
    fn is_library_folder(&self, abs: &Path) -> bool {
        self.all && abs.parent() == Some(self.root.as_path())
    }
}

/// The callbacks Windows makes into the provider, on threads of its own.
struct Filter {
    libraries: Arc<Libraries>,
    wait: Duration,
    daemon: Mutex<Daemon>,
}

fn own_process(req: &CfRequest) -> bool {
    req.process().id() == std::process::id()
}

impl Filter {
    /// Whether to refuse a delete or rename: the folder is read-only and it's
    /// one of retifs' files (the user's own local files there may go).
    fn refuse(&self, shared: &Shared, req: &CfRequest) -> bool {
        shared.read_only.load(Ordering::Relaxed) && names::parse_identity(req.file_blob()).is_some_and(|(id, _)| !id.is_empty())
    }

    /// Takes the record behind an album's entry out of `album` (an album's
    /// folder itself goes once its entries have).
    fn take_out_of_album(&self, shared: &Shared, abs: &Path, blob: &[u8], album: &str) {
        let Some((id, _)) = names::parse_identity(blob).filter(|(id, _)| !id.is_empty()) else { return };
        let mut d = self.daemon.lock().unwrap();
        let attrs = match d.records_of(Request::RecordGet { ns: shared.ns.clone(), id: id.to_string() }) {
            Ok(rs) => rs.into_iter().next().map(|r| r.attrs).unwrap_or_default(),
            Err(e) => {
                eprintln!("retifs-cloudfiles: {}: {e}", abs.display());
                return;
            }
        };
        let (set, unset) = tree::without_album(&attrs, album);
        if set.is_empty() && unset.is_empty() {
            return;
        }
        match d.call(Request::RecordSet { ns: shared.ns.clone(), id: id.to_string(), attrs: set, unset, data: None }) {
            Ok(_) => eprintln!("retifs-cloudfiles: {}: taken out of album {album}", abs.display()),
            Err(e) => eprintln!("retifs-cloudfiles: {}: taking it out of album {album}: {e}", abs.display()),
        }
    }

    /// Deletes the records at and below `abs` (a delete in the folder, or a
    /// move out of it, e.g. to the Recycle Bin).
    fn delete_records(&self, shared: &Shared, abs: &Path, blob: &[u8]) {
        if is_scratch(abs) {
            return; // the old version, put aside during a save (below)
        }
        let Some(path) = shared.tree_path(abs) else { return };
        let ns = &shared.ns;
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

    /// Moves the records at and below `from` to `to`, in one commit. Out of
    /// Unfiled, a file gets a path (found by its identity: it has none);
    /// into it, its path goes.
    fn move_records(&self, shared: &Shared, from: &Path, to: &Path, blob: &[u8]) {
        if is_scratch(to) {
            // How Office and many editors save: the file is renamed aside, the
            // new one written under its name, the old one deleted. The record
            // stays where it is, so the new file becomes its next version,
            // with its ID, history and attributes.
            return;
        }
        let (Some(old), Some(new)) = (shared.tree_path(from), shared.tree_path(to)) else { return };
        let ns = &shared.ns;
        let mut d = self.daemon.lock().unwrap();
        let records = match d.records_under(ns, &old) {
            Ok(rs) => rs,
            Err(e) => {
                eprintln!("retifs-cloudfiles: {old}: {e}");
                return;
            }
        };
        let new_name = names::tree_path(&new).rsplit('/').next().unwrap_or("").to_string();
        if tree::is_virtual(&old) || tree::is_virtual(&new) {
            let Some((id, _)) = names::parse_identity(blob).filter(|(id, _)| !id.is_empty()) else { return };
            let (attrs, unset) = match place(&new, &new_name).as_slice() {
                [path, name] => (vec![path.clone(), name.clone()], vec![]),
                only_name => (only_name.to_vec(), vec!["path".to_string()]),
            };
            match d.call(Request::RecordSet { ns: ns.clone(), id: id.to_string(), attrs, unset, data: None }) {
                Ok(_) => eprintln!("retifs-cloudfiles: {old} -> {new}"),
                Err(e) => eprintln!("retifs-cloudfiles: {old} -> {new}: {e}"),
            }
            return;
        }
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
        let ns = self.libraries.of(&req.path()).ok_or(CloudErrorKind::Unsuccessful)?.ns.clone();
        let size = req.file_size();
        let range = info.required_file_range();
        eprintln!("retifs-cloudfiles: {}: fetching {}..{} of {size} for process {}", req.path().display(), range.start, range.end, req.process().id());
        let end = (range.end.div_ceil(4096) * 4096).min(size);
        // A failure goes back with the range asked for: without it Windows
        // takes the answer as invalid, and the read waits out its timeout.
        let fail = |kind: CloudErrorKind| {
            if let Err(e) = ticket.fail_range(range.start..end, kind) {
                eprintln!("retifs-cloudfiles: {}: failing the read: {e}", req.path().display());
            }
            Ok(())
        };
        // Chunks of the file here: while they keep coming (a new photo still
        // on its way from the phone) the read waits on, past one wait.
        let local = || match self.daemon.lock().unwrap().call(Request::Status { cap: cap.to_string() }) {
            Ok(Response::Status(s)) => s.local_chunks,
            _ => 0,
        };
        let started = Instant::now();
        let mut have = local();
        let mut pos = range.start;
        let piece = self.daemon.lock().unwrap().piece();
        while pos < end {
            let len = piece.min(end - pos);
            let read = Request::ReadRange { cap: cap.to_string(), ns: Some(ns.clone()), offset: pos, len, wait_ms: self.wait.as_millis() as u64 };
            let answer = self.daemon.lock().unwrap().call(read);
            let data = match answer {
                Ok(Response::Range { data }) if data.len() as u64 == len => data,
                other => {
                    let now = local();
                    if now > have && started.elapsed() < MAX_FETCH {
                        // Telling Windows how far it is keeps it from giving up on the read.
                        have = now;
                        _ = ticket.report_progress(size, pos);
                        continue;
                    }
                    let path = req.path();
                    return match other {
                        Err(e) => {
                            eprintln!("retifs-cloudfiles: {}: {e}", path.display());
                            fail(CloudErrorKind::NetworkUnavailable)
                        }
                        Ok(_) => {
                            eprintln!("retifs-cloudfiles: {}: short read at {pos}", path.display());
                            fail(CloudErrorKind::Unsuccessful)
                        }
                    };
                }
            };
            if let Err(e) = ticket.write_at(&data, pos) {
                eprintln!("retifs-cloudfiles: {}: {e}", req.path().display());
                return fail(CloudErrorKind::Unsuccessful);
            }
            pos += len;
            _ = ticket.report_progress(size, pos);
        }
        Ok(())
    }

    /// A folder opened for the first time: its entries, from the library's
    /// last plan (or a fresh one, before the first round has made it).
    fn fetch_placeholders(&self, req: CfRequest, ticket: ticket::FetchPlaceholders, _info: info::FetchPlaceholders) -> CResult<()> {
        let dir = req.path();
        let Some(shared) = self.libraries.of(&dir) else {
            // The root of every library: their folders are made as they come.
            return ticket.pass_with_placeholder(&mut []).map_err(|_| CloudErrorKind::Unsuccessful);
        };
        let plan = shared.plan.lock().unwrap().clone();
        let plan = match plan {
            Some(p) => p,
            None => {
                let records = self.daemon.lock().unwrap().query(&shared.ns, Vec::new()).map_err(|e| {
                    eprintln!("retifs-cloudfiles: {}: {e}", dir.display());
                    CloudErrorKind::NetworkUnavailable
                })?;
                let p = Arc::new(names::plan(&Tree::build(&records), &records, &shared.device));
                *shared.plan.lock().unwrap() = Some(p.clone());
                p
            }
        };
        // Nothing is asked of the folder itself here: anything opened in it
        // would wait for this very filling. (Its entries can't be on disk yet:
        // the sync loop makes none in a folder not filled.)
        let rel = dir.strip_prefix(&shared.root).map(|r| r.to_string_lossy().to_lowercase()).unwrap_or_default();
        let mut wants: Vec<&Want> = plan.wants.iter().filter(|w| w.rel.rsplit_once('\\').map_or("", |(parent, _)| parent).to_lowercase() == rel).collect();
        // Folders first: a folder after a file in the same filling is made
        // unreadable (ERROR_CLOUD_FILE_METADATA_CORRUPT, never filled itself).
        wants.sort_by_key(|w| !w.dir);
        let mut entries: Vec<PlaceholderFile> = wants.into_iter().map(placeholder).collect();
        eprintln!("retifs-cloudfiles: {}: filling ({} entries) for process {}", dir.display(), entries.len(), req.process().id());
        ticket.pass_with_placeholder(&mut entries).map_err(|e| {
            eprintln!("retifs-cloudfiles: {}: filling: {e}", dir.display());
            CloudErrorKind::Unsuccessful
        })
    }

    fn dehydrate(&self, _req: CfRequest, ticket: ticket::Dehydrate, _info: info::Dehydrate) -> CResult<()> {
        // The content stays in the daemon (and on other nodes), so freeing
        // this copy loses nothing.
        ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful)
    }

    fn delete(&self, req: CfRequest, ticket: ticket::Delete, _info: info::Delete) -> CResult<()> {
        let path = req.path();
        if !own_process(&req) {
            if self.libraries.is_library_folder(&path) {
                // Leaving a library is the library's business, not a folder's.
                eprintln!("retifs-cloudfiles: {}: not deleted: a library's folder goes when the library does", path.display());
                return Err(CloudErrorKind::AccessDenied);
            }
            if let Some(shared) = self.libraries.of(&path) {
                if self.refuse(&shared, &req) {
                    eprintln!("retifs-cloudfiles: {}: not deleted: {} is read-only here", path.display(), shared.ns);
                    return Err(CloudErrorKind::ReadOnlyVolume);
                }
                shared.settle(&path);
            }
        }
        ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful)
    }

    fn deleted(&self, req: CfRequest, _info: info::Deleted) {
        let path = req.path();
        if !own_process(&req)
            && let Some(shared) = self.libraries.of(&path)
        {
            match shared.album_at(&path) {
                // In an album's folder: out of the album, the record stays.
                Some(album) => self.take_out_of_album(&shared, &path, req.file_blob(), &album),
                None => self.delete_records(&shared, &path, req.file_blob()),
            }
        }
    }

    fn rename(&self, req: CfRequest, ticket: ticket::Rename, info: info::Rename) -> CResult<()> {
        let path = req.path();
        if !own_process(&req) {
            if self.libraries.is_library_folder(&path) {
                eprintln!("retifs-cloudfiles: {}: not moved: a library's folder has the library's name", path.display());
                return Err(CloudErrorKind::AccessDenied);
            }
            if let Some(shared) = self.libraries.of(&path) {
                if self.refuse(&shared, &req) {
                    eprintln!("retifs-cloudfiles: {}: not moved: {} is read-only here", path.display(), shared.ns);
                    return Err(CloudErrorKind::ReadOnlyVolume);
                }
                if info.target_in_scope() && !info.target_path().starts_with(&shared.root) {
                    // Records belong to one library: copied across, not moved.
                    eprintln!("retifs-cloudfiles: {}: not moved: to another library, copy it instead", path.display());
                    return Err(CloudErrorKind::AccessDenied);
                }
                shared.settle(&path);
                if !info.target_in_scope() {
                    // Out of the folder (the Recycle Bin, another drive): gone from
                    // retifs. Done now; nothing is heard of it afterwards.
                    self.delete_records(&shared, &path, req.file_blob());
                }
            }
        }
        ticket.pass().map_err(|_| CloudErrorKind::Unsuccessful)
    }

    fn renamed(&self, req: CfRequest, info: info::Renamed) {
        if own_process(&req) {
            return;
        }
        let (from, to) = (info.source_path(), req.path());
        if let Some(shared) = self.libraries.of(&from)
            && to.starts_with(&shared.root)
        {
            self.move_records(&shared, &from, &to, req.file_blob());
        }
    }

    /// Pin states changed: "Always keep on this device" pins, "Free up
    /// space" unpins. They become this device's keep tag.
    fn state_changed(&self, changes: Vec<PathBuf>) {
        for path in changes {
            if path.is_dir() {
                continue;
            }
            let Some(shared) = self.libraries.of(&path) else { continue };
            let Some(info) = Placeholder::open(&path).ok().and_then(|ph| info(&ph)) else { continue };
            let Some((id, _)) = names::parse_identity(&info.blob) else { continue };
            let id = id.to_string();
            let want = match info.pin {
                PinState::Pinned => true,
                PinState::Unpinned => false,
                _ => continue,
            };
            let hydrated = info.on_disk > 0;
            let has = shared.kept.lock().unwrap().get(&id).copied().unwrap_or(false);
            if want != has {
                // The user's choice (the sync loop's own pins match the tag).
                // Until the daemon has the new tag, the loop would put the old
                // pin state back.
                shared.pinned_here(&id);
                let key = format!("keep:{}", shared.device);
                let (attrs, unset) = if want { (vec![(key, AttrValue::Bool(true))], vec![]) } else { (vec![], vec![key]) };
                match self.daemon.lock().unwrap().call(Request::RecordSet { ns: shared.ns.clone(), id: id.clone(), attrs, unset, data: None }) {
                    Ok(_) => {
                        shared.kept.lock().unwrap().insert(id, want);
                    }
                    Err(e) => eprintln!("retifs-cloudfiles: {}: keep: {e}", path.display()),
                }
            }
            if want {
                _ = shared.hydrate.lock().unwrap().send(path);
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

fn register(id: &SyncRootId, display_name: &str, folder: &Path) -> Result<(), String> {
    // A root registered before folders were filled on demand is registered
    // again (in place: its placeholders stay).
    if id.is_registered().map_err(|e| e.to_string())? && id.info().is_ok_and(|i| matches!(i.population_type(), PopulationType::Full)) {
        return Ok(());
    }
    let info = SyncRootInfo::default()
        .with_display_name(display_name)
        .with_path(folder)
        .map_err(|e| format!("{}: {e}", folder.display()))?
        // Folders are filled when first opened (`fetch_placeholders`).
        .with_population_type(PopulationType::Full)
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
    crate::share_menu::unregister(ns);
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

/// A sync root's folder, as Windows wants it named (no `\\?\`), made first.
fn root_folder(folder: &Path) -> Result<PathBuf, String> {
    if !cloud_filter::root::is_supported().unwrap_or(false) {
        return Err("Cloud Files isn't supported on this Windows".into());
    }
    fs::create_dir_all(folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    let folder = fs::canonicalize(folder).map_err(|e| e.to_string())?;
    Ok(PathBuf::from(folder.to_string_lossy().trim_start_matches(r"\\?\")))
}

/// `NS FOLDER`: one namespace as a sync root of its own.
pub fn run(store: &Path, ns: &str, folder: &Path, wait: Duration, via: Option<String>) -> Result<(), String> {
    let folder = root_folder(folder)?;
    let lib = Library::open(store, ns, &folder, via.clone())?;
    register(&root_id(ns)?, &format!("retifs {ns}"), &folder)?;
    let libraries = Arc::new(Libraries { root: folder.clone(), all: false, by_name: Mutex::new(HashMap::from([(ns.to_string(), lib.shared.clone())])) });
    let filter = Filter { libraries, wait, daemon: Mutex::new(Daemon::new(store, via.clone())?) };
    let _connection = Session::new().connect(&folder, filter).map_err(|e| format!("connecting the sync root: {e}"))?;
    let on = via.as_deref().map(|v| format!(" on node {v}")).unwrap_or_default();
    eprintln!("retifs-cloudfiles: namespace {ns}{on} in {} (device {}; Ctrl+C stops it, --unregister removes it)", folder.display(), lib.shared.device);
    let (wake_tx, wake) = mpsc::channel();
    serve(lib, store, via, Arc::new(AtomicBool::new(false)), wake_tx, wake);
    Ok(())
}

/// The account name of the sync root that holds every library (`--all`),
/// apart from a namespace's own (`@` keeps it from being a library's name).
pub const ALL: &str = "@libraries";
/// How often the libraries are asked for (the local API has no watch of them).
const LIBRARIES_EVERY: Duration = Duration::from_secs(5);

/// `--all FOLDER`: every library of this node's in one sync root, a folder
/// each, made when the library comes (joined, made) and removed when it
/// goes (left), once nothing in it is waiting to be written to retifs.
pub fn run_all(store: &Path, folder: &Path, wait: Duration) -> Result<(), String> {
    let root = root_folder(folder)?;
    register(&root_id(ALL)?, "retifs", &root)?;
    let libraries = Arc::new(Libraries { root: root.clone(), all: true, by_name: Mutex::new(HashMap::new()) });
    let filter = Filter { libraries: libraries.clone(), wait, daemon: Mutex::new(Daemon::new(store, None)?) };
    let _connection = Session::new().connect(&root, filter).map_err(|e| format!("connecting the sync root: {e}"))?;
    eprintln!("retifs-cloudfiles: every library in {} (Ctrl+C stops it, --unregister --all removes it)", root.display());

    struct Serving {
        stop: Arc<AtomicBool>,
        wake: mpsc::Sender<()>,
        thread: std::thread::JoinHandle<()>,
    }
    let mut serving: HashMap<String, Serving> = HashMap::new();
    let mut daemon = Daemon::new(store, None)?;
    let mut said = HashSet::new();
    let mut not_shown = HashSet::new();
    loop {
        // While retifsd can't be asked, the folders stay as they are.
        let names = match daemon.call(Request::Namespaces) {
            Ok(Response::Names { names }) => names,
            Ok(_) => Vec::new(),
            Err(e) => {
                if said.insert(e.clone()) {
                    eprintln!("retifs-cloudfiles: {e}");
                }
                std::thread::sleep(LIBRARIES_EVERY);
                continue;
            }
        };
        said.clear();
        let here: HashSet<String> = names
            .into_iter()
            .filter(|n| n != libretifs::saved::ME)
            .filter(|n| {
                let ok = !n.contains('/') && names::windows_rel(&format!("/{n}")).is_some();
                if !ok && not_shown.insert(n.clone()) {
                    eprintln!("retifs-cloudfiles: library {n}: not a Windows folder name; not shown");
                }
                ok
            })
            .collect();
        let new: Vec<String> = here.iter().filter(|n| !serving.contains_key(*n)).cloned().collect();
        for ns in &new {
            let opened = library_folder(&root, ns).and_then(|dir| Library::open(store, ns, &dir, None));
            match opened {
                Ok(lib) => {
                    libraries.by_name.lock().unwrap().insert(ns.clone(), lib.shared.clone());
                    let stop = Arc::new(AtomicBool::new(false));
                    let (wake_tx, wake) = mpsc::channel();
                    let (store, s, w) = (store.to_path_buf(), stop.clone(), wake_tx.clone());
                    let thread = std::thread::spawn(move || serve(lib, &store, None, s, w, wake));
                    serving.insert(ns.clone(), Serving { stop, wake: wake_tx, thread });
                    eprintln!("retifs-cloudfiles: library {ns} in {}", root.join(ns).display());
                }
                Err(e) => eprintln!("retifs-cloudfiles: library {ns}: {e}"),
            }
        }
        let gone: Vec<String> = serving.keys().filter(|n| !here.contains(*n)).cloned().collect();
        for ns in gone {
            let s = serving.remove(&ns).unwrap();
            s.stop.store(true, Ordering::Relaxed);
            _ = s.wake.send(());
            _ = s.thread.join();
            libraries.by_name.lock().unwrap().remove(&ns);
            crate::share_menu::unregister(&ns);
            eprintln!("retifs-cloudfiles: library {ns} is gone");
        }
        // Folders of libraries gone, now or while this didn't run (not of one
        // that's here but couldn't be opened this round: it's tried again).
        if let Ok(entries) = fs::read_dir(&root) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !here.contains(&name) && !serving.contains_key(&name) && e.path().is_dir() && Placeholder::open(e.path()).ok().and_then(|ph| info(&ph)).is_some() {
                    remove_library_folder(&e.path());
                }
            }
        }
        std::thread::sleep(LIBRARIES_EVERY);
    }
}

/// Library `ns`'s folder in the root: made as a placeholder, or an existing
/// folder of that name made one.
fn library_folder(root: &Path, ns: &str) -> Result<PathBuf, String> {
    let dir = root.join(ns);
    match fs::symlink_metadata(&dir) {
        Err(_) => {
            // Its contents come when it's first opened.
            let ph = PlaceholderFile::new(ns).metadata(Metadata::directory()).blob(names::identity("", None)).mark_in_sync();
            ph.create::<&Path>(root).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        Ok(m) if !m.is_dir() => return Err(format!("{}: a file is where the library's folder goes", dir.display())),
        Ok(_) if Placeholder::open(&dir).ok().and_then(|ph| info(&ph)).is_some() => {}
        Ok(_) => {
            // Read-only from before (the sync root registered again): the
            // round makes it read-only again.
            set_read_only(&dir, false)?;
            let f = fs::OpenOptions::new().read(true).access_mode(GENERIC_READ_WRITE).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            Placeholder::from(f).convert_to_placeholder(ConvertOptions::default().blob(names::identity("", None)).mark_in_sync(), None).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
    }
    Ok(dir)
}

/// Removes a gone library's folder, unless something in it isn't in retifs
/// (a file written here and not yet stored, one of the user's own): then
/// it stays, and says so (once a run).
fn remove_library_folder(dir: &Path) {
    fn all_in_sync(abs: &Path) -> bool {
        let in_sync = Placeholder::open(abs).ok().and_then(|ph| info(&ph)).is_some_and(|i| i.in_sync);
        // A folder never opened has nothing in it but what retifs would put there.
        in_sync && (!abs.is_dir() || is_partial(abs) || fs::read_dir(abs).is_ok_and(|es| es.flatten().all(|e| all_in_sync(&e.path()))))
    }
    static KEPT: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);
    if !all_in_sync(dir) {
        if KEPT.lock().unwrap().get_or_insert_with(HashSet::new).insert(dir.to_path_buf()) {
            eprintln!("retifs-cloudfiles: {}: its library is gone, but it has files that aren't in retifs; left as it is", dir.display());
        }
        return;
    }
    match fs::remove_dir_all(dir) {
        Ok(()) => eprintln!("retifs-cloudfiles: {}: removed (its library is gone)", dir.display()),
        Err(e) => eprintln!("retifs-cloudfiles: {}: removing: {e}", dir.display()),
    }
}

/// A namespace's folder made to match it, a round at a time (`serve`).
struct Library {
    shared: Arc<Shared>,
    sync: Sync,
    daemon: Daemon,
    /// Whether the folder is read-only (None: not set yet); checked each
    /// round, so a grant that arrives makes it writable.
    applied: Option<bool>,
    /// Entries already said to be left out (once a run, not every round).
    said_skipped: Mutex<HashSet<String>>,
}

impl Library {
    /// Library `ns` in `folder` (which is there): "Share with retifs" for
    /// it, and its hydration thread (which ends with the library).
    fn open(store: &Path, ns: &str, folder: &Path, via: Option<String>) -> Result<Library, String> {
        let mut daemon = Daemon::new(store, via.clone())?;
        let device = daemon.device(ns)?;
        if let Err(e) = crate::share_menu::register(ns, folder, via.as_deref()) {
            eprintln!("retifs-cloudfiles: {e}");
        }
        let (hydrate_tx, hydrate_rx) = mpsc::channel::<PathBuf>();
        let shared = Arc::new(Shared {
            ns: ns.to_string(),
            device,
            root: folder.to_path_buf(),
            kept: Mutex::new(HashMap::new()),
            settling: Mutex::new(HashMap::new()),
            pinning: Mutex::new(HashMap::new()),
            hydrate: Mutex::new(hydrate_tx.clone()),
            read_only: AtomicBool::new(false),
            refused: Mutex::new(HashSet::new()),
            plan: Mutex::new(None),
        });
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
        Ok(Library { sync: Sync { shared: shared.clone(), hydrate: hydrate_tx, changed: Mutex::new(HashSet::new()) }, shared, daemon, applied: None, said_skipped: Mutex::new(HashSet::new()) })
    }

    fn round(&mut self) {
        let (ns, folder, device) = (self.shared.ns.clone(), self.shared.root.clone(), self.shared.device.clone());
        match self.daemon.may_write(&ns) {
            Ok(may) if self.applied != Some(!may) => match set_read_only(&folder, !may) {
                Ok(()) => {
                    self.shared.read_only.store(!may, Ordering::Relaxed);
                    if !may {
                        eprintln!("retifs-cloudfiles: {ns} is read-only here (this node has no write grant): the folder is read-only");
                    } else if self.applied.is_some() {
                        eprintln!("retifs-cloudfiles: {ns} may be written here now: the folder is writable");
                        self.shared.refused.lock().unwrap().clear();
                    }
                    self.applied = Some(!may);
                }
                Err(e) => eprintln!("retifs-cloudfiles: making the folder {}: {e}", if may { "writable" } else { "read-only" }),
            },
            Ok(_) => {}
            Err(e) => eprintln!("retifs-cloudfiles: {e}"),
        }
        match self.daemon.query(&ns, Vec::new()) {
            Ok(records) => {
                *self.shared.kept.lock().unwrap() = records.iter().map(|r| (r.id.clone(), is_kept(r, &device))).collect();
                let plan = Arc::new(names::plan(&Tree::build(&records), &records, &device));
                let mut said = self.said_skipped.lock().unwrap();
                for p in plan.skipped.iter().filter(|p| said.insert((*p).clone())) {
                    eprintln!("retifs-cloudfiles: {ns}: {p}: not a Windows name, or another entry has it in other case; not shown");
                }
                drop(said);
                *self.shared.plan.lock().unwrap() = Some(plan.clone());
                self.sync.reconcile(&plan, &mut self.daemon);
                for dir in self.sync.changed.lock().unwrap().drain() {
                    shell_updated(&dir);
                }
            }
            Err(e) => eprintln!("retifs-cloudfiles: {e}"),
        }
    }
}

/// Runs a library's rounds until `stop`: on every change to the namespace
/// or the folder (`wake`), and at least every `RESYNC`.
fn serve(mut lib: Library, store: &Path, via: Option<String>, stop: Arc<AtomicBool>, wake_tx: mpsc::Sender<()>, wake: mpsc::Receiver<()>) {
    watch(store, &lib.shared.ns, via, wake_tx.clone(), stop.clone());
    watch_folder(&lib.shared.root, wake_tx);
    while !stop.load(Ordering::Relaxed) {
        lib.round();
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
fn watch(store: &Path, ns: &str, via: Option<String>, wake: mpsc::Sender<()>, stop: Arc<AtomicBool>) {
    let (store, ns) = (store.to_path_buf(), ns.to_string());
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
        let mut since = 0;
        while !stop.load(Ordering::Relaxed) {
            let Ok(client) = rt.block_on(Client::connect(&store)) else {
                std::thread::sleep(Duration::from_secs(5)); // the daemon restarting
                continue;
            };
            let mut client = client.via(via.clone());
            while let Ok(Response::Changed { count }) = rt.block_on(client.call(Request::Watch { ns: ns.clone(), since, timeout_ms: 30_000 })) {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
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
    /// Folders whose entries this round added, replaced or removed: Explorer
    /// is told after it, or an open window shows them only on F5.
    changed: Mutex<HashSet<PathBuf>>,
}

impl Sync {
    fn root(&self) -> &Path {
        &self.shared.root
    }

    /// When read-only: a local file or folder that got in before the folder
    /// was made read-only stays here, not in retifs; said once.
    fn refused(&self, abs: &Path) -> bool {
        if !self.shared.read_only.load(Ordering::Relaxed) {
            return false;
        }
        if self.shared.refused.lock().unwrap().insert(abs.to_path_buf()) {
            eprintln!("retifs-cloudfiles: {}: stays only on this device: {} is read-only here (no write grant)", abs.display(), self.shared.ns);
        }
        true
    }

    /// Makes what's on disk match `plan`. A folder Windows hasn't asked for
    /// the contents of yet is left alone: it's filled when first opened
    /// (`fetch_placeholders`), so a large library costs nothing until it's
    /// looked at.
    fn reconcile(&self, plan: &names::Plan, d: &mut Daemon) {
        self.sweep(Path::new(""), plan, d);
        let mut open: HashMap<PathBuf, bool> = HashMap::new();
        for w in &plan.wants {
            let abs = self.root().join(&w.rel);
            let parent = abs.parent().unwrap_or(self.root()).to_path_buf();
            let filled = *open.entry(parent.clone()).or_insert_with(|| parent.is_dir() && !is_partial(&parent));
            if filled && fs::symlink_metadata(&abs).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) && !names::parse_identity(&w.blob).is_some_and(|(id, _)| self.shared.is_settling(id)) {
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
        self.changed.lock().unwrap().insert(parent.to_path_buf());
        match placeholder(w).create::<&Path>(parent) {
            Ok(_) => self.pin(abs, w),
            Err(e) => eprintln!("retifs-cloudfiles: {}: {e}", abs.display()),
        }
    }

    /// Walks what's on disk under `rel`: updates placeholders whose record
    /// changed, removes those whose record is gone (directories once empty),
    /// writes new and changed files to retifs. True if `rel` is now empty.
    fn sweep(&self, rel: &Path, plan: &names::Plan, d: &mut Daemon) -> bool {
        let dir = self.root().join(rel);
        // Not opened yet: reading it would make Windows fill it.
        if is_partial(&dir) {
            return false;
        }
        let Ok(entries) = fs::read_dir(&dir) else { return false };
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
                            self.changed.lock().unwrap().insert(dir.clone());
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
                        self.changed.lock().unwrap().insert(dir.clone());
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
        // A size unlike the content's: made when records with thumbnails
        // said the size of all their blocks (before 2026-11-09), and every
        // read past the content's end failed.
        if state.blob != w.blob || fs::metadata(abs).is_ok_and(|m| m.len() != w.size) {
            self.create(abs, w, true);
            return;
        }
        self.pin(abs, w);
    }

    /// Writes the file at `abs` to retifs: a new version of record `id`, or
    /// a new record; then makes it an in-sync placeholder of that version.
    /// A file another program is still writing is left for the next round.
    fn upload(&self, abs: &Path, id: Option<&str>, placeholder: bool, d: &mut Daemon) {
        if self.refused(abs) {
            return;
        }
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
            let piece_len = d.piece();
            if size <= piece_len {
                let mut data = Vec::with_capacity(size as usize);
                file.read_to_end(&mut data).map_err(|e| e.to_string())?;
                let mtime = ("mtime".to_string(), AttrValue::Int(mtime));
                return match id {
                    Some(id) => first(d.records_of(Request::RecordSet { ns: ns.clone(), id: id.to_string(), attrs: vec![mtime], unset: vec![], data: Some(data) })?),
                    None => {
                        let mut attrs = place(&path, &name);
                        attrs.push(mtime);
                        first(d.records_of(Request::RecordCreate { ns: ns.clone(), attrs, data: Some(data) })?)
                    }
                };
            }
            // Large: through a write session, a piece at a time.
            let id = match id {
                Some(id) => id.to_string(),
                None => first(d.records_of(Request::RecordCreate { ns: ns.clone(), attrs: place(&path, &name), data: None })?)?.id,
            };
            let session = match d.call(Request::WriteBegin { ns: ns.clone(), id, truncate: true })? {
                Response::Session { session, .. } => session,
                _ => return Err("unexpected answer to WriteBegin".into()),
            };
            let mut offset = 0;
            let mut piece = vec![0u8; piece_len as usize];
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
            // Storing a large file can outlast an answer over a Link (--via):
            // the commit is asked again, and the daemon answers a repeat with
            // the first one's result, so nothing is sent twice.
            let commit = Request::WriteCommit { session, attrs: vec![("mtime".into(), AttrValue::Int(mtime))] };
            let mut tries = 0;
            loop {
                match d.records_of(commit.clone()) {
                    Err(e) if e.contains("timed out") && tries < 10 => {
                        tries += 1;
                        eprintln!("retifs-cloudfiles: {path}: still storing ({e}); asking again");
                    }
                    r => break first(r?),
                }
            }
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
        if self.refused(abs) {
            return;
        }
        let Some(path) = self.shared.tree_path(abs) else { return };
        // No directory record can be there (a file put in one is, as in its parent).
        if tree::is_virtual(&path) {
            return;
        }
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        let attrs = vec![("path".into(), AttrValue::Str(path.clone())), ("type".into(), AttrValue::Str(libretifs::types::DIRECTORY.into())), ("name".into(), AttrValue::Str(name))];
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
/// A placeholder's identity (record ID and read-cap), for "Share with
/// retifs".
pub fn identity_of(ph: &Placeholder) -> Option<Vec<u8>> {
    info(ph).map(|i| i.blob)
}

fn is_local(abs: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    fs::metadata(abs).is_ok_and(|m| m.file_attributes() & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS == 0)
}

/// A placeholder opened for changing it: an ordinary Win32 handle with write
/// access (`CfUpdatePlaceholder` refuses the protected handles of
/// `Placeholder::options().write_access()`). Opening doesn't hydrate it.
/// Tells Explorer that `dir`'s entries changed, so an open window shows
/// them now (placeholders made or removed under it don't always do).
fn shell_updated(dir: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_UPDATEDIR, SHCNF_FLUSHNOWAIT, SHCNF_PATHW};
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe { SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, Some(wide.as_ptr().cast()), None) };
}

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
