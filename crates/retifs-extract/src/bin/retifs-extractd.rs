//! `retifs-extractd [--store DIR] [--token-file FILE] [--via NODE] [--ns NS[,NS]] [--every SECS] [--once]`:
//! watches the user's libraries and writes what's in new content as
//! attributes (ADR-0023), as BeOS filled in a file's attributes when it
//! arrived. An app of the user's own node like any other: with a token
//! (`retifs app add extract --ns … --write --keys …`) it sees and writes only
//! what that allows; without one it's the owner and looks at every library
//! but `me`. One node of the user's running it is enough: the attributes
//! reach the others as they sync. With `--via` it describes the libraries of
//! another node of the user's (one that admitted this one), reading only
//! the parts of files it needs over the network.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

use libretifs::{AttrValue, Client, RecordView, Request, Response, TxStep};
use retifs_extract::{extract, is_extracted_key, thumbnails, MARKER};
use sha2::Digest;

fn usage() -> ! {
    eprintln!("retifs-extractd [--store DIR] [--token-file FILE] [--via NODE] [--ns NS[,NS]] [--every SECS] [--once]");
    std::process::exit(2)
}

struct Conn {
    rt: tokio::runtime::Runtime,
    client: Client,
    store: PathBuf,
    token: Option<String>,
    via: Option<String>,
}

impl Conn {
    fn open(rt: &tokio::runtime::Runtime, store: &PathBuf, token: &Option<String>, via: &Option<String>) -> Result<Client, String> {
        rt.block_on(async {
            match token {
                Some(t) => Client::connect_app(store, t).await,
                None => Client::connect(store).await,
            }
        })
        .map(|c| c.via(via.clone()))
        .map_err(|e| e.to_string())
    }

    fn call(&mut self, req: Request) -> Result<Response, String> {
        let r = match self.rt.block_on(self.client.call(req.clone())) {
            Ok(r) => r,
            Err(_) => {
                // The daemon restarted: connect again once.
                self.client = Self::open(&self.rt, &self.store, &self.token, &self.via)?;
                self.rt.block_on(self.client.call(req)).map_err(|e| e.to_string())?
            }
        };
        match r {
            Response::Error { message } => Err(message),
            r => Ok(r),
        }
    }
}

/// Pictures larger than this get no thumbnails (they'd be read whole).
const MAX_PICTURE: u64 = 64 << 20;

/// How much is read from the daemon at a time.
const PIECE: u64 = 256 << 10;

/// A record's content as `Read + Seek`, fetched from the daemon a piece at
/// a time as the extractors ask for it (a lazy library fetches only those).
struct Content<'a> {
    conn: &'a mut Conn,
    ns: String,
    cap: String,
    size: u64,
    pos: u64,
    piece: (u64, Vec<u8>),
}

impl Read for Content<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let (start, data) = &self.piece;
        if self.pos < *start || self.pos >= start + data.len() as u64 {
            let len = PIECE.min(self.size - self.pos);
            let req = Request::ReadRange { cap: self.cap.clone(), ns: Some(self.ns.clone()), offset: self.pos, len, wait_ms: 30_000 };
            match self.conn.call(req) {
                Ok(Response::Range { data }) if !data.is_empty() => self.piece = (self.pos, data),
                Ok(_) => return Err(std::io::Error::other("no content")),
                Err(e) => return Err(std::io::Error::other(e)),
            }
        }
        let (start, data) = &self.piece;
        let from = (self.pos - start) as usize;
        let n = buf.len().min(data.len() - from);
        buf[..n].copy_from_slice(&data[from..from + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Content<'_> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.size as i128 + n as i128,
            SeekFrom::Current(n) => self.pos as i128 + n as i128,
        };
        if pos < 0 {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        self.pos = pos as u64;
        Ok(self.pos)
    }
}

fn attr<'a>(r: &'a RecordView, key: &str) -> Option<&'a AttrValue> {
    r.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Which content a record's attributes were taken from: a short hash of its
/// read-cap (the cap itself is a key, and stays out of attributes).
fn marker(cap: &str) -> String {
    sha2::Sha256::digest(cap.as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Brings one record's extracted attributes up to date. `Ok(false)`: they were.
fn update(conn: &mut Conn, ns: &str, r: &RecordView) -> Result<bool, String> {
    let Some(cap) = r.blocks.first() else { return Ok(false) };
    let mark = marker(cap);
    if matches!(attr(r, MARKER), Some(AttrValue::Str(m)) if *m == mark) {
        return Ok(false);
    }
    let size = match attr(r, "size") {
        Some(AttrValue::Int(n)) if *n > 0 => *n as u64,
        _ => return Ok(false),
    };
    let (found, picture) = {
        let mut content = Content { conn, ns: ns.into(), cap: cap.clone(), size, pos: 0, piece: (0, Vec::new()) };
        let name = [attr(r, "path"), attr(r, "name")].into_iter().flatten().find_map(|v| if let AttrValue::Str(s) = v { Some(s.clone()) } else { None });
        let found = extract(&mut content, size, name.as_deref());
        // Nothing could be read (not here, and its holders unreachable):
        // left for a later look rather than marked as empty.
        if content.piece.1.is_empty() {
            return Err("its content isn't reachable now".into());
        }
        // A picture is read whole for its thumbnails (ADR-0026).
        let mut picture = Vec::new();
        if found.kind == Some("image") && size <= MAX_PICTURE && content.seek(SeekFrom::Start(0)).is_ok() {
            content.read_to_end(&mut picture).map_err(|e| e.to_string())?;
        }
        (found, picture)
    };
    let mut attrs = found.attrs.clone();
    // What it is, when nothing says yet: its MIME type (ADR-0025).
    if attr(r, "type").is_none() {
        if let Some(AttrValue::Str(mime)) = found.attrs.iter().find(|(k, _)| k == "mime").map(|(_, v)| v) {
            attrs.push(("type".into(), AttrValue::Str(mime.clone())));
        }
    }
    attrs.push((MARKER.into(), AttrValue::Str(mark)));
    // Thumbnails: stored, then named by role after the content (ADR-0026).
    let orientation = found.attrs.iter().find_map(|(k, v)| match (k.as_str(), v) {
        ("exif.orientation", AttrValue::Int(o)) => Some(*o),
        _ => None,
    });
    let mut blocks = None;
    if let Some((thumb, preview)) = (!picture.is_empty()).then(|| thumbnails(&picture, orientation)).flatten() {
        let mut caps = vec![cap.clone()];
        for data in [thumb, preview] {
            match conn.call(Request::Put { data, public: false, compress: false, publish: false, record: Some(r.id.clone()) })? {
                Response::Put { cap } => caps.push(cap),
                other => return Err(format!("unexpected answer to Put: {other:?}")),
            }
        }
        attrs.push(("block:thumb".into(), AttrValue::Int(1)));
        attrs.push(("block:preview".into(), AttrValue::Int(2)));
        blocks = Some(caps);
    }
    // What earlier content had and this one hasn't.
    let unset: Vec<String> = r.attrs.iter().map(|(k, _)| k).filter(|k| is_extracted_key(k) && !attrs.iter().any(|(a, _)| a == *k)).cloned().collect();
    // Only what changes: the same values again would be a new version.
    attrs.retain(|(k, v)| attr(r, k) != Some(v));
    match blocks {
        // Attributes and blocks in one commit.
        Some(blocks) => conn.call(Request::Transaction { ns: ns.into(), steps: vec![TxStep::Set { id: r.id.clone(), attrs, unset, data: None, blocks: Some(blocks) }] })?,
        None => conn.call(Request::RecordSet { ns: ns.into(), id: r.id.clone(), attrs, unset, data: None })?,
    };
    Ok(true)
}

fn scan(conn: &mut Conn, ns: &str) -> Result<(usize, usize), String> {
    let records = match conn.call(Request::Query { ns: ns.into(), terms: vec!["has:size".into()], at: None })? {
        Response::Records { records } => records,
        _ => return Ok((0, 0)),
    };
    let (mut done, mut failed) = (0, 0);
    for r in &records {
        match update(conn, ns, r) {
            Ok(true) => done += 1,
            Ok(false) => {}
            Err(e) => {
                failed += 1;
                eprintln!("{ns} {}: {e}", attr(r, "path").map(libretifs_text).unwrap_or_else(|| r.id.clone()));
            }
        }
    }
    Ok((done, failed))
}

fn libretifs_text(v: &AttrValue) -> String {
    match v {
        AttrValue::Str(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone());
    for a in &args {
        if a.starts_with("--") && !["--store", "--token-file", "--via", "--ns", "--every", "--once"].contains(&a.as_str()) {
            usage();
        }
    }
    let store = flag("--store").map(PathBuf::from).unwrap_or_else(libretifs::default_store_dir);
    let token = flag("--token-file")
        .map(|f| std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{f}: {e}")).trim().to_string())
        .or_else(|| std::env::var("RETIFS_EXTRACT_TOKEN").ok());
    let only: Option<Vec<String>> = flag("--ns").map(|s| s.split(',').map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).collect());
    let every = Duration::from_secs(flag("--every").and_then(|s| s.parse().ok()).unwrap_or(5));
    let once = args.iter().any(|a| a == "--once");
    let via = flag("--via");

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a tokio runtime");
    let client = loop {
        match Conn::open(&rt, &store, &token, &via) {
            Ok(c) => break c,
            Err(e) if once => {
                eprintln!("retifs-extractd: {e}");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("retifs-extractd: {e}; trying again");
                std::thread::sleep(every * 2);
            }
        }
    };
    let mut conn = Conn { rt, client, store, token, via };
    eprintln!("retifs-extractd: watching {}", only.as_ref().map_or("every library".into(), |o| o.join(", ")));

    // Each library's change count when last looked at.
    let mut seen: HashMap<String, u64> = HashMap::new();
    loop {
        let names = match conn.call(Request::Namespaces) {
            Ok(Response::Names { names }) => names,
            Ok(_) => Vec::new(),
            Err(e) => {
                eprintln!("retifs-extractd: {e}");
                Vec::new()
            }
        };
        for ns in names.into_iter().filter(|n| n != "me" && only.as_ref().is_none_or(|o| o.contains(n))) {
            let count = match conn.call(Request::Watch { ns: ns.clone(), since: 0, timeout_ms: 0 }) {
                Ok(Response::Changed { count }) => count,
                _ => continue,
            };
            if seen.get(&ns) == Some(&count) {
                continue;
            }
            match scan(&mut conn, &ns) {
                Ok((0, 0)) => {}
                Ok((done, failed)) => eprintln!("{ns}: {done} record(s) described{}", if failed > 0 { format!(", {failed} to look at again") } else { String::new() }),
                Err(e) => eprintln!("{ns}: {e}"),
            }
            // Its own writes change the count too: the next look finds them done.
            let count = match conn.call(Request::Watch { ns: ns.clone(), since: 0, timeout_ms: 0 }) {
                Ok(Response::Changed { count }) => count,
                _ => count,
            };
            seen.insert(ns, count);
        }
        if once {
            break;
        }
        std::thread::sleep(every);
    }
}
