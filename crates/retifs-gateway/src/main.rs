//! `retifs-gateway [--store DIR] [--listen 127.0.0.1:8740]`: every namespace
//! as a local, read-only website (`http://<namespace>.localhost:8740/`),
//! through `retifsd`'s local API. The base for the browser extension (plan,
//! phase 1). Content not here yet is fetched as it's read (ADR-0002).

mod site;

use std::path::PathBuf;

use libretifs::{AttrValue, Client, RecordView, Request, Response};
use tiny_http::{Header, Method, Response as HttpResponse, Server};

fn usage() -> ! {
    eprintln!("retifs-gateway [--store DIR] [--listen 127.0.0.1:8740]");
    std::process::exit(2)
}

struct Gateway {
    rt: tokio::runtime::Runtime,
    client: Client,
    store: PathBuf,
}

impl Gateway {
    fn call(&mut self, req: Request) -> Result<Response, String> {
        if let Ok(r) = self.rt.block_on(self.client.call(req.clone())) {
            return Ok(r);
        }
        // The daemon restarted: connect again once.
        self.client = self.rt.block_on(Client::connect(&self.store)).map_err(|e| e.to_string())?;
        self.rt.block_on(self.client.call(req)).map_err(|e| e.to_string())
    }

    fn record(&mut self, ns: &str, path: &str) -> Result<Option<RecordView>, String> {
        match self.call(Request::Query { ns: ns.into(), terms: vec![format!("path={path}")], at: None })? {
            Response::Records { mut records } => Ok(if records.is_empty() { None } else { Some(records.remove(0)) }),
            Response::Error { message } => Err(message),
            _ => Err("unexpected response".into()),
        }
    }

    fn read(&mut self, ns: &str, cap: &str, offset: u64, len: u64) -> Result<Vec<u8>, String> {
        let req = Request::ReadRange { cap: cap.into(), ns: Some(ns.into()), offset, len, wait_ms: 30_000 };
        match self.call(req)? {
            Response::Range { data } => Ok(data),
            Response::Error { message } => Err(message),
            _ => Err("unexpected response".into()),
        }
    }
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

fn page(status: u16, title: &str, body: &str) -> HttpResponse<std::io::Cursor<Vec<u8>>> {
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>{t}</title><style>body{{font:16px system-ui;margin:2rem auto;max-width:40rem;padding:0 1rem}}</style><h1>{t}</h1>{body}",
        t = site::escape_html(title)
    );
    let mut r = HttpResponse::from_data(html.into_bytes()).with_status_code(status).with_header(header("Content-Type", "text/html; charset=utf-8"));
    for (k, v) in site::SECURITY_HEADERS {
        r.add_header(header(k, v));
    }
    r
}

fn main() {
    let mut store = libretifs::default_store_dir();
    let mut listen = "127.0.0.1:8740".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--store" => store = args.next().unwrap_or_else(|| usage()).into(),
            "--listen" => listen = args.next().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let client = rt.block_on(Client::connect(&store)).unwrap_or_else(|e| {
        eprintln!("retifs-gateway: can't reach retifsd at {}: {e}", store.display());
        std::process::exit(1)
    });
    let server = Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("retifs-gateway: can't listen on {listen}: {e}");
        std::process::exit(1)
    });
    let port = listen.rsplit(':').next().unwrap_or("8740").to_string();
    eprintln!("retifs-gateway: http://localhost:{port}/ (sites at http://<namespace>.localhost:{port}/)");
    let mut gw = Gateway { rt, client, store };
    for req in server.incoming_requests() {
        let _ = serve(&mut gw, req, &port);
    }
}

fn serve(gw: &mut Gateway, req: tiny_http::Request, port: &str) -> std::io::Result<()> {
    if !matches!(req.method(), Method::Get | Method::Head) {
        return req.respond(page(405, "Read-only", "<p>This gateway only reads.</p>"));
    }
    let host = req.headers().iter().find(|h| h.field.equiv("Host")).map(|h| h.value.as_str().to_string()).unwrap_or_default();
    let ns = match site::site(&host) {
        Ok(ns) => ns,
        Err(()) => return req.respond(page(421, "Not a retifs site", "<p>This gateway serves <code>localhost</code> only.</p>")),
    };
    let Some(ns) = ns else {
        // The index: every namespace here, each a link to its own origin.
        let names = match gw.call(Request::Namespaces) {
            Ok(Response::Names { names }) => names,
            _ => Vec::new(),
        };
        let list: String = names
            .iter()
            .filter(|n| site::site(&format!("{n}.localhost")).is_ok())
            .map(|n| format!("<li><a href=\"http://{n}.localhost:{port}/\">{n}</a></li>", n = site::escape_html(n)))
            .collect();
        return req.respond(page(200, "retifs", &format!("<p>Namespaces on this node:</p><ul>{list}</ul>")));
    };
    let url = req.url().to_string();
    let mut found = None;
    for path in site::candidates(&url) {
        match gw.record(&ns, &path) {
            Ok(Some(r)) => {
                found = Some((path, r));
                break;
            }
            Ok(None) => {}
            Err(e) => return req.respond(page(502, "retifsd", &format!("<p>{}</p>", site::escape_html(&e)))),
        }
    }
    let Some((path, rec)) = found else {
        return req.respond(page(404, "Not found", &format!("<p>No record with path <code>{}</code> in {}.</p>", site::escape_html(&url), site::escape_html(&ns))));
    };
    let attr = |k: &str| rec.attrs.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let size = match attr("size") {
        Some(AttrValue::Int(n)) if *n >= 0 => *n as u64,
        _ => 0,
    };
    let declared = match attr("type") {
        Some(AttrValue::Str(t)) => Some(t.as_str()),
        _ => None,
    };
    let ctype = site::content_type(&path, declared);
    let Some(cap) = rec.blocks.first().cloned() else {
        return req.respond(page(404, "No content", "<p>That record has no content.</p>"));
    };
    let range = req.headers().iter().find(|h| h.field.equiv("Range")).and_then(|h| site::byte_range(h.value.as_str(), size));
    let (status, span) = match &range {
        Some(r) => (206, r.clone()),
        None => (200, 0..size),
    };
    let head = *req.method() == Method::Head;
    let body = if head { Vec::new() } else {
        match gw.read(&ns, &cap, span.start, span.end - span.start) {
            Ok(d) => d,
            Err(e) => return req.respond(page(504, "Not available", &format!("<p>The content isn't here and couldn't be fetched: {}</p>", site::escape_html(&e)))),
        }
    };
    let mut resp = HttpResponse::from_data(body).with_status_code(status).with_header(header("Content-Type", ctype)).with_header(header("Accept-Ranges", "bytes"));
    if let Some(r) = &range {
        resp.add_header(header("Content-Range", &format!("bytes {}-{}/{size}", r.start, r.end - 1)));
    }
    for (k, v) in site::SECURITY_HEADERS {
        resp.add_header(header(k, v));
    }
    req.respond(resp)
}
