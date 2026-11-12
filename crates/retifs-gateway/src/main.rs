//! `retifs-gateway [--store DIR] [--listen 127.0.0.1:8740] [--via NODE]`: every library
//! as a local, read-only website (`http://<namespace>.localhost:8740/`),
//! through `retifsd`'s local API. The base for the browser extension (plan,
//! phase 1). Content not here yet is fetched as it's read (ADR-0002).

mod micron;
mod peer;
mod site;

use std::path::PathBuf;

use libretifs::{AttrValue, Client, RecordView, Request, Response};
use tiny_http::{Header, Method, Response as HttpResponse, Server};

fn usage() -> ! {
    eprintln!("retifs-gateway [--store DIR] [--listen 127.0.0.1:8740] [--via NODE]");
    std::process::exit(2)
}

struct Gateway {
    rt: tokio::runtime::Runtime,
    client: Client,
    store: PathBuf,
    /// Every request to this own node over a Link (`--via`, ADR-0019): a
    /// thin client serving another node's libraries.
    via: Option<String>,
}

impl Gateway {
    fn call(&mut self, req: Request) -> Result<Response, String> {
        if let Ok(r) = self.rt.block_on(self.client.call(req.clone())) {
            return Ok(r);
        }
        // The daemon restarted: connect again once.
        self.client = self
            .rt
            .block_on(Client::connect(&self.store))
            .map_err(|e| e.to_string())?
            .via(self.via.clone());
        self.rt
            .block_on(self.client.call(req))
            .map_err(|e| e.to_string())
    }

    fn record(&mut self, ns: &str, path: &str) -> Result<Option<RecordView>, String> {
        match self.call(Request::Query {
            ns: ns.into(),
            terms: vec![format!("path={path}")],
            at: None,
        })? {
            Response::Records { mut records } => Ok(if records.is_empty() {
                None
            } else {
                Some(records.remove(0))
            }),
            Response::Error { message } => Err(message),
            _ => Err("unexpected response".into()),
        }
    }

    fn read(&mut self, ns: &str, cap: &str, offset: u64, len: u64) -> Result<Vec<u8>, String> {
        let req = Request::ReadRange {
            cap: cap.into(),
            ns: Some(ns.into()),
            offset,
            len,
            wait_ms: 30_000,
        };
        match self.call(req)? {
            Response::Range { data } => Ok(data),
            Response::Error { message } => Err(message),
            _ => Err("unexpected response".into()),
        }
    }
}

/// How much of a file is read from the daemon at a time.
const PIECE: u64 = 1 << 20;

/// A response body read from the daemon a piece at a time.
struct Pieces<'a> {
    gw: &'a mut Gateway,
    ns: String,
    cap: String,
    pos: u64,
    end: u64,
    buf: Vec<u8>,
    at: usize,
}

impl std::io::Read for Pieces<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.buf.len() {
            if self.pos >= self.end {
                return Ok(0);
            }
            let n = (self.end - self.pos).min(PIECE);
            self.buf = self.gw.read(&self.ns, &self.cap, self.pos, n).map_err(std::io::Error::other)?;
            if self.buf.is_empty() {
                return Err(std::io::Error::other("the daemon returned nothing"));
            }
            self.pos += self.buf.len() as u64;
            self.at = 0;
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
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
    let mut r = HttpResponse::from_data(html.into_bytes())
        .with_status_code(status)
        .with_header(header("Content-Type", "text/html; charset=utf-8"));
    for (k, v) in site::SECURITY_HEADERS {
        r.add_header(header(k, v));
    }
    r
}

fn main() {
    let mut store = libretifs::default_store_dir();
    let mut listen = "127.0.0.1:8740".to_string();
    let mut via = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--store" => store = args.next().unwrap_or_else(|| usage()).into(),
            "--listen" => listen = args.next().unwrap_or_else(|| usage()),
            "--via" => via = Some(args.next().unwrap_or_else(|| usage())),
            _ => usage(),
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let client = rt.block_on(Client::connect(&store)).unwrap_or_else(|e| {
        eprintln!(
            "retifs-gateway: can't reach retifsd at {}: {e}",
            store.display()
        );
        std::process::exit(1)
    });
    let client = client.via(via.clone());
    let server = Server::http(&listen).unwrap_or_else(|e| {
        eprintln!("retifs-gateway: can't listen on {listen}: {e}");
        std::process::exit(1)
    });
    let port = listen.rsplit(':').next().unwrap_or("8740").to_string();
    eprintln!(
        "retifs-gateway: http://localhost:{port}/ (sites at http://<library>.localhost:{port}/, NomadNet nodes at http://nn-<address>.localhost:{port}/)"
    );
    let mut gw = Gateway { rt, client, store, via };
    for req in server.incoming_requests() {
        let _ = serve(&mut gw, req, &port);
    }
}

/// A NomadNet node's site: `nn-<32 hex digits>`, its own origin.
fn nomadnet_node(site: &str) -> Option<String> {
    let node = site.strip_prefix("nn-")?;
    (node.len() == 32 && node.chars().all(|c| c.is_ascii_hexdigit())).then(|| node.to_ascii_lowercase())
}

/// Links in a NomadNet page: the same node's pages on this origin, another
/// node's on its own.
struct NnLinks<'a> {
    port: &'a str,
}

impl micron::Links for NnLinks<'_> {
    fn page(&self, node: Option<&str>, path: &str, vars: &[(String, String)]) -> String {
        let query: Vec<String> = vars.iter().map(|(k, v)| format!("{}={}", site::percent_encode(k), site::percent_encode(v))).collect();
        let query = if query.is_empty() { String::new() } else { format!("?{}", query.join("&")) };
        match node {
            Some(n) => format!("http://nn-{n}.localhost:{}{path}{query}", self.port),
            None => format!("{path}{query}"),
        }
    }
}

/// A page (rendered from micron) or file from a NomadNet node, fetched over
/// Reticulum by retifsd.
fn serve_nomadnet(gw: &mut Gateway, req: tiny_http::Request, node: &str, port: &str) -> std::io::Result<()> {
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let path = site::percent_decode(path);
    let path = if path == "/" || path.is_empty() { "/page/index.mu".to_string() } else { path };
    let fields: Vec<(String, String)> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (site::percent_decode(k), site::percent_decode(v)))
        .filter(|(k, _)| k.starts_with("var_") || k.starts_with("field_"))
        .collect();
    let data = match gw.call(Request::NomadNetPage { node: node.into(), path: path.clone(), fields }) {
        Ok(Response::Page { data }) => data,
        Ok(Response::Error { message }) | Err(message) => {
            return req.respond(page(504, "Not reachable", &format!("<p>{}</p>", site::escape_html(&message))));
        }
        Ok(_) => return req.respond(page(502, "retifsd", "<p>unexpected response</p>")),
    };
    if !path.ends_with(".mu") {
        let resp = HttpResponse::from_data(data).with_header(header("Content-Type", site::content_type(&path, None)));
        let mut resp = resp;
        for (k, v) in site::SECURITY_HEADERS {
            resp.add_header(header(k, v));
        }
        return req.respond(resp);
    }
    let body = micron::to_html(&String::from_utf8_lossy(&data), &NnLinks { port });
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>{t}</title><style>{css}</style><div class=bar>NomadNet &lt;{node}&gt;{p} · <a href=\"http://localhost:{port}/\">retifs</a></div><main>{body}</main>",
        t = site::escape_html(&format!("{node}{path}")),
        p = site::escape_html(&path),
        css = NOMADNET_CSS,
    );
    let mut resp = HttpResponse::from_data(html.into_bytes()).with_header(header("Content-Type", "text/html; charset=utf-8"));
    for (k, v) in site::SECURITY_HEADERS {
        resp.add_header(header(k, v));
    }
    req.respond(resp)
}

/// NomadNet pages are made for a terminal: monospace, light on dark.
const NOMADNET_CSS: &str = "body{margin:0;background:#1d1f21;color:#ddd;font:15px/1.4 ui-monospace,Menlo,Consolas,monospace}\
.bar{padding:.4rem 1rem;background:#2b2e31;color:#999;font-size:13px}.bar a{color:#8ab4f8}\
main{max-width:100ch;margin:1rem auto;padding:0 1rem}.l,.lit{white-space:pre-wrap;min-height:1.4em}\
h1,h2,h3{font-size:1em;margin:.6em 0;padding:.1em .4em}.h1{background:#3b4252}.h2{background:#2f3540}.h3{background:#272b33}\
.hr{overflow:hidden;white-space:nowrap;color:#555}a{color:#8ab4f8}.ext{text-decoration:underline dotted}\
.field{background:#333;color:#ddd;border:1px solid #555;font:inherit}";

fn serve(gw: &mut Gateway, req: tiny_http::Request, port: &str) -> std::io::Result<()> {
    let own = match (req.remote_addr(), port.parse::<u16>()) {
        (Some(peer), Ok(p)) => peer::is_own_user(peer, p),
        _ => false,
    };
    if !own {
        return req.respond(page(
            403,
            "Not yours",
            "<p>This gateway serves only the user it runs as.</p>",
        ));
    }
    let fetch_header = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().to_string())
    };
    if peer::cross_site_subresource(
        fetch_header("Sec-Fetch-Site").as_deref(),
        fetch_header("Sec-Fetch-Mode").as_deref(),
    ) {
        return req.respond(page(
            403,
            "Cross-site request",
            "<p>Other websites can link here, not embed or fetch from here.</p>",
        ));
    }
    if !matches!(req.method(), Method::Get | Method::Head) {
        return req.respond(page(405, "Read-only", "<p>This gateway only reads.</p>"));
    }
    let host = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    let ns = match site::site(&host) {
        Ok(ns) => ns,
        Err(()) => {
            return req.respond(page(
                421,
                "Not a retifs site",
                "<p>This gateway serves <code>localhost</code> only.</p>",
            ));
        }
    };
    let Some(ns) = ns else {
        // The index: every library here, each a link to its own origin.
        let names = match gw.call(Request::Namespaces) {
            Ok(Response::Names { names }) => names,
            _ => Vec::new(),
        };
        let list: String = names
            .iter()
            .filter(|n| site::site(&format!("{n}.localhost")).is_ok())
            .map(|n| {
                format!(
                    "<li><a href=\"http://{n}.localhost:{port}/\">{n}</a></li>",
                    n = site::escape_html(n)
                )
            })
            .collect();
        return req.respond(page(
            200,
            "retifs",
            &format!("<p>Libraries on this node:</p><ul>{list}</ul><p>NomadNet nodes, over Reticulum: <code>http://nn-&lt;address&gt;.localhost:{port}/</code>, where the address is the node's 32 hex digits.</p>"),
        ));
    };
    if let Some(node) = nomadnet_node(&ns) {
        return serve_nomadnet(gw, req, &node, port);
    }
    let url = req.url().to_string();
    let mut found = None;
    for path in site::candidates(&url) {
        match gw.record(&ns, &path) {
            Ok(Some(r)) => {
                found = Some((path, r));
                break;
            }
            Ok(None) => {}
            Err(e) => {
                return req.respond(page(
                    502,
                    "retifsd",
                    &format!("<p>{}</p>", site::escape_html(&e)),
                ));
            }
        }
    }
    let Some((path, rec)) = found else {
        return req.respond(page(
            404,
            "Not found",
            &format!(
                "<p>No record with path <code>{}</code> in {}.</p>",
                site::escape_html(&url),
                site::escape_html(&ns)
            ),
        ));
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
        return req.respond(page(
            404,
            "No content",
            "<p>That record has no content.</p>",
        ));
    };
    let range = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .and_then(|h| site::byte_range(h.value.as_str(), size));
    let (status, span) = match &range {
        Some(r) => (206, r.clone()),
        None => (200, 0..size),
    };
    let head = *req.method() == Method::Head;
    // The first piece is read before answering, so a file that can't be
    // fetched gets a 504; the rest streams a piece at a time, so a large file
    // is never held whole (here or in the daemon).
    let len = if head { 0 } else { span.end - span.start };
    let first = if head {
        Vec::new()
    } else {
        match gw.read(&ns, &cap, span.start, len.min(PIECE)) {
            Ok(d) => d,
            Err(e) => {
                return req.respond(page(
                    504,
                    "Not available",
                    &format!(
                        "<p>The content isn't here and couldn't be fetched: {}</p>",
                        site::escape_html(&e)
                    ),
                ));
            }
        }
    };
    let pos = span.start + first.len() as u64;
    let body = Pieces { gw, ns: ns.clone(), cap, pos, end: span.start + len, buf: first, at: 0 };
    let mut resp = HttpResponse::new(tiny_http::StatusCode(status), Vec::new(), body, Some(len as usize), None)
        .with_header(header("Content-Type", ctype))
        .with_header(header("Accept-Ranges", "bytes"));
    if let Some(r) = &range {
        resp.add_header(header(
            "Content-Range",
            &format!("bytes {}-{}/{size}", r.start, r.end - 1),
        ));
    }
    for (k, v) in site::SECURITY_HEADERS {
        resp.add_header(header(k, v));
    }
    req.respond(resp)
}
