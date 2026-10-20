//! What the gateway serves, independent of HTTP (tested on its own).
//!
//! - `http://<namespace>.localhost:<port>/<path>` is the record of that
//!   namespace whose `path` attribute is `/<path>`; `/` and directories look
//!   for `index.html`.
//! - Every namespace is its own origin, so one site can't read another's
//!   data through the browser.

/// The namespace a Host header names, if it's one of ours: `<ns>.localhost`
/// (with any port). `None` for the bare `localhost` (the index) or a foreign
/// host (refused: DNS rebinding).
pub fn site(host: &str) -> Result<Option<String>, ()> {
    let host = host.rsplit_once(':').map_or(host, |(h, port)| if port.chars().all(|c| c.is_ascii_digit()) { h } else { host });
    let host = host.to_ascii_lowercase();
    if host == "localhost" || host == "127.0.0.1" {
        return Ok(None);
    }
    let Some(name) = host.strip_suffix(".localhost") else { return Err(()) };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(());
    }
    Ok(Some(name.to_string()))
}

/// The record paths to try for a request path, in order.
pub fn candidates(url_path: &str) -> Vec<String> {
    let path = percent_decode(url_path.split(['?', '#']).next().unwrap_or("/"));
    let path = if path.starts_with('/') { path } else { format!("/{path}") };
    if path.split('/').any(|c| c == "..") {
        return Vec::new();
    }
    if path.ends_with('/') {
        vec![format!("{path}index.html")]
    } else {
        vec![path.clone(), format!("{path}/index.html")]
    }
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(x) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(x);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// A content type from the file name (or the record's `type` attribute if
/// it's a MIME type).
pub fn content_type(path: &str, declared: Option<&str>) -> &'static str {
    if let Some(d) = declared {
        for known in ["text/html", "text/plain", "application/json", "image/png", "image/jpeg", "application/pdf"] {
            if d == known {
                return known;
            }
        }
    }
    let ext = path.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" | "md" | "mu" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// A single `bytes=a-b` range (the only kind browsers send for media), as
/// start..end within `size`. `None`: no usable range, serve it whole.
pub fn byte_range(header: &str, size: u64) -> Option<std::ops::Range<u64>> {
    let spec = header.trim().strip_prefix("bytes=")?;
    if spec.contains(',') || size == 0 {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (start, end) = match (a.trim(), b.trim()) {
        ("", n) => {
            let n: u64 = n.parse().ok()?;
            (size.saturating_sub(n), size)
        }
        (a, "") => (a.parse().ok()?, size),
        (a, b) => (a.parse().ok()?, b.parse::<u64>().ok()?.saturating_add(1).min(size)),
    };
    (start < end && start < size).then_some(start..end)
}

/// Headers every response carries: the page may use only its own origin
/// (no requests to anywhere else), may not be framed, and isn't sniffed.
pub const SECURITY_HEADERS: [(&str, &str); 4] = [
    (
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
];

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(site("photos.localhost:8740"), Ok(Some("photos".into())));
        assert_eq!(site("ch-1a2b.LOCALHOST"), Ok(Some("ch-1a2b".into())));
        assert_eq!(site("localhost:8740"), Ok(None));
        assert_eq!(site("127.0.0.1:8740"), Ok(None));
        assert_eq!(site("evil.example:8740"), Err(()), "DNS rebinding");
        assert_eq!(site("a.b.localhost"), Err(()));
    }

    #[test]
    fn paths() {
        assert_eq!(candidates("/"), ["/index.html"]);
        assert_eq!(candidates("/blog"), ["/blog", "/blog/index.html"]);
        assert_eq!(candidates("/a%20b.txt?x=1"), ["/a b.txt", "/a b.txt/index.html"]);
        assert!(candidates("/../etc/passwd").is_empty());
    }

    #[test]
    fn ranges() {
        assert_eq!(byte_range("bytes=0-99", 1000), Some(0..100));
        assert_eq!(byte_range("bytes=900-", 1000), Some(900..1000));
        assert_eq!(byte_range("bytes=-100", 1000), Some(900..1000));
        assert_eq!(byte_range("bytes=0-5000", 1000), Some(0..1000));
        assert_eq!(byte_range("bytes=2000-", 1000), None);
        assert_eq!(byte_range("bytes=0-1,5-6", 1000), None);
    }
}
