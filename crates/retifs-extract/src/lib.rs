//! What's in a file, as attributes (ADR-0023): its media type by its bytes
//! (or its name, for text), an image's size, camera and place, a
//! recording's tags and length, a document's title, author and pages.
//! The attribute keys are the conventions of `docs/07-api.md` §6.3.
//!
//! Extractors read through `Read + Seek`, so a caller can serve only the
//! parts they ask for (the head of a photo, an audio file's tags) instead of
//! the whole file.

use std::io::{BufReader, Read, Seek, SeekFrom};

use libretifs::AttrValue;

/// The keys extractors write, for the extractor to take back what new
/// content no longer has: exact keys, and prefixes ending in `.`.
pub const KEYS: &[&str] = &["mime", "width", "height", "taken", "camera", "geo", "duration", "exif.", "audio.", "doc."];

/// The marker of the content attributes were taken from.
pub const MARKER: &str = "extracted";

/// Whether `key` is one extractors write.
pub fn is_extracted_key(key: &str) -> bool {
    key == MARKER || KEYS.iter().any(|k| if k.ends_with('.') { key.starts_with(k) } else { key == *k })
}

/// What a file holds.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Extracted {
    pub attrs: Vec<(String, AttrValue)>,
    /// `image`, `audio`, `video`, `document` or `text`: the record's `type`
    /// when it has none.
    pub kind: Option<&'static str>,
}

impl Extracted {
    fn set(&mut self, key: &str, value: AttrValue) {
        self.attrs.retain(|(k, _)| k != key);
        self.attrs.push((key.to_string(), value));
    }

    fn text(&mut self, key: &str, value: impl AsRef<str>) {
        let v = value.as_ref().trim().trim_matches('\0').trim();
        if !v.is_empty() {
            self.set(key, AttrValue::Str(v.to_string()));
        }
    }
}

/// How much of the start of a file is read to tell what it is.
const HEAD: usize = 64 << 10;

/// Everything the extractors find in `r` (`size` bytes; `name`, if known,
/// tells text formats apart). Errors in one extractor leave its attributes
/// out; they don't fail the rest.
pub fn extract<R: Read + Seek>(r: &mut R, size: u64, name: Option<&str>) -> Extracted {
    let mut out = Extracted::default();
    let mut head = vec![0u8; HEAD.min(size as usize)];
    if r.seek(SeekFrom::Start(0)).is_err() || read_full(r, &mut head).is_err() {
        return out;
    }
    let is_text = !head.is_empty() && std::str::from_utf8(trim_partial_utf8(&head)).is_ok();
    let mime = match infer::get(&head) {
        Some(t) => t.mime_type().to_string(),
        None if is_text => text_mime(name).into(),
        None => return out,
    };
    // Office documents, OpenDocument and EPUB are zips: what's inside says which.
    let mime = if mime == "application/zip" { package_mime(r).map(String::from).unwrap_or(mime) } else { mime };
    out.kind = kind(&mime);
    out.text("mime", &mime);
    match out.kind {
        Some("image") => image(r, &head, &mut out),
        Some("audio") => media(r, &mut out, true),
        Some("video") => media(r, &mut out, false),
        Some("document") if mime == "application/pdf" => pdf(r, &head, size, &mut out),
        Some("document") => packaged(r, &mime, &mut out),
        Some("text") if mime == "text/markdown" => {
            let text = String::from_utf8_lossy(trim_partial_utf8(&head)).into_owned();
            if let Some(t) = text.trim_start_matches('\u{feff}').lines().find_map(|l| l.strip_prefix("# ")) {
                out.text("doc.title", t);
            }
        }
        _ => {}
    }
    out
}

/// A text file's type by its name's extension.
fn text_mime(name: Option<&str>) -> &'static str {
    let ext = name.and_then(|n| n.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "md" | "markdown" => "text/markdown",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "json" => "application/json",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",
        "js" | "mjs" => "text/javascript",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "c" | "h" => "text/x-c",
        "cpp" | "cc" | "hpp" => "text/x-c++",
        "sh" => "text/x-shellscript",
        "mu" => "text/micron",
        _ => "text/plain",
    }
}

fn kind(mime: &str) -> Option<&'static str> {
    let (top, sub) = mime.split_once('/')?;
    Some(match top {
        "image" if sub == "svg+xml" => "text",
        "image" => "image",
        "audio" => "audio",
        "video" => "video",
        "text" => "text",
        "application" if sub == "json" || sub == "xml" || sub == "toml" || sub == "yaml" => "text",
        "application"
            if sub == "pdf"
                || sub == "epub+zip"
                || sub == "rtf"
                || sub == "msword"
                || sub.starts_with("vnd.openxmlformats-officedocument")
                || sub.starts_with("vnd.oasis.opendocument")
                || sub.starts_with("vnd.ms-") =>
        {
            "document"
        }
        _ => return None,
    })
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    if n < buf.len() {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// The head without a UTF-8 sequence cut off at its end.
fn trim_partial_utf8(b: &[u8]) -> &[u8] {
    match std::str::from_utf8(b) {
        Err(e) if e.error_len().is_none() => &b[..e.valid_up_to()],
        _ => b,
    }
}

fn image<R: Read + Seek>(r: &mut R, head: &[u8], out: &mut Extracted) {
    if let Ok(s) = imagesize::blob_size(head) {
        out.set("width", AttrValue::Int(s.width as i64));
        out.set("height", AttrValue::Int(s.height as i64));
    }
    if r.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    let Ok(exif) = exif::Reader::new().read_from_container(&mut BufReader::new(r)) else { return };
    use exif::{In, Tag};
    let text = |tag| exif.get_field(tag, In::PRIMARY).map(|f| f.display_value().to_string().trim_matches('"').to_string());
    if let Some(t) = text(Tag::DateTimeOriginal).or_else(|| text(Tag::DateTime)) {
        out.text("taken", exif_time(&t));
    }
    let camera = [text(Tag::Make), text(Tag::Model)].into_iter().flatten().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
    if !camera.is_empty() {
        // "Google Pixel 7", not "Google Google Pixel 7".
        let joined = if camera.len() == 2 && camera[1].starts_with(&camera[0]) { camera[1].clone() } else { camera.join(" ") };
        out.text("camera", joined);
    }
    for (tag, key) in [
        (Tag::LensModel, "exif.lens"),
        (Tag::ExposureTime, "exif.exposure"),
        (Tag::FNumber, "exif.fnumber"),
        (Tag::PhotographicSensitivity, "exif.iso"),
        (Tag::FocalLength, "exif.focal"),
        (Tag::Software, "exif.software"),
    ] {
        if let Some(v) = text(tag) {
            out.text(key, v);
        }
    }
    if let Some(o) = exif.get_field(Tag::Orientation, In::PRIMARY).and_then(|f| f.value.get_uint(0)) {
        out.set("exif.orientation", AttrValue::Int(o as i64));
    }
    if let Some((lat, lon)) = gps(&exif) {
        out.set("geo", AttrValue::List(vec![AttrValue::Float(lat), AttrValue::Float(lon)]));
    }
}

/// `2026:07:14 18:22:05` → `2026-07-14T18:22:05`.
fn exif_time(t: &str) -> String {
    match t.split_once(' ') {
        Some((d, time)) => format!("{}T{}", d.replace(':', "-"), time),
        None => t.replace(':', "-"),
    }
}

fn gps(exif: &exif::Exif) -> Option<(f64, f64)> {
    use exif::{In, Tag, Value};
    let degrees = |tag, rf| {
        let Value::Rational(v) = &exif.get_field(tag, In::PRIMARY)?.value else { return None };
        let d = v.first()?.to_f64() + v.get(1).map_or(0.0, |m| m.to_f64() / 60.0) + v.get(2).map_or(0.0, |s| s.to_f64() / 3600.0);
        let sign = exif.get_field(rf, In::PRIMARY).map(|f| f.display_value().to_string()).is_some_and(|r| r.contains('S') || r.contains('W'));
        Some(if sign { -d } else { d })
    };
    let (lat, lon) = (degrees(Tag::GPSLatitude, Tag::GPSLatitudeRef)?, degrees(Tag::GPSLongitude, Tag::GPSLongitudeRef)?);
    (lat.is_finite() && lon.is_finite() && (lat, lon) != (0.0, 0.0)).then_some((lat, lon))
}

/// A recording's length, and with `tags`, its title, artist and album.
fn media<R: Read + Seek>(r: &mut R, out: &mut Extracted, tags: bool) {
    use lofty::prelude::*;
    if r.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    let Ok(probe) = lofty::probe::Probe::new(BufReader::new(r)).guess_file_type() else { return };
    let Ok(file) = probe.read() else { return };
    let secs = file.properties().duration().as_secs_f64();
    if secs > 0.0 {
        out.set("duration", AttrValue::Int(secs.round() as i64));
    }
    if !tags {
        return;
    }
    let Some(tag) = file.primary_tag().or_else(|| file.first_tag()) else { return };
    if let Some(v) = tag.title() {
        out.text("audio.title", v);
    }
    if let Some(v) = tag.artist() {
        out.text("audio.artist", v);
    }
    if let Some(v) = tag.album() {
        out.text("audio.album", v);
    }
    if let Some(v) = tag.genre() {
        out.text("audio.genre", v);
    }
    if let Some(n) = tag.track() {
        out.set("audio.track", AttrValue::Int(n as i64));
    }
    if let Some(y) = tag.get_string(&ItemKey::Year).or_else(|| tag.get_string(&ItemKey::RecordingDate)).and_then(|d| d.get(..4)?.parse::<i64>().ok()) {
        out.set("audio.year", AttrValue::Int(y));
    }
}

/// A PDF's title, author and page count: from its document information
/// (or XMP) near the start or the end, where it usually is; a compressed
/// one may hide them, and then they're left out.
fn pdf<R: Read + Seek>(r: &mut R, head: &[u8], size: u64, out: &mut Extracted) {
    let mut text = head.to_vec();
    let tail_len = HEAD.min(size as usize);
    if size > head.len() as u64 && r.seek(SeekFrom::Start(size - tail_len as u64)).is_ok() {
        let mut tail = vec![0u8; tail_len];
        if read_full(r, &mut tail).is_ok() {
            text.extend_from_slice(&tail);
        }
    }
    for (key, name, xmp_tag) in [("doc.title", "/Title", "dc:title"), ("doc.author", "/Author", "dc:creator")] {
        if let Some(v) = pdf_string(&text, name.as_bytes()).or_else(|| xml_text(&String::from_utf8_lossy(&text), xmp_tag)) {
            out.text(key, v);
        }
    }
    // The page tree's root has the largest /Count.
    let pages = find_all(&text, b"/Count")
        .filter_map(|i| {
            let digits: String = text[i + 6..].iter().skip_while(|b| b.is_ascii_whitespace()).take_while(|b| b.is_ascii_digit()).map(|&b| b as char).collect();
            digits.parse::<i64>().ok()
        })
        .max();
    if let Some(n) = pages.filter(|n| *n > 0) {
        out.set("doc.pages", AttrValue::Int(n));
    }
}

fn find_all<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    hay.windows(needle.len()).enumerate().filter(move |(_, w)| *w == needle).map(|(i, _)| i)
}

/// `/Title (Boat repairs)` or `/Title <FEFF…>` → the string.
fn pdf_string(text: &[u8], name: &[u8]) -> Option<String> {
    for i in find_all(text, name) {
        let rest = &text[i + name.len()..];
        let Some(start) = rest.iter().position(|b| !b.is_ascii_whitespace()) else { continue };
        let rest = &rest[start..];
        let bytes = match rest.first() {
            Some(b'(') => {
                let (mut out, mut depth, mut esc) = (Vec::new(), 0, false);
                for &b in &rest[1..] {
                    if esc {
                        out.push(if b == b'n' { b'\n' } else { b });
                        esc = false;
                        continue;
                    }
                    match b {
                        b'\\' => esc = true,
                        b'(' => {
                            depth += 1;
                            out.push(b)
                        }
                        b')' if depth == 0 => break,
                        b')' => {
                            depth -= 1;
                            out.push(b)
                        }
                        b => out.push(b),
                    }
                }
                out
            }
            Some(b'<') if rest.get(1) != Some(&b'<') => {
                let Some(end) = rest.iter().position(|&b| b == b'>') else { continue };
                let hex: Vec<u8> = rest[1..end].iter().copied().filter(|b| b.is_ascii_hexdigit()).collect();
                hex.chunks(2).filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()).collect()
            }
            _ => continue,
        };
        let s = match bytes.strip_prefix(&[0xfe, 0xff]) {
            Some(utf16) => String::from_utf16_lossy(&utf16.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect::<Vec<_>>()),
            None => bytes.iter().map(|&b| b as char).collect(),
        };
        if !s.trim().is_empty() {
            return Some(s);
        }
    }
    None
}

/// The text inside XML element `tag` (`<dc:title><rdf:Alt><rdf:li>Boat</rdf:li>…`: "Boat").
fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let mut from = 0;
    let after = loop {
        let start = from + xml[from..].find(&open)?;
        let after = &xml[start + open.len()..];
        if after.starts_with(['>', ' ', '\n', '\t', '\r']) {
            break after;
        }
        from = start + open.len();
    };
    let body_start = after.find('>')? + 1;
    let close = format!("</{tag}>");
    let body = &after[body_start..body_start + after[body_start..].find(&close)?];
    // Inner elements (rdf:Alt, rdf:li) are skipped: the text between them.
    let mut text = String::new();
    let mut in_tag = false;
    for c in body.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => text.push(c),
            _ => {}
        }
    }
    let text = text.trim().replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&");
    (!text.is_empty()).then_some(text)
}

/// A zip package's own type: OpenDocument and EPUB name it in their
/// `mimetype` part; Office Open XML by its folders.
fn package_mime<R: Read + Seek>(r: &mut R) -> Option<&'static str> {
    r.seek(SeekFrom::Start(0)).ok()?;
    let mut zip = zip::ZipArchive::new(BufReader::new(r)).ok()?;
    if let Ok(f) = zip.by_name("mimetype") {
        let mut m = String::new();
        f.take(200).read_to_string(&mut m).ok()?;
        return [
            "application/epub+zip",
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.spreadsheet",
            "application/vnd.oasis.opendocument.presentation",
            "application/vnd.oasis.opendocument.graphics",
        ]
        .into_iter()
        .find(|known| m.trim() == *known);
    }
    let has = |prefix: &str| zip.file_names().any(|n| n.starts_with(prefix));
    if has("word/") {
        Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    } else if has("xl/") {
        Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    } else if has("ppt/") {
        Some("application/vnd.openxmlformats-officedocument.presentationml.presentation")
    } else {
        None
    }
}

/// Office Open XML, OpenDocument and EPUB: zip packages with the document's
/// properties in a known part (read from the zip's directory at the end,
/// then that part alone).
fn packaged<R: Read + Seek>(r: &mut R, mime: &str, out: &mut Extracted) {
    if r.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    let Ok(mut zip) = zip::ZipArchive::new(BufReader::new(r)) else { return };
    let mut part = |name: &str| -> Option<String> {
        let f = zip.by_name(name).ok()?;
        let mut s = String::new();
        f.take(1 << 20).read_to_string(&mut s).ok()?;
        Some(s)
    };
    let (title, author, pages) = if mime.starts_with("application/vnd.openxmlformats-officedocument") {
        let core = part("docProps/core.xml").unwrap_or_default();
        let app = part("docProps/app.xml").unwrap_or_default();
        (xml_text(&core, "dc:title"), xml_text(&core, "dc:creator"), xml_text(&app, "Pages").or_else(|| xml_text(&app, "Slides")))
    } else if mime.starts_with("application/vnd.oasis.opendocument") {
        let meta = part("meta.xml").unwrap_or_default();
        let pages = meta.split("meta:page-count=\"").nth(1).and_then(|r| r.split('"').next()).map(String::from);
        (xml_text(&meta, "dc:title"), xml_text(&meta, "meta:initial-creator").or_else(|| xml_text(&meta, "dc:creator")), pages)
    } else if mime == "application/epub+zip" {
        let opf_path = part("META-INF/container.xml").and_then(|c| c.split("full-path=\"").nth(1).and_then(|r| r.split('"').next()).map(String::from));
        let opf = opf_path.and_then(|p| part(&p)).unwrap_or_default();
        (xml_text(&opf, "dc:title"), xml_text(&opf, "dc:creator"), None)
    } else {
        return;
    };
    if let Some(t) = title {
        out.text("doc.title", t);
    }
    if let Some(a) = author {
        out.text("doc.author", a);
    }
    if let Some(n) = pages.and_then(|n| n.trim().parse().ok()) {
        out.set("doc.pages", AttrValue::Int(n));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
        v
    }

    fn get<'a>(e: &'a Extracted, k: &str) -> Option<&'a AttrValue> {
        e.attrs.iter().find(|(key, _)| key == k).map(|(_, v)| v)
    }

    #[test]
    fn png_size_and_type() {
        let data = png(1920, 1080);
        let e = extract(&mut Cursor::new(&data), data.len() as u64, None);
        assert_eq!(e.kind, Some("image"));
        assert_eq!(get(&e, "mime"), Some(&AttrValue::Str("image/png".into())));
        assert_eq!(get(&e, "width"), Some(&AttrValue::Int(1920)));
        assert_eq!(get(&e, "height"), Some(&AttrValue::Int(1080)));
    }

    #[test]
    fn text_and_unknown() {
        let e = extract(&mut Cursor::new("tere, maailm õhtul"), 19, None);
        assert_eq!((e.kind, get(&e, "mime")), (Some("text"), Some(&AttrValue::Str("text/plain".into()))));
        let e = extract(&mut Cursor::new([0u8, 1, 2, 0xff, 0xfe]), 5, None);
        assert_eq!(e, Extracted::default());
    }

    #[test]
    fn wav_length() {
        // One second of 8 kHz, 8-bit mono silence.
        let mut v = b"RIFF".to_vec();
        v.extend_from_slice(&(36u32 + 8000).to_le_bytes());
        v.extend_from_slice(b"WAVEfmt \x10\0\0\0\x01\0\x01\0");
        v.extend_from_slice(&8000u32.to_le_bytes());
        v.extend_from_slice(&8000u32.to_le_bytes());
        v.extend_from_slice(b"\x01\0\x08\0data");
        v.extend_from_slice(&8000u32.to_le_bytes());
        v.extend(std::iter::repeat_n(128u8, 8000));
        let e = extract(&mut Cursor::new(&v), v.len() as u64, None);
        assert_eq!(e.kind, Some("audio"));
        assert_eq!(get(&e, "duration"), Some(&AttrValue::Int(1)));
    }

    #[test]
    fn markdown_by_name() {
        let md = "\u{feff}# Boat repairs\n\nThe hull first.\n";
        let e = extract(&mut Cursor::new(md), md.len() as u64, Some("/notes/boat.md"));
        assert_eq!(get(&e, "mime"), Some(&AttrValue::Str("text/markdown".into())));
        assert_eq!(get(&e, "doc.title"), Some(&AttrValue::Str("Boat repairs".into())));
    }

    #[test]
    fn pdf_info() {
        let pdf = b"%PDF-1.4\n1 0 obj << /Type /Pages /Kids [3 0 R] /Count 3 >> endobj\n2 0 obj << /Title (Boat \\(hull\\) repairs) /Author <FEFF004D00E4007200740065> >> endobj\ntrailer << /Info 2 0 R >>\n%%EOF\n";
        let e = extract(&mut Cursor::new(&pdf[..]), pdf.len() as u64, None);
        assert_eq!(e.kind, Some("document"));
        assert_eq!(get(&e, "doc.title"), Some(&AttrValue::Str("Boat (hull) repairs".into())));
        assert_eq!(get(&e, "doc.author"), Some(&AttrValue::Str("Märte".into())));
        assert_eq!(get(&e, "doc.pages"), Some(&AttrValue::Int(3)));
    }

    #[test]
    fn docx_properties() {
        use std::io::Write;
        let mut buf = Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let o = zip::write::SimpleFileOptions::default();
            z.start_file("[Content_Types].xml", o).unwrap();
            z.write_all(b"<Types/>").unwrap();
            z.start_file("word/document.xml", o).unwrap();
            z.write_all(b"<w:document/>").unwrap();
            z.start_file("docProps/core.xml", o).unwrap();
            z.write_all(b"<cp:coreProperties><dc:title>Club rules</dc:title><dc:creator>Vootele</dc:creator></cp:coreProperties>").unwrap();
            z.start_file("docProps/app.xml", o).unwrap();
            z.write_all(b"<Properties><Pages>4</Pages></Properties>").unwrap();
            z.finish().unwrap();
        }
        let data = buf.into_inner();
        let e = extract(&mut Cursor::new(&data), data.len() as u64, Some("rules.docx"));
        assert_eq!(e.kind, Some("document"), "{e:?}");
        assert_eq!(get(&e, "doc.title"), Some(&AttrValue::Str("Club rules".into())));
        assert_eq!(get(&e, "doc.author"), Some(&AttrValue::Str("Vootele".into())));
        assert_eq!(get(&e, "doc.pages"), Some(&AttrValue::Int(4)));
    }

    #[test]
    fn times_and_keys() {
        assert_eq!(exif_time("2026:07:14 18:22:05"), "2026-07-14T18:22:05");
        assert!(is_extracted_key("exif.iso") && is_extracted_key("audio.artist") && is_extracted_key("mime") && is_extracted_key(MARKER));
        assert!(!is_extracted_key("album") && !is_extracted_key("path") && !is_extracted_key("mimetype"));
    }
}
