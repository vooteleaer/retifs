//! Micron (NomadNet's page markup) rendered as HTML, for NomadNet pages
//! browsed through the gateway. Covers what pages use most: headings (`>`,
//! `>>`, `>>>`, `<` to reset), dividers (`-`), comments and directives
//! (`#`, `#!`), literal blocks (`` `= ``), escapes (`\`), and the inline
//! tags `` `! `` bold, `` `* `` italic, `` `_ `` underline, `` `F ``/`` `f ``
//! and `` `B ``/`` `b `` colours (`abc`, `T` + 6 hex digits, `g` + 2 digits
//! grey), `` `c ``/`` `l ``/`` `r ``/`` `a `` alignment, ``` `` ``` reset,
//! links `` `[label`target`fields] `` and input fields `` `<…> `` (shown
//! read-only: the gateway only reads).

use crate::site::escape_html;

/// Where a micron link goes, as the gateway serves it.
pub trait Links {
    /// The URL for `path` on the node `node` (`None`: the page's own node),
    /// with the link's variables (`var_name=value`).
    fn page(&self, node: Option<&str>, path: &str, vars: &[(String, String)]) -> String;
}

#[derive(Clone, Default, PartialEq)]
struct Style {
    bold: bool,
    italic: bool,
    underline: bool,
    fg: Option<String>,
    bg: Option<String>,
}

impl Style {
    fn css(&self) -> String {
        let mut s = String::new();
        if self.bold {
            s.push_str("font-weight:bold;");
        }
        if self.italic {
            s.push_str("font-style:italic;");
        }
        if self.underline {
            s.push_str("text-decoration:underline;");
        }
        if let Some(c) = &self.fg {
            s.push_str(&format!("color:{c};"));
        }
        if let Some(c) = &self.bg {
            s.push_str(&format!("background:{c};"));
        }
        s
    }
}

/// A micron colour (`abc`, `Tabcdef`, `gNN`) as CSS, and how many characters it took.
fn colour(s: &[char]) -> Option<(String, usize)> {
    if s.first() == Some(&'T') && s.len() >= 7 && s[1..7].iter().all(|c| c.is_ascii_hexdigit()) {
        return Some((format!("#{}", s[1..7].iter().collect::<String>()), 7));
    }
    if s.len() >= 3 && s[0] == 'g' && s[1].is_ascii_digit() && s[2].is_ascii_digit() {
        let pct: u32 = s[1..3].iter().collect::<String>().parse().ok()?;
        let v = (pct * 255 / 99).min(255);
        return Some((format!("#{v:02x}{v:02x}{v:02x}"), 3));
    }
    if s.len() >= 3 && s[..3].iter().all(|c| c.is_ascii_hexdigit()) {
        return Some((format!("#{}", s[..3].iter().collect::<String>()), 3));
    }
    None
}

/// Renders a micron page as an HTML fragment.
pub fn to_html(page: &str, links: &impl Links) -> String {
    let mut out = String::new();
    let mut style = Style::default();
    let mut align = "left";
    let mut literal = false;
    let mut depth = 0usize;
    for line in page.lines() {
        if line.trim_end() == "`=" {
            literal = !literal;
            continue;
        }
        if literal {
            out.push_str(&format!("<div class=lit>{}</div>", escape_html(line)));
            continue;
        }
        if line.starts_with('#') {
            continue; // a comment or a directive (#!)
        }
        if line.starts_with('<') && line.trim() == "<" {
            depth = 0;
            continue;
        }
        let heading = line.chars().take_while(|c| *c == '>').count();
        if heading > 0 {
            depth = heading.min(3);
            let text = inline(&line[heading..], &mut Style::default(), &mut align.to_string(), links);
            out.push_str(&format!("<h{n} class=h{n}>{text}</h{n}>", n = depth));
            continue;
        }
        if let Some(rest) = line.strip_prefix('-')
            && rest.chars().count() <= 1
        {
            let ch = rest.chars().next().unwrap_or('\u{2500}');
            out.push_str(&format!("<div class=hr aria-hidden=true>{}</div>", escape_html(&ch.to_string().repeat(80))));
            continue;
        }
        let mut a = align.to_string();
        let body = inline(line, &mut style, &mut a, links);
        align = match a.as_str() {
            "center" => "center",
            "right" => "right",
            _ => "left",
        };
        let indent = if depth > 1 { format!("padding-left:{}ch;", (depth - 1) * 2) } else { String::new() };
        if body.is_empty() {
            out.push_str("<div class=l>&nbsp;</div>");
        } else {
            out.push_str(&format!("<div class=l style=\"text-align:{a};{indent}\">{body}</div>"));
        }
    }
    out
}

/// One line's inline markup. `style` and `align` carry over to the next line, as in micron.
fn inline(line: &str, style: &mut Style, align: &mut String, links: &impl Links) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut text = String::new();
    let mut open = false;
    let flush = |out: &mut String, text: &mut String, style: &Style, open: &mut bool| {
        if text.is_empty() {
            return;
        }
        let css = style.css();
        if css.is_empty() {
            out.push_str(&escape_html(text));
        } else {
            out.push_str(&format!("<span style=\"{css}\">{}</span>", escape_html(text)));
        }
        text.clear();
        *open = false;
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            text.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if c != '`' {
            text.push(c);
            i += 1;
            continue;
        }
        // A tag.
        let Some(&t) = chars.get(i + 1) else {
            i += 1;
            continue;
        };
        flush(&mut out, &mut text, style, &mut open);
        i += 2;
        match t {
            '!' => style.bold = !style.bold,
            '*' => style.italic = !style.italic,
            '_' => style.underline = !style.underline,
            '`' => *style = Style::default(),
            'f' => style.fg = None,
            'b' => style.bg = None,
            'F' | 'B' => {
                if let Some((css, n)) = colour(&chars[i..]) {
                    if t == 'F' {
                        style.fg = Some(css);
                    } else {
                        style.bg = Some(css);
                    }
                    i += n;
                }
            }
            'c' => *align = "center".into(),
            'l' | 'a' => *align = "left".into(),
            'r' => *align = "right".into(),
            '[' => {
                let end = chars[i..].iter().position(|c| *c == ']').map_or(chars.len(), |p| i + p);
                let inner: String = chars[i..end].iter().collect();
                out.push_str(&link(&inner, style, links));
                i = (end + 1).min(chars.len());
            }
            '<' => {
                let end = chars[i..].iter().position(|c| *c == '>').map_or(chars.len(), |p| i + p);
                let inner: String = chars[i..end].iter().collect();
                // `<flags|name`default>`: shown as a read-only box with its default.
                let default = inner.split_once('`').map(|(_, d)| d).unwrap_or("");
                out.push_str(&format!("<input class=field disabled value=\"{}\">", escape_html(default)));
                i = (end + 1).min(chars.len());
            }
            _ => {}
        }
    }
    flush(&mut out, &mut text, style, &mut open);
    out
}

/// `label`target`fields` (or `target`, or `label`target`) as an HTML link.
fn link(inner: &str, style: &Style, links: &impl Links) -> String {
    let parts: Vec<&str> = inner.split('`').collect();
    let (label, target, fields) = match parts.as_slice() {
        [t] => (*t, *t, ""),
        [l, t] => (*l, *t, ""),
        [l, t, f, ..] => (*l, *t, *f),
        [] => return String::new(),
    };
    let vars: Vec<(String, String)> = fields
        .split('|')
        .filter_map(|f| f.split_once('='))
        .map(|(k, v)| (format!("var_{k}"), v.to_string()))
        .collect();
    let css = style.css();
    let label = escape_html(if label.is_empty() { target } else { label });
    let href = if let Some(path) = target.strip_prefix(':') {
        Some(links.page(None, path, &vars))
    } else if target.starts_with('/') {
        Some(links.page(None, target, &vars))
    } else if let Some((node, path)) = target.split_once(':')
        && node.len() == 32
        && node.chars().all(|c| c.is_ascii_hexdigit())
    {
        Some(links.page(Some(&node.to_ascii_lowercase()), path, &vars))
    } else if target.len() == 32 && target.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(links.page(Some(&target.to_ascii_lowercase()), "/page/index.mu", &vars))
    } else {
        None // lxmf@…, the web: not something this gateway opens
    };
    match href {
        Some(h) => format!("<a href=\"{}\" style=\"{css}\">{label}</a>", escape_html(&h)),
        None => format!("<span class=ext title=\"{}\" style=\"{css}\">{label}</span>", escape_html(target)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct L;
    impl Links for L {
        fn page(&self, node: Option<&str>, path: &str, vars: &[(String, String)]) -> String {
            let q: Vec<String> = vars.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{}{path}{}{}", node.map(|n| format!("//{n}")).unwrap_or_default(), if q.is_empty() { "" } else { "?" }, q.join("&"))
        }
    }

    #[test]
    fn headings_dividers_and_comments() {
        let h = to_html("#!c=0\n# a comment\n>Title\n>>Sub\n-\ntext", &L);
        assert!(h.starts_with("<h1 class=h1>Title</h1><h2 class=h2>Sub</h2><div class=hr"));
        assert!(!h.contains("comment") && !h.contains("c=0"));
        assert!(h.ends_with("padding-left:2ch;\">text</div>"));
    }

    #[test]
    fn inline_styles_carry_and_reset() {
        let h = to_html("`!bold`! plain `F0f0green`f `*it\nstill italic``\nplain", &L);
        assert!(h.contains("<span style=\"font-weight:bold;\">bold</span> plain <span style=\"color:#0f0;\">green</span>"));
        assert!(h.contains("<span style=\"font-style:italic;\">still italic</span>"));
        assert!(h.ends_with(">plain</div>"));
        assert!(to_html("`FT00ff00x`Bg99y", &L).contains("color:#00ff00;\">x</span><span style=\"color:#00ff00;background:#ffffff;\">y"));
    }

    #[test]
    fn links_fields_escapes_and_literals() {
        let h = to_html("`[Home`:/page/index.mu] `[Other`0123456789abcdef0123456789ABCDEF:/page/a.mu`n=1|f] `[x`lxmf@abc]", &L);
        assert!(h.contains("<a href=\"/page/index.mu\" style=\"\">Home</a>"));
        assert!(h.contains("<a href=\"//0123456789abcdef0123456789abcdef/page/a.mu?var_n=1\""));
        assert!(h.contains("<span class=ext title=\"lxmf@abc\""));
        let h = to_html("`<24|name`Alice>", &L);
        assert!(h.contains("<input class=field disabled value=\"Alice\">"));
        let h = to_html("\\`! not bold <b>\n`=\n`! >raw\n`=", &L);
        assert!(h.contains("`! not bold &lt;b&gt;") && h.contains("<div class=lit>`! &gt;raw</div>"));
    }
}
