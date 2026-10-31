//! Haiku's query language, as `fs_query` and Tracker's Find send it, over
//! retifs records: `(city=="Tartu")&&(population>50000)`,
//! `name=="*[tT][aA][rR]*"`, `!(BEOS:TYPE=="text/plain")`.
//!
//! - Terms: `attribute op value`, op one of `== != < > <= >=`; a value is
//!   quoted (`"…"` or `'…'`, `\` escaping) or bare; `==` and `!=` with `*`,
//!   `?` or `[…]` in a string value match as a pattern.
//! - `&&`, `||`, `!` and parentheses.
//! - A node without the attribute matches only `!=` (it isn't the value).
//!
//! The exact parts of the query's top-level AND are also given as retifs
//! terms ([`pushdown`]), so a library held only in part is asked through its
//! index; the whole expression then filters what comes back.

use libretifs::AttrValue;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Term { attr: String, op: Op, value: String, quoted: bool },
}

pub fn parse(q: &str) -> Result<Expr, String> {
    let mut p = Parser { s: q.as_bytes(), i: 0 };
    let e = p.or()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(format!("unexpected {:?} at {} in query {q:?}", &q[p.i..], p.i));
    }
    Ok(e)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.s.get(self.i).is_some_and(|c| c.is_ascii_whitespace()) {
            self.i += 1;
        }
    }

    fn eat(&mut self, t: &str) -> bool {
        self.ws();
        if self.s[self.i..].starts_with(t.as_bytes()) {
            self.i += t.len();
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut e = self.and()?;
        while self.eat("||") {
            e = Expr::Or(Box::new(e), Box::new(self.and()?));
        }
        Ok(e)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut e = self.unary()?;
        while self.eat("&&") {
            e = Expr::And(Box::new(e), Box::new(self.unary()?));
        }
        Ok(e)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat("!") && !self.s[self.i..].starts_with(b"=") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if self.eat("(") {
            let e = self.or()?;
            if !self.eat(")") {
                return Err(format!("missing ) at {}", self.i));
            }
            return Ok(e);
        }
        self.term()
    }

    fn term(&mut self) -> Result<Expr, String> {
        self.ws();
        let attr = if self.s.get(self.i) == Some(&b'"') {
            self.quoted()?
        } else {
            let start = self.i;
            while self.s.get(self.i).is_some_and(|c| !b"=!<>()&| \t\r\n".contains(c)) {
                self.i += 1;
            }
            String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
        };
        if attr.is_empty() {
            return Err(format!("expected an attribute at {}", self.i));
        }
        let op = [("==", Op::Eq), ("!=", Op::Ne), ("<=", Op::Le), (">=", Op::Ge), ("<", Op::Lt), (">", Op::Gt), ("=", Op::Eq)]
            .into_iter()
            .find(|(t, _)| self.eat(t))
            .map(|(_, op)| op)
            .ok_or_else(|| format!("expected an operator after {attr:?}"))?;
        self.ws();
        let (value, quoted) = if matches!(self.s.get(self.i), Some(b'"' | b'\'')) {
            (self.quoted()?, true)
        } else {
            let start = self.i;
            while self.s.get(self.i).is_some_and(|c| !b"()&| \t\r\n".contains(c)) {
                self.i += 1;
            }
            (String::from_utf8_lossy(&self.s[start..self.i]).into_owned(), false)
        };
        Ok(Expr::Term { attr, op, value, quoted })
    }

    fn quoted(&mut self) -> Result<String, String> {
        let q = self.s[self.i];
        self.i += 1;
        let mut out = Vec::new();
        loop {
            match self.s.get(self.i) {
                None => return Err("unterminated string".into()),
                Some(c) if *c == q => {
                    self.i += 1;
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                // An escape keeps the next character, and its backslash too
                // where it escapes a pattern character (matched literally).
                Some(b'\\') if self.i + 1 < self.s.len() => {
                    let n = self.s[self.i + 1];
                    if b"*?[]\\".contains(&n) {
                        out.push(b'\\');
                    }
                    out.push(n);
                    self.i += 2;
                }
                Some(c) => {
                    out.push(*c);
                    self.i += 1;
                }
            }
        }
    }
}

/// What a query is matched against: a node's attributes by name, Haiku's
/// own (`name`, `size`, `last_modified`, `BEOS:TYPE`) included.
pub trait Subject {
    fn get(&self, attr: &str) -> Option<AttrValue>;
}

impl Expr {
    pub fn matches(&self, s: &dyn Subject) -> bool {
        match self {
            Expr::And(a, b) => a.matches(s) && b.matches(s),
            Expr::Or(a, b) => a.matches(s) || b.matches(s),
            Expr::Not(e) => !e.matches(s),
            Expr::Term { attr, op, value, quoted } => match s.get(attr) {
                None => *op == Op::Ne,
                Some(AttrValue::List(items)) => {
                    if *op == Op::Ne {
                        !items.iter().any(|v| compare(v, Op::Eq, value, *quoted))
                    } else {
                        items.iter().any(|v| compare(v, *op, value, *quoted))
                    }
                }
                Some(v) => compare(&v, *op, value, *quoted),
            },
        }
    }
}

fn compare(v: &AttrValue, op: Op, value: &str, quoted: bool) -> bool {
    use std::cmp::Ordering;
    let ord = |o: Ordering| match op {
        Op::Eq => o == Ordering::Equal,
        Op::Ne => o != Ordering::Equal,
        Op::Lt => o == Ordering::Less,
        Op::Gt => o == Ordering::Greater,
        Op::Le => o != Ordering::Greater,
        Op::Ge => o != Ordering::Less,
    };
    match v {
        AttrValue::Str(s) => {
            if matches!(op, Op::Eq | Op::Ne) && is_pattern(value) {
                glob(value.as_bytes(), s.as_bytes()) == (op == Op::Eq)
            } else {
                ord(s.as_str().cmp(&unescape(value)))
            }
        }
        AttrValue::Int(i) => match value.trim().parse::<f64>() {
            Ok(n) => (*i as f64).partial_cmp(&n).is_some_and(ord),
            Err(_) => false,
        },
        AttrValue::Float(f) => match value.trim().parse::<f64>() {
            Ok(n) => f.partial_cmp(&n).is_some_and(ord),
            Err(_) => false,
        },
        AttrValue::Bool(b) => match value.trim() {
            "true" | "1" => ord(b.cmp(&true)),
            "false" | "0" => ord(b.cmp(&false)),
            _ => false,
        },
        _ => {
            let _ = quoted;
            false
        }
    }
}

fn is_pattern(v: &str) -> bool {
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'*' | b'?' | b'[' => return true,
            _ => i += 1,
        }
    }
    false
}

fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Shell-style matching on bytes: `*`, `?`, `[abc]`, `[a-z]`, `[^…]`/`[!…]`,
/// `\` for a literal.
fn glob(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') => (0..=s.len()).any(|k| glob(&p[1..], &s[k..])),
        Some(b'?') => !s.is_empty() && glob(&p[1..], &s[1..]),
        Some(b'[') => {
            let Some(c) = s.first() else { return false };
            let mut i = 1;
            let negate = matches!(p.get(1), Some(b'^' | b'!'));
            if negate {
                i += 1;
            }
            let mut hit = false;
            let mut first = true;
            while i < p.len() && (p[i] != b']' || first) {
                first = false;
                if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|e| *e != b']') {
                    hit |= (p[i]..=p[i + 2]).contains(c);
                    i += 3;
                } else {
                    hit |= p[i] == *c;
                    i += 1;
                }
            }
            if i >= p.len() {
                return p[0] == *c && glob(&p[1..], &s[1..]); // no closing ]: a literal [
            }
            hit != negate && glob(&p[i + 1..], &s[1..])
        }
        Some(b'\\') if p.len() > 1 => s.first() == Some(&p[1]) && glob(&p[2..], &s[1..]),
        Some(c) => s.first() == Some(c) && glob(&p[1..], &s[1..]),
    }
}

/// The parts of the top-level AND that retifs can answer from its index, as
/// its query terms (`key="v"`, `key^=prefix`, `key>=n`, …): exact strings,
/// a pattern that is only a prefix (`Tar*`), numbers. Haiku's own attributes
/// aren't record attributes, except `BEOS:TYPE`, which is the record's `type`.
pub fn pushdown(e: &Expr) -> Vec<String> {
    let mut out = Vec::new();
    collect(e, &mut out);
    out
}

fn collect(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::And(a, b) => {
            collect(a, out);
            collect(b, out);
        }
        Expr::Term { attr, op, value, quoted } => {
            let key = match attr.as_str() {
                "BEOS:TYPE" => "type",
                "name" | "size" | "last_modified" => return,
                k => k,
            };
            // retifs compares by type (an integer never equals a float or a
            // string), Haiku by the attribute's: only strings are narrowed,
            // and nothing that reads as a number or holds an operator.
            let _ = quoted;
            if key.contains(['=', '<', '>', '^', ',']) || key.starts_with("has:") || value.contains(['<', '>', '^']) {
                return;
            }
            if *op != Op::Eq || value.trim().parse::<f64>().is_ok() {
                return;
            }
            let term = if !is_pattern(value) {
                format!("{key}=\"{}\"", unescape(value))
            } else {
                match value.strip_suffix('*') {
                    Some(prefix) if !prefix.is_empty() && !is_pattern(prefix) => format!("{key}^={}", unescape(prefix)),
                    _ => return,
                }
            };
            out.push(term);
        }
        // Under || or !, nothing can be narrowed safely.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct M(HashMap<&'static str, AttrValue>);
    impl Subject for M {
        fn get(&self, a: &str) -> Option<AttrValue> {
            self.0.get(a).cloned()
        }
    }

    fn tartu() -> M {
        M(HashMap::from([
            ("name", AttrValue::Str("Tartu".into())),
            ("city", AttrValue::Str("Tartu".into())),
            ("population", AttrValue::Int(91407)),
            ("lat", AttrValue::Float(58.378)),
            ("capital", AttrValue::Bool(false)),
            ("find", AttrValue::List(vec![AttrValue::Str("tartu".into()), AttrValue::Str("tartumaa".into())])),
            ("BEOS:TYPE", AttrValue::Str("application/x-vnd.retifs.place".into())),
        ]))
    }

    fn q(s: &str) -> bool {
        parse(s).unwrap().matches(&tartu())
    }

    #[test]
    fn terms_and_logic() {
        assert!(q(r#"(city=="Tartu")"#));
        assert!(q(r#"city == 'Tartu'"#));
        assert!(!q(r#"(city=="Tallinn")"#));
        assert!(q(r#"(population>50000)&&(lat<=58.5)"#));
        assert!(!q(r#"(population>100000)||(capital==true)"#));
        assert!(q(r#"!(city=="Tallinn")"#));
        assert!(q(r#"(city!="Tallinn")"#));
        assert!(q(r#"((name=="Tartu")||(name=="Tallinn"))&&(BEOS:TYPE=="application/x-vnd.retifs.place")"#));
        // Missing attributes: only != matches.
        assert!(!q(r#"(author=="x")"#));
        assert!(q(r#"(author!="x")"#));
        // List values: any element.
        assert!(q(r#"(find=="tartumaa")"#));
        assert!(!q(r#"(find!="tartu")"#));
    }

    #[test]
    fn patterns_as_tracker_writes_them() {
        assert!(q(r#"(name=="*[tT][aA][rR]*")"#));
        assert!(q(r#"(name=="T?rtu")"#));
        assert!(q(r#"(name=="[A-Z]artu")"#));
        assert!(!q(r#"(name=="[^T]artu")"#));
        assert!(!q(r#"(name=="*x*")"#));
        assert!(q(r#"(name!="*x*")"#));
        // An escaped * is a literal.
        assert!(!q(r#"(name=="Tar\*")"#));
    }

    #[test]
    fn bad_queries() {
        assert!(parse("(city==").is_err() || !parse("(city==").unwrap().matches(&tartu()));
        assert!(parse("((city==\"x\")").is_err());
        assert!(parse("==\"x\"").is_err());
    }

    #[test]
    fn pushdown_terms() {
        let e = parse(r#"(city=="Tartu")&&(population>=50000)&&(name=="*tar*")&&(BEOS:TYPE=="application/x-vnd.retifs.place")&&(street=="Rüü*")"#).unwrap();
        assert_eq!(pushdown(&e), vec!["city=\"Tartu\"", "type=\"application/x-vnd.retifs.place\"", "street^=Rüü"]);
        // Numbers, quoted or not, are compared by type in retifs: not narrowed.
        assert!(pushdown(&parse(r#"(population=="91407")&&(lat>58)"#).unwrap()).is_empty());
        // Nothing under || or !.
        assert!(pushdown(&parse(r#"(city=="a")||(city=="b")"#).unwrap()).is_empty());
        assert!(pushdown(&parse(r#"!(city=="a")"#).unwrap()).is_empty());
    }
}
