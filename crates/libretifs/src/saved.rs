//! Saved queries (ADR-0020): records in the user's own namespace `me`, so
//! every device of theirs has them. `type = retifs.query`, `name`, `query`
//! (terms as `retifs query` takes them, comma-separated) and `scope`: the
//! namespaces it looks in, by their creators' keys (stable, and the same on
//! every device whatever each calls them); empty: every namespace.
//!
//! One convention for the CLI, the desktop utility's Find and any app.

use std::collections::HashMap;

use crate::{AttrValue, Client, Request, Response};

/// The user's own namespace: contacts, saved queries, settings.
pub const ME: &str = "me";
pub const TYPE: &str = "retifs.query";

#[derive(Debug, Clone, PartialEq)]
pub struct SavedQuery {
    pub id: String,
    pub name: String,
    pub query: String,
    /// Creator keys (hex); empty: every namespace.
    pub scope: Vec<String>,
}

impl SavedQuery {
    pub fn terms(&self) -> Vec<String> {
        split_terms(&self.query)
    }
}

/// `a=1, b^=x` → `["a=1", "b^=x"]`.
pub fn split_terms(query: &str) -> Vec<String> {
    query.split(',').map(str::trim).filter(|t| !t.is_empty()).map(String::from).collect()
}

fn err(r: Result<Response, crate::ClientError>) -> Result<Response, String> {
    match r {
        Ok(Response::Error { message }) => Err(message),
        Ok(r) => Ok(r),
        Err(e) => Err(e.to_string()),
    }
}

/// The saved queries, by name.
pub async fn list(c: &mut Client) -> Vec<SavedQuery> {
    let req = Request::Query { ns: ME.into(), terms: vec![format!("type={TYPE}")], at: None };
    let Ok(Response::Records { records }) = c.call(req).await else { return Vec::new() };
    let mut out: Vec<SavedQuery> = records
        .iter()
        .filter_map(|r| {
            let get = |k: &str| r.attrs.iter().find(|(key, _)| key == k).map(|(_, v)| v);
            let text = |k: &str| match get(k) {
                Some(AttrValue::Str(s)) => Some(s.clone()),
                _ => None,
            };
            let scope = match get("scope") {
                Some(AttrValue::List(items)) => items.iter().filter_map(|v| if let AttrValue::Str(s) = v { Some(s.clone()) } else { None }).collect(),
                _ => Vec::new(),
            };
            Some(SavedQuery { id: r.id.clone(), name: text("name")?, query: text("query")?, scope })
        })
        .collect();
    out.sort_by_key(|q| q.name.to_lowercase());
    out
}

/// Every namespace on this device but `me`.
pub async fn namespaces(c: &mut Client) -> Result<Vec<String>, String> {
    match err(c.call(Request::Namespaces).await)? {
        Response::Names { names } => Ok(names.into_iter().filter(|n| n != ME).collect()),
        _ => Ok(Vec::new()),
    }
}

/// A namespace's creator key (hex), from its address (`retifs-ch:1:<creator>:<read key>`).
pub async fn creator(c: &mut Client, ns: &str) -> Result<String, String> {
    match err(c.call(Request::NsInfo { ns: ns.into() }).await)? {
        Response::Namespace(v) => v.address.split(':').nth(2).map(String::from).ok_or_else(|| "a malformed address".into()),
        _ => Err("unexpected answer".into()),
    }
}

/// This device's namespaces by creator key.
pub async fn by_creator(c: &mut Client) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for n in namespaces(c).await? {
        if let Ok(w) = creator(c, &n).await {
            out.insert(w, n);
        }
    }
    Ok(out)
}

/// Where a saved query looks on this device: its namespaces' local names,
/// and the creator keys of those not here.
pub async fn resolve(c: &mut Client, q: &SavedQuery) -> Result<(Vec<String>, Vec<String>), String> {
    if q.scope.is_empty() {
        return Ok((namespaces(c).await?, Vec::new()));
    }
    let by = by_creator(c).await?;
    let (mut here, mut missing) = (Vec::new(), Vec::new());
    for w in &q.scope {
        match by.get(w) {
            Some(n) => here.push(n.clone()),
            None => missing.push(w.clone()),
        }
    }
    Ok((here, missing))
}

/// Saves (or replaces, by name) `terms` over namespaces `scope` (local
/// names; empty: every namespace).
pub async fn save(c: &mut Client, name: &str, scope: &[String], terms: &[String]) -> Result<(), String> {
    let mut keys = Vec::new();
    for n in scope {
        keys.push(AttrValue::Str(creator(c, n).await?));
    }
    let attrs = vec![
        ("name".to_string(), AttrValue::Str(name.into())),
        ("query".to_string(), AttrValue::Str(terms.join(", "))),
        ("scope".to_string(), AttrValue::List(keys)),
    ];
    let req = match list(c).await.into_iter().find(|q| q.name.eq_ignore_ascii_case(name)) {
        Some(q) => Request::RecordSet { ns: ME.into(), id: q.id, attrs, unset: vec![], data: None },
        None => {
            let mut attrs = attrs;
            attrs.push(("type".into(), AttrValue::Str(TYPE.into())));
            Request::RecordCreate { ns: ME.into(), attrs, data: None }
        }
    };
    err(c.call(req).await).map(|_| ())
}

/// Removes saved query `name`.
pub async fn remove(c: &mut Client, name: &str) -> Result<(), String> {
    let q = list(c).await.into_iter().find(|q| q.name.eq_ignore_ascii_case(name)).ok_or_else(|| format!("no saved query {name}"))?;
    err(c.call(Request::RecordDelete { ns: ME.into(), id: q.id }).await).map(|_| ())
}

#[cfg(test)]
mod tests {
    #[test]
    fn terms_split_on_commas() {
        assert_eq!(super::split_terms(" type=photo,album=Prangli 2026 ,, "), ["type=photo", "album=Prangli 2026"]);
    }
}
