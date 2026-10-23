//! Applications allowed on the local API's app socket (ADR-0004): each has
//! a token (only its hash is kept), the namespaces it may use, whether it may
//! write (and which attribute keys, if limited), and the executable it was
//! first used from (pinned on Linux).

use redb::{ReadableTable, TableDefinition};

use crate::{SlabStore, StoreError};

/// App name → hash(32) ‖ write(1) ‖ u16 n ‖ (u16 len ‖ namespace)* ‖ u16 len ‖ exe
/// [‖ device(16) [‖ u16 n ‖ (u16 len ‖ key)*]]; with keys but no device, the device is zeros.
const APPS: TableDefinition<&str, &[u8]> = TableDefinition::new("apps");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(APPS)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    pub name: String,
    pub token_hash: [u8; 32],
    pub namespaces: Vec<String>,
    pub write: bool,
    /// The executable that first used the token (Linux), if pinned.
    pub exe: Option<String>,
    /// For one of the user's own nodes asking over a Link (ADR-0019): its
    /// `retifs.node` address. Such an entry has no token.
    pub device: Option<[u8; 16]>,
    /// The attribute keys it may write (`exif.*` for a prefix, `@content`,
    /// `@delete`, `@create`); empty: any. A local limit, not a grant.
    pub keys: Vec<String>,
}

impl App {
    /// Whether its key limit lets it write `key`.
    pub fn may_write_key(&self, key: &str) -> bool {
        self.keys.is_empty() || self.keys.iter().any(|k| k == key || k.strip_suffix('*').is_some_and(|p| key.starts_with(p)))
    }
}

fn encode(a: &App) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&a.token_hash);
    v.push(a.write as u8);
    v.extend_from_slice(&(a.namespaces.len() as u16).to_be_bytes());
    for ns in &a.namespaces {
        v.extend_from_slice(&(ns.len() as u16).to_be_bytes());
        v.extend_from_slice(ns.as_bytes());
    }
    let exe = a.exe.as_deref().unwrap_or("");
    v.extend_from_slice(&(exe.len() as u16).to_be_bytes());
    v.extend_from_slice(exe.as_bytes());
    if a.device.is_some() || !a.keys.is_empty() {
        v.extend_from_slice(&a.device.unwrap_or([0; 16]));
    }
    if !a.keys.is_empty() {
        v.extend_from_slice(&(a.keys.len() as u16).to_be_bytes());
        for k in &a.keys {
            v.extend_from_slice(&(k.len() as u16).to_be_bytes());
            v.extend_from_slice(k.as_bytes());
        }
    }
    v
}

fn decode(name: &str, v: &[u8]) -> Option<App> {
    let mut r = v;
    let mut take = |n: usize| -> Option<&[u8]> {
        let (a, b) = r.split_at_checked(n)?;
        r = b;
        Some(a)
    };
    let token_hash: [u8; 32] = take(32)?.try_into().ok()?;
    let write = take(1)?[0] == 1;
    let n = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let mut namespaces = Vec::new();
    for _ in 0..n {
        let len = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
        namespaces.push(String::from_utf8(take(len)?.to_vec()).ok()?);
    }
    let len = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
    let exe = String::from_utf8(take(len)?.to_vec()).ok()?;
    let device: Option<[u8; 16]> = take(16).and_then(|d| d.try_into().ok()).filter(|d| *d != [0; 16]);
    let mut keys = Vec::new();
    if let Some(n) = take(2) {
        for _ in 0..u16::from_be_bytes(n.try_into().ok()?) {
            let len = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
            keys.push(String::from_utf8(take(len)?.to_vec()).ok()?);
        }
    }
    Some(App { name: name.to_string(), token_hash, namespaces, write, exe: (!exe.is_empty()).then_some(exe), device, keys })
}

impl SlabStore {
    pub fn put_app(&self, app: &App) -> Result<(), StoreError> {
        let w = self.db.begin_write()?;
        w.open_table(APPS)?.insert(app.name.as_str(), encode(app).as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn remove_app(&self, name: &str) -> Result<bool, StoreError> {
        let w = self.db.begin_write()?;
        let removed = w.open_table(APPS)?.remove(name)?.is_some();
        w.commit()?;
        Ok(removed)
    }

    pub fn apps(&self) -> Result<Vec<App>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(APPS)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            if let Some(a) = decode(k.value(), v.value()) {
                out.push(a);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apps_round_trip() {
        let a = App { name: "viewer".into(), token_hash: [7; 32], namespaces: vec!["photos".into(), "notes".into()], write: false, exe: Some("/usr/bin/viewer".into()), device: None, keys: vec![] };
        assert_eq!(decode("viewer", &encode(&a)), Some(a.clone()));
        let b = App { exe: None, write: true, namespaces: vec![], ..a };
        assert_eq!(decode("viewer", &encode(&b)), Some(b.clone()));
        let c = App { device: Some([9; 16]), ..b };
        assert_eq!(decode("viewer", &encode(&c)), Some(c.clone()));
        let d = App { keys: vec!["mime".into(), "exif.*".into()], ..c.clone() };
        assert_eq!(decode("viewer", &encode(&d)), Some(d.clone()));
        let e = App { device: None, ..d };
        assert_eq!(decode("viewer", &encode(&e)), Some(e.clone()));
        assert!(e.may_write_key("exif.FNumber") && e.may_write_key("mime"));
        assert!(!e.may_write_key("path") && !e.may_write_key("mimetype"));
        assert!(c.may_write_key("path"));
    }
}
