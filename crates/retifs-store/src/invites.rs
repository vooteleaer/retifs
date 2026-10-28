//! Invitations (ADR-0020): those this node made and keeps pending until
//! redeemed, and those it was given and still has to redeem.

use redb::{ReadableTable, TableDefinition};
use retifs_core::invite::Invitation;

use crate::{SlabStore, StoreError};

/// Invitation ID → spent(1) ‖ u16 len ‖ namespace ‖ the invitation (canonical).
const INVITES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("invites");
/// Namespace name → an invitation to redeem there (canonical).
const REDEEMS: TableDefinition<&str, &[u8]> = TableDefinition::new("redeems");

pub(crate) fn open_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(INVITES)?;
    w.open_table(REDEEMS)?;
    Ok(())
}

/// An invitation this node made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MadeInvite {
    pub ns: String,
    pub invitation: Invitation,
    pub spent: bool,
}

fn encode(m: &MadeInvite) -> Vec<u8> {
    let mut v = vec![m.spent as u8];
    v.extend_from_slice(&(m.ns.len() as u16).to_be_bytes());
    v.extend_from_slice(m.ns.as_bytes());
    v.extend_from_slice(&m.invitation.encode());
    v
}

fn decode(v: &[u8]) -> Option<MadeInvite> {
    let spent = *v.first()? == 1;
    let len = u16::from_be_bytes(v.get(1..3)?.try_into().ok()?) as usize;
    let ns = String::from_utf8(v.get(3..3 + len)?.to_vec()).ok()?;
    let invitation = Invitation::decode(v.get(3 + len..)?).ok()?;
    Some(MadeInvite { ns, invitation, spent })
}

impl SlabStore {
    pub fn put_invite(&self, m: &MadeInvite) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(INVITES)?.insert(m.invitation.id().as_slice(), encode(m).as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn invite(&self, id: &[u8; 32]) -> Result<Option<MadeInvite>, StoreError> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(INVITES)?.get(id.as_slice())?.and_then(|v| decode(v.value())))
    }

    pub fn invites(&self) -> Result<Vec<MadeInvite>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(INVITES)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            if let Some(m) = decode(e?.1.value()) {
                out.push(m);
            }
        }
        Ok(out)
    }

    pub fn remove_invite(&self, id: &[u8; 32]) -> Result<bool, StoreError> {
        let w = self.write()?;
        let removed = w.open_table(INVITES)?.remove(id.as_slice())?.is_some();
        w.commit()?;
        Ok(removed)
    }

    pub fn put_redeem(&self, ns: &str, invitation: &Invitation) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(REDEEMS)?.insert(ns, invitation.encode().as_slice())?;
        w.commit()?;
        Ok(())
    }

    pub fn redeems(&self) -> Result<Vec<(String, Invitation)>, StoreError> {
        let r = self.db.begin_read()?;
        let t = r.open_table(REDEEMS)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            if let Ok(i) = Invitation::decode(v.value()) {
                out.push((k.value().to_string(), i));
            }
        }
        Ok(out)
    }

    pub fn remove_redeem(&self, ns: &str) -> Result<(), StoreError> {
        let w = self.write()?;
        w.open_table(REDEEMS)?.remove(ns)?;
        w.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use retifs_core::channel::ChannelAddr;

    #[test]
    fn invites_and_redeems_persist() {
        let dir = tempfile::tempdir().unwrap();
        let store = SlabStore::open(dir.path()).unwrap();
        let inv = Invitation {
            ns: ChannelAddr { writer: [1; 32], read_key: [2; 32] },
            node: [3; 16],
            secret: [4; 32],
            grant: false,
            keys: vec![],
            until: None,
            expires: 5,
            q: None,
        };
        let m = MadeInvite { ns: "family".into(), invitation: inv.clone(), spent: false };
        store.put_invite(&m).unwrap();
        assert_eq!(store.invite(&inv.id()).unwrap(), Some(m.clone()));
        store.put_invite(&MadeInvite { spent: true, ..m.clone() }).unwrap();
        assert!(store.invite(&inv.id()).unwrap().unwrap().spent);
        assert_eq!(store.invites().unwrap().len(), 1);
        assert!(store.remove_invite(&inv.id()).unwrap());
        assert_eq!(store.invite(&inv.id()).unwrap(), None);
        store.put_redeem("calendar", &inv).unwrap();
        assert_eq!(store.redeems().unwrap(), vec![("calendar".to_string(), inv)]);
        store.remove_redeem("calendar").unwrap();
        assert!(store.redeems().unwrap().is_empty());
    }
}
