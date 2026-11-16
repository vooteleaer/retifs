//! Merges files that have two records at one path into one:
//!
//!     cargo run -p libretifs --example merge_twins -- STORE LIB [--apply]
//!
//! Before 2026-11-16 the Windows sync could write a file that had just been
//! changed and moved in the folder (MusicBrainz Picard: tags, then renames)
//! as a second record at the same path. Of each pair the older record (by
//! `mtime`) is the original, with its history, tags and keep marks: it gets
//! the newer one's content as its next version (by reference, nothing is
//! copied), and the newer record is deleted. Without `--apply` it only
//! tells what it would do.

use std::collections::BTreeMap;

use libretifs::{AttrValue, Client, RecordView, Request, Response, TxStep};

fn attr<'a>(r: &'a RecordView, key: &str) -> Option<&'a AttrValue> {
    r.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn mtime(r: &RecordView) -> i64 {
    match attr(r, "mtime") {
        Some(AttrValue::Int(n)) => *n,
        _ => 0,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let store = std::path::PathBuf::from(args.next().expect("STORE"));
    let ns = args.next().expect("LIB");
    let apply = args.any(|a| a == "--apply");
    let mut c = Client::connect(&store).await.expect("connect");
    let records = match c.call(Request::Query { ns: ns.clone(), terms: vec!["has:path".into()], at: None }).await.expect("query") {
        Response::Records { records } => records,
        r => panic!("unexpected {r:?}"),
    };
    let mut by_path: BTreeMap<String, Vec<RecordView>> = BTreeMap::new();
    for r in records {
        if let Some(AttrValue::Str(p)) = attr(&r, "path") {
            by_path.entry(p.clone()).or_default().push(r);
        }
    }
    let (mut same, mut newer, mut skipped) = (0, 0, 0);
    let mut steps = Vec::new();
    for (path, mut rs) in by_path.into_iter().filter(|(_, rs)| rs.len() > 1) {
        if rs.iter().any(|r| r.blocks.is_empty()) {
            skipped += 1;
            println!("left alone (a folder, or no content): {path}");
            continue;
        }
        rs.sort_by_key(mtime);
        let (keep, rest) = rs.split_first().unwrap();
        let last = rest.last().unwrap();
        let mut attrs = vec![("mtime".to_string(), AttrValue::Int(mtime(last)))];
        if let Some(size) = attr(last, "size") {
            attrs.push(("size".into(), size.clone()));
        }
        if keep.blocks.first() == last.blocks.first() {
            same += 1;
            steps.push(TxStep::Set { id: keep.id.clone(), attrs, unset: vec![], data: None, blocks: None });
        } else {
            newer += 1;
            // Read again by the extractor: the tags are what changed.
            steps.push(TxStep::Set { id: keep.id.clone(), attrs, unset: vec!["extracted".into()], data: None, blocks: Some(last.blocks.clone()) });
        }
        steps.extend(rest.iter().map(|r| TxStep::Delete { id: r.id.clone() }));
    }
    println!("{newer} pair(s) with a newer version, {same} with the same content, {skipped} left alone");
    if !apply {
        println!("dry run; --apply to merge");
        return;
    }
    // A pair's steps stay together: Set, then its Deletes.
    let mut batch = Vec::new();
    let mut done = 0;
    for step in steps {
        if matches!(step, TxStep::Set { .. }) && batch.len() >= 200 {
            done += send(&mut c, &ns, std::mem::take(&mut batch)).await;
        }
        batch.push(step);
    }
    done += send(&mut c, &ns, batch).await;
    println!("{done} step(s) done");
}

async fn send(c: &mut Client, ns: &str, steps: Vec<TxStep>) -> usize {
    let n = steps.len();
    match c.call(Request::Transaction { ns: ns.to_string(), steps }).await {
        Ok(Response::Records { .. }) => {
            println!("  {n} step(s)");
            n
        }
        r => {
            eprintln!("  a batch of {n} failed: {r:?}");
            0
        }
    }
}
