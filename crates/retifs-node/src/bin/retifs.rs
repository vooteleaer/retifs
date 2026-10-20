//! retifs CLI (prototype): a thin client of the local retifsd (libretifs).
//!
//!     retifs [--store DIR] ping
//!     retifs [--store DIR] put FILE [--public] [--compress] [--publish] [--record NAME | --one-off]
//!
//! `put` treats the file's absolute path as its record by default, so putting
//! an edited file again stores only the changed chunks (ADR-0008).
//!     retifs [--store DIR] get READ-CAP [--from NODE]... [-o OUT] [--links N] [--batch N]
//!     retifs [--store DIR] status READ-CAP
//!     retifs [--store DIR] want READ-CAP [--from NODE]...
//!     retifs [--store DIR] replicate READ-CAP --to NODE...
//!     retifs [--store DIR] forget READ-CAP
//!     retifs [--store DIR] channel create NAME
//!     retifs [--store DIR] channel publish NAME FILE [--compress]
//!     retifs [--store DIR] channel publish-ns NAME NS
//!     retifs [--store DIR] follow ADDRESS [--from NODE]...
//!     retifs [--store DIR] channels
//!
//!     retifs [--store DIR] rec add NS [KEY=VALUE]... [--file PATH]
//!     retifs [--store DIR] rec set NS ID [KEY=VALUE]... [--unset KEY]...
//!     retifs [--store DIR] rec get NS ID | rec rm NS ID
//!     retifs [--store DIR] rec history NS ID
//!     retifs [--store DIR] query NS [--at VERSION] [TERM]...
//!
//!     retifs [--store DIR] ns address NS | ns info NS
//!     retifs [--store DIR] ns join NAME ADDRESS [--from NODE]...
//!     retifs [--store DIR] ns grant NS WRITER [--grant] [--from NODE]... | ns revoke NS WRITER
//!
//! Several writers per namespace (ADR-0017): a member joins with the address
//! and shows its writer key; the creator grants it; members sync each other.
//! Every change to a namespace is a version (ADR-0006): a signed commit in the
//! namespace's own chain. `rec history` shows a record's versions; `--at`
//! queries the namespace as it was.
//!
//! Channels (ADR-0015): a writer publishes versions; followers keep the latest.
//! Records (ADR-0016): attributes and content blocks, queried BeFS style:
//! terms `key=value`, `key>n`, `key>=n`, `key<n`, `key<=n`, `key^=prefix`,
//! `has:key`, all of which must hold. Values: true/false, integers, decimals,
//! else strings ("quoted" to force a string); `key=a,b` with --list sets a list.
//!
//! `replicate` keeps an own file on other nodes under signed leases (ADR-0011);
//! `status` then shows how many of them confirmed with a receipt.
//!
//! `get` reads from the daemon's local store first, then fetches the rest from
//! the given nodes; fetched chunks stay cached in the daemon's store.

use std::path::PathBuf;

use libretifs::{default_store_dir, Client};

fn usage() -> ! {
    eprintln!(
        "retifs [--store DIR] ping\n\
         retifs [--store DIR] put FILE [--public] [--compress] [--publish] [--record NAME | --one-off]\n\
         retifs [--store DIR] get READ-CAP [--from NODE]... [-o OUT] [--links N] [--batch N]\n\
         retifs [--store DIR] status READ-CAP\n\
         retifs [--store DIR] read READ-CAP [--offset N] [--len N] [--ns NS] [--wait SECONDS]\n\
         retifs [--store DIR] want READ-CAP [--from NODE]...
         retifs [--store DIR] replicate READ-CAP --to NODE...\n\
         retifs [--store DIR] forget READ-CAP\n\
         retifs [--store DIR] channel create NAME | channel publish NAME FILE [--compress] | channel publish-ns NAME NS\n\
         retifs [--store DIR] follow ADDRESS [--from NODE]... | channels\n\
         retifs [--store DIR] rec add NS [KEY=VALUE]... [--file PATH] | rec set NS ID [KEY=VALUE]... [--unset KEY]...\n\
         retifs [--store DIR] rec get NS ID | rec rm NS ID | rec history NS ID | query NS [--at VERSION] [TERM]...\n\
         retifs [--store DIR] ns address NS | ns info NS | ns checkpoint NS | ns verify NS | ns keep NS all|rules | ns join NAME ADDRESS [--from NODE]...\n\
         retifs [--store DIR] ns grant NS WRITER [--grant] [--from NODE]... | ns revoke NS WRITER"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut store = default_store_dir();
    if let Some(i) = args.iter().position(|a| a == "--store") {
        store = args.get(i + 1).cloned().unwrap_or_else(|| usage()).into();
        args.drain(i..=i + 1);
    }
    let mut it = args.into_iter();
    let command = it.next().unwrap_or_else(|| usage());

    let mut client = Client::connect(&store).await.unwrap_or_else(|e| fail(e));
    match command.as_str() {
        "ping" => {
            let (node, chunks, usage) = client.ping().await.unwrap_or_else(|e| fail(e));
            println!("retifsd <{node}>, {chunks} chunks in store");
            if let Some(u) = usage {
                println!(
                    "  own (pinned) {}  promised (leased) {}  of store limit {}\n  cache {} of {}  spare {}\n  volume: {} free of {}, reserve {}",
                    human(u.pinned), human(u.leased), human(u.store_limit),
                    human(u.cache), human(u.cache_max), human(u.spare),
                    human(u.disk_available), human(u.disk_total), human(u.reserve)
                );
            }
        }
        "put" => {
            let path: PathBuf = it.next().unwrap_or_else(|| usage()).into();
            let flags: Vec<String> = it.collect();
            let public = flags.iter().any(|a| a == "--public");
            let compress = flags.iter().any(|a| a == "--compress");
            let publish = flags.iter().any(|a| a == "--publish");
            let record = if flags.iter().any(|a| a == "--one-off") {
                None
            } else if let Some(i) = flags.iter().position(|a| a == "--record") {
                Some(flags.get(i + 1).cloned().unwrap_or_else(|| usage()))
            } else {
                Some(std::path::absolute(&path).unwrap_or_else(|_| path.clone()).to_string_lossy().into_owned())
            };
            let data = std::fs::read(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
            let cap = client.put(data, public, compress, publish, record).await.unwrap_or_else(|e| fail(e));
            println!("{cap}");
        }
        "get" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let (mut from, mut out, mut links, mut batch) = (Vec::new(), PathBuf::from("retifs.out"), 1usize, 0usize);
            while let Some(arg) = it.next() {
                let mut value = || it.next().unwrap_or_else(|| usage());
                match arg.as_str() {
                    "--from" => from.push(value()),
                    "-o" | "--out" => out = value().into(),
                    "--links" => links = value().parse().unwrap_or_else(|_| usage()),
                    "--batch" => batch = value().parse().unwrap_or_else(|_| usage()),
                    _ => usage(),
                }
            }
            let (data, s) = client.get(&cap, &from, links, batch).await.unwrap_or_else(|e| fail(e));
            std::fs::write(&out, &data).unwrap_or_else(|e| fail(format!("{}: {e}", out.display())));
            let secs = s.millis as f64 / 1000.0;
            println!(
                "{} bytes in {:.2} s ({:.1} Mbps) after {:.2} s connecting: {} chunks, {} local, {} requests, {} retries, {} network bytes over {} link(s) -> {}",
                data.len(), secs, data.len() as f64 * 8.0 / secs.max(1e-6) / 1e6, s.connect_millis as f64 / 1000.0,
                s.chunks, s.from_local, s.requests, s.retries, s.network_bytes, s.links, out.display()
            );
        }
        "want" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let mut from = Vec::new();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--from" => from.push(it.next().unwrap_or_else(|| usage())),
                    _ => usage(),
                }
            }
            let s = client.want(&cap, &from).await.unwrap_or_else(|e| fail(e));
            print_status(&s);
        }
        "replicate" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let mut to = Vec::new();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--to" => to.push(it.next().unwrap_or_else(|| usage())),
                    _ => usage(),
                }
            }
            if to.is_empty() {
                usage();
            }
            let s = client.replicate(&cap, &to).await.unwrap_or_else(|e| fail(e));
            print_status(&s);
        }
        "channel" => match it.next().as_deref() {
            Some("create") => {
                let name = it.next().unwrap_or_else(|| usage());
                println!("{}", client.channel_create(&name).await.unwrap_or_else(|e| fail(e)));
            }
            Some("publish") => {
                let name = it.next().unwrap_or_else(|| usage());
                let path: PathBuf = it.next().unwrap_or_else(|| usage()).into();
                let compress = it.any(|a| a == "--compress");
                let data = std::fs::read(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
                let (seq, cap) = client.channel_publish(&name, data, compress).await.unwrap_or_else(|e| fail(e));
                println!("published {name} version {seq}: {cap}");
            }
            Some("publish-ns") => {
                let name = it.next().unwrap_or_else(|| usage());
                let ns = it.next().unwrap_or_else(|| usage());
                let req = libretifs::Request::ChannelPublishNs { name: name.clone(), ns: ns.clone() };
                match client.call(req).await.unwrap_or_else(|e| fail(e)) {
                    libretifs::Response::Published { seq, cap } => println!("published namespace {ns} as {name} version {seq}: {cap}"),
                    libretifs::Response::Error { message } => fail(message),
                    _ => fail("unexpected response"),
                }
            }
            _ => usage(),
        },
        "follow" => {
            let address = it.next().unwrap_or_else(|| usage());
            let mut from = Vec::new();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--from" => from.push(it.next().unwrap_or_else(|| usage())),
                    _ => usage(),
                }
            }
            let (own, follows) = client.follow(&address, &from).await.unwrap_or_else(|e| fail(e));
            print_channels(&own, &follows);
        }
        "channels" => {
            let (own, follows) = client.channels().await.unwrap_or_else(|e| fail(e));
            print_channels(&own, &follows);
        }
        "rec" => {
            let sub = it.next().unwrap_or_else(|| usage());
            let ns = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            let req = match sub.as_str() {
                "add" => {
                    let mut attrs = Vec::new();
                    let mut data = None;
                    let mut i = 0;
                    while i < rest.len() {
                        if rest[i] == "--file" {
                            let path: PathBuf = rest.get(i + 1).cloned().unwrap_or_else(|| usage()).into();
                            data = Some(std::fs::read(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display()))));
                            if !rest.iter().any(|a| a.starts_with("name=")) {
                                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                                attrs.push(("name".to_string(), libretifs::AttrValue::Str(name)));
                            }
                            i += 2;
                        } else {
                            attrs.push(attr(&rest[i]));
                            i += 1;
                        }
                    }
                    libretifs::Request::RecordCreate { ns, attrs, data }
                }
                "set" => {
                    let id = rest.first().cloned().unwrap_or_else(|| usage());
                    let (mut attrs, mut unset) = (Vec::new(), Vec::new());
                    let mut i = 1;
                    while i < rest.len() {
                        if rest[i] == "--unset" {
                            unset.push(rest.get(i + 1).cloned().unwrap_or_else(|| usage()));
                            i += 2;
                        } else {
                            attrs.push(attr(&rest[i]));
                            i += 1;
                        }
                    }
                    libretifs::Request::RecordSet { ns, id, attrs, unset, data: None }
                }
                "get" => libretifs::Request::RecordGet { ns, id: rest.first().cloned().unwrap_or_else(|| usage()) },
                "rm" => libretifs::Request::RecordDelete { ns, id: rest.first().cloned().unwrap_or_else(|| usage()) },
                "history" => {
                    let id = rest.first().cloned().unwrap_or_else(|| usage());
                    match client.call(libretifs::Request::RecordHistory { ns, id }).await.unwrap_or_else(|e| fail(e)) {
                        libretifs::Response::History { entries } => {
                            let mut last: Option<Option<libretifs::RecordView>> = None;
                            for e in entries.iter().rev() {
                                if last.as_ref() == Some(&e.record) {
                                    continue; // unchanged in this version
                                }
                                match &e.record {
                                    Some(r) => {
                                        let attrs: Vec<String> = r.attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
                                        println!("version {}: {}", e.version, attrs.join(" "));
                                    }
                                    None => println!("version {}: (absent)", e.version),
                                }
                                last = Some(e.record.clone());
                            }
                        }
                        libretifs::Response::Error { message } => fail(message),
                        _ => fail("unexpected response"),
                    }
                    return;
                }
                _ => usage(),
            };
            for r in client.records(req).await.unwrap_or_else(|e| fail(e)) {
                print_record(&r);
            }
        }
        "ns" => {
            let sub = it.next().unwrap_or_else(|| usage());
            let ns = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            let froms = |rest: &[String]| -> Vec<String> {
                rest.windows(2).filter(|w| w[0] == "--from").map(|w| w[1].clone()).collect()
            };
            let req = match sub.as_str() {
                "address" => libretifs::Request::NsAddress { ns },
                "info" => libretifs::Request::NsInfo { ns },
                "checkpoint" => libretifs::Request::NsCheckpoint { ns },
                "keep" => libretifs::Request::NsKeep { ns, mode: rest.first().cloned().unwrap_or_else(|| usage()) },
                "verify" => libretifs::Request::NsVerify { ns },
                "join" => libretifs::Request::NsJoin {
                    ns,
                    address: rest.first().cloned().unwrap_or_else(|| usage()),
                    from: froms(&rest),
                },
                "grant" => libretifs::Request::NsGrant {
                    ns,
                    writer: rest.first().cloned().unwrap_or_else(|| usage()),
                    grant: rest.iter().any(|a| a == "--grant"),
                    from: froms(&rest),
                },
                "revoke" => libretifs::Request::NsRevoke { ns, writer: rest.first().cloned().unwrap_or_else(|| usage()) },
                _ => usage(),
            };
            match client.call(req).await.unwrap_or_else(|e| fail(e)) {
                libretifs::Response::Channel { address } => println!("{address}"),
                libretifs::Response::Namespace(v) => {
                    println!("namespace {}: {} record(s), {} peer node(s)", v.name, v.records, v.peers);
                    println!("  address    {}", v.address);
                    println!("  my writer  {}", v.own_writer);
                    for (w, rights) in &v.writers {
                        println!("  writer     {w}  {}", rights.join(","));
                    }
                    if let Some(c) = &v.checkpoint {
                        println!("  checkpoint {c}");
                    }
                    println!("  keeps      {} on device {} ({} file(s) pulled for it)", v.keep, v.device, v.kept);
                }
                libretifs::Response::Verified { ok, detail } => {
                    println!("{detail}");
                    if !ok {
                        std::process::exit(1);
                    }
                }
                libretifs::Response::Error { message } => fail(message),
                _ => fail("unexpected response"),
            }
        }
        "query" => {
            let ns = it.next().unwrap_or_else(|| usage());
            let mut terms: Vec<String> = it.collect();
            let at = terms.iter().position(|t| t == "--at").map(|i| {
                let v = terms.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
                terms.drain(i..=i + 1);
                v
            });
            let found = client.records(libretifs::Request::Query { ns, terms, at }).await.unwrap_or_else(|e| fail(e));
            for r in &found {
                print_record(r);
            }
            println!("{} record(s)", found.len());
        }
        "forget" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let s = client.forget(&cap).await.unwrap_or_else(|e| fail(e));
            println!("no longer needed here: its copies elsewhere expire unless others need them");
            print_status(&s);
        }
        "status" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let s = client.status(&cap).await.unwrap_or_else(|e| fail(e));
            print_status(&s);
        }
        "read" => {
            // Part of a file, fetched on demand from a namespace's peers if it isn't here.
            let cap = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            let opt = |name: &str| rest.windows(2).find(|w| w[0] == name).map(|w| w[1].clone());
            let num = |name: &str, default: u64| opt(name).map_or(default, |v| v.parse().unwrap_or_else(|_| usage()));
            let req = libretifs::Request::ReadRange {
                cap,
                ns: opt("--ns"),
                offset: num("--offset", 0),
                len: num("--len", u64::MAX),
                wait_ms: num("--wait", 30) * 1000,
            };
            match client.call(req).await.unwrap_or_else(|e| fail(e)) {
                libretifs::Response::Range { data } => {
                    use std::io::Write;
                    std::io::stdout().write_all(&data).unwrap_or_else(|e| fail(e.to_string()));
                }
                libretifs::Response::Error { message } => fail(message),
                _ => fail("unexpected response"),
            }
        }
        _ => usage(),
    }
}

fn print_status(s: &libretifs::Status) {
    let total = s.total_chunks.map_or("?".to_string(), |t| t.to_string());
    println!(
        "{} bytes: {}/{} chunks local{}{}{}",
        s.size, s.local_chunks, total,
        if s.missing_nodes > 0 { format!(", {} manifest node(s) not held locally", s.missing_nodes) } else { String::new() },
        if s.complete() { " (complete, readable offline)" } else { "" },
        if s.seeking { format!(", seeking ({} holder(s) known)", s.holders_known) } else { String::new() }
    );
    if let Some(secs) = s.slow_link_wait_secs {
        println!("  rest waits for a faster path (about {} over the slow link)", duration(secs));
    }
    if s.leased_to > 0 {
        println!("  leased to {} node(s), {} confirmed by receipt", s.leased_to, s.replicas);
    }
}

/// `key=value` on the command line; `key=a,b,c` with a trailing `,` or more than one comma is a list.
fn attr(arg: &str) -> (String, libretifs::AttrValue) {
    let (k, v) = arg.split_once('=').unwrap_or_else(|| fail(format!("expected KEY=VALUE, got {arg:?}")));
    let scalar = |v: &str| -> libretifs::AttrValue {
        if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            return libretifs::AttrValue::Str(v[1..v.len() - 1].to_string());
        }
        match v {
            "true" => libretifs::AttrValue::Bool(true),
            "false" => libretifs::AttrValue::Bool(false),
            _ => v
                .parse::<i64>()
                .map(libretifs::AttrValue::Int)
                .or_else(|_| v.parse::<f64>().map(libretifs::AttrValue::Float))
                .unwrap_or_else(|_| libretifs::AttrValue::Str(v.to_string())),
        }
    };
    let value = if v.contains(',') && !v.starts_with('"') {
        libretifs::AttrValue::List(v.split(',').filter(|s| !s.is_empty()).map(scalar).collect())
    } else {
        scalar(v)
    };
    (k.to_string(), value)
}

fn print_record(r: &libretifs::RecordView) {
    println!("{}", r.id);
    for (k, v) in &r.attrs {
        println!("  {k} = {v}");
    }
    for b in &r.blocks {
        println!("  block {b}");
    }
}

fn print_channels(own: &[libretifs::ChannelInfo], follows: &[libretifs::FollowInfo]) {
    for c in own {
        println!("writes {} (version {}): {}", c.name, c.seq, c.address);
    }
    for f in follows {
        let short = f.address.get(..32).unwrap_or(&f.address);
        match &f.current {
            Some(cap) => println!(
                "follows {short}… version {}{}{}: {cap}",
                f.seq,
                if f.complete { " (complete)" } else { " (fetching)" },
                f.namespace.as_ref().map(|n| format!(", namespace {n}")).unwrap_or_default()
            ),
            None => println!("follows {short}… (no version yet)"),
        }
    }
}

fn duration(secs: u64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

fn human(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (mut v, mut i) = (b as f64, 0);
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.1} {}", UNITS[i]) }
}

fn fail(e: impl std::fmt::Display) -> ! {
    eprintln!("retifs: {e}");
    std::process::exit(1);
}
