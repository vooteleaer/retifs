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
//!     retifs [--store DIR] rec set NS ID [KEY=VALUE]... [--unset KEY]... [--file PATH]
//!     retifs [--store DIR] rec get NS ID | rec rm NS ID
//!     retifs [--store DIR] rec import NS < LINES   (one record per line of KEY=VALUE, 500 per transaction)
//!     retifs [--store DIR] rec history NS ID
//!     retifs [--store DIR] query NS [--at VERSION] [TERM]...
//!     retifs [--store DIR] query NS KEY=VALUE... --search NODE   (through a search node's blind index)
//!     retifs [--store DIR] ns search NS   (publish the blind index; prints the search capability)
//!
//!     retifs [--store DIR] ns address NS | ns info NS
//!     retifs [--store DIR] ns join NAME ADDRESS [--from NODE]... [--lazy]
//!     retifs [--store DIR] ns grant NS WRITER [--grant] [--keys K1,K2,@content,@delete] [--until YYYY-MM-DD|+30d] [--from NODE]... | ns revoke NS WRITER
//!     retifs [--store DIR] share create NAME --from NS [TERM]... [--id ID]... [--omit KEY]... [--qr] | share list NS | share rm NS ID
//!     retifs [--store DIR] ns link NS [--name LABEL] [--q TERMS] [--qr] | open LINK [--as NAME]
//!     retifs [--store DIR] me | me link [--name LABEL] [--qr] | contact add NAME NODE|LINK | contact list | contact rm NAME
//!     retifs [--store DIR] invite create NS [--grant] [--keys K1,K2] [--until DATE] [--expires 1d] [--q TERMS] [--name LABEL] [--qr] | invite list NS | invite cancel NS ID
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
         retifs [--store DIR] app add NAME --ns NS[,NS] [--write] [--device NODE] | app list | app remove NAME\n\
         retifs [--store DIR] --app TOKEN ...   (as an application: only what its token allows)\n\
         retifs [--store DIR] --via NODE ...    (ask own node NODE over a Link; it must have added this node with --device)\n\
         retifs [--store DIR] want READ-CAP [--from NODE]...
         retifs [--store DIR] replicate READ-CAP --to NODE...\n\
         retifs [--store DIR] forget READ-CAP\n\
         retifs [--store DIR] channel create NAME | channel publish NAME FILE [--compress] | channel publish-ns NAME NS\n\
         retifs [--store DIR] follow ADDRESS [--from NODE]... | channels\n\
         retifs [--store DIR] rec add NS [KEY=VALUE]... [--file PATH] | rec set NS ID [KEY=VALUE]... [--unset KEY]... [--file PATH]\n\
         retifs [--store DIR] rec get NS ID | rec rm NS ID | rec history NS ID | rec import NS < LINES | query NS[,NS]... [--at VERSION] [TERM]... [--search NODE]\n\
         retifs [--store DIR] ns address NS | ns info NS | ns checkpoint NS | ns search NS | ns verify NS | ns keep NS all|rules | ns join NAME ADDRESS [--from NODE]... [--lazy]\n\
         retifs [--store DIR] ns grant NS WRITER [--grant] [--from NODE]... | ns revoke NS WRITER\n\
         retifs [--store DIR] share create NAME --from NS [TERM]... [--id ID]... [--omit KEY]... [--qr] | share list NS | share rm NS ID\n\
         retifs [--store DIR] ns link NS [--name LABEL] [--q TERMS] [--qr] | open LINK [--as NAME] | ns join NAME LINK\n\
         retifs [--store DIR] me | me link [--name LABEL] [--qr] | contact add NAME NODE|LINK | contact list | contact rm NAME\n\
         retifs [--store DIR] invite create NS [--grant] [--keys K1,K2] [--until DATE] [--expires 1d] [--q TERMS] [--name LABEL] [--qr] | invite list NS | invite cancel NS ID"
    );
    std::process::exit(2);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Like any command-line tool: a closed pipe (`retifs query … | head -1`)
    // ends the program quietly instead of panicking on the next print.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut store = default_store_dir();
    if let Some(i) = args.iter().position(|a| a == "--store") {
        store = args.get(i + 1).cloned().unwrap_or_else(|| usage()).into();
        args.drain(i..=i + 1);
    }
    // As an application (the app socket, limited to what the token allows).
    let mut app_token = None;
    if let Some(i) = args.iter().position(|a| a == "--app") {
        app_token = Some(args.get(i + 1).cloned().unwrap_or_else(|| usage()));
        args.drain(i..=i + 1);
    }
    // Ask one of the user's own nodes instead, over a Link (ADR-0019).
    let mut via = None;
    if let Some(i) = args.iter().position(|a| a == "--via") {
        via = Some(args.get(i + 1).cloned().unwrap_or_else(|| usage()));
        args.drain(i..=i + 1);
    }
    let mut it = args.into_iter();
    let command = it.next().unwrap_or_else(|| usage());

    let mut client = match &app_token {
        Some(token) => Client::connect_app(&store, token).await,
        None => Client::connect(&store).await,
    }
    .unwrap_or_else(|e| fail(e))
    .via(via.clone());
    let via_set = via.is_some();
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
            // On Unix the daemon gets the open file and reads it itself (fd
            // passing): nothing is copied through the socket. `--copy` sends the bytes.
            #[cfg(unix)]
            let by_fd = !flags.iter().any(|a| a == "--copy") && !via_set;
            #[cfg(not(unix))]
            let by_fd = !via_set && false;
            let cap = if by_fd {
                #[cfg(unix)]
                {
                    let f = std::fs::File::open(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
                    client.put_fd(&f, public, compress, publish, record).await.unwrap_or_else(|e| fail(e))
                }
                #[cfg(not(unix))]
                unreachable!()
            } else {
                let data = std::fs::read(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
                client.put(data, public, compress, publish, record).await.unwrap_or_else(|e| fail(e))
            };
            println!("{cap}");
        }
        "get" => {
            let cap = it.next().unwrap_or_else(|| usage());
            let (mut from, mut out, mut links, mut batch) = (Vec::new(), PathBuf::from("retifs.out"), 4usize, 0usize);
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
            if sub == "import" {
                // One record per input line (KEY=VALUE pairs, separated by
                // tabs, or by spaces when there are no tabs), in transactions
                // of 500: one commit each, not one per record.
                use std::io::BufRead;
                let mut steps = Vec::new();
                let mut total = 0usize;
                for line in std::io::stdin().lock().lines() {
                    let line = line.unwrap_or_else(|e| fail(e));
                    let fields: Vec<&str> = if line.contains('\t') { line.split('\t').collect() } else { line.split_whitespace().collect() };
                    let attrs: Vec<_> = fields.iter().filter(|f| !f.is_empty()).map(|f| attr(f)).collect();
                    if attrs.is_empty() {
                        continue;
                    }
                    steps.push(libretifs::TxStep::Create { attrs, data: None });
                    total += 1;
                    if steps.len() == 500 {
                        let req = libretifs::Request::Transaction { ns: ns.clone(), steps: std::mem::take(&mut steps) };
                        client.call(req).await.unwrap_or_else(|e| fail(e));
                    }
                }
                if !steps.is_empty() {
                    client.call(libretifs::Request::Transaction { ns: ns.clone(), steps }).await.unwrap_or_else(|e| fail(e));
                }
                println!("{total} record(s) imported");
                return;
            }
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
                    let (mut attrs, mut unset, mut data) = (Vec::new(), Vec::new(), None);
                    let mut i = 1;
                    while i < rest.len() {
                        if rest[i] == "--unset" {
                            unset.push(rest.get(i + 1).cloned().unwrap_or_else(|| usage()));
                            i += 2;
                        } else if rest[i] == "--file" {
                            let path = std::path::PathBuf::from(rest.get(i + 1).cloned().unwrap_or_else(|| usage()));
                            data = Some(std::fs::read(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display()))));
                            i += 2;
                        } else {
                            attrs.push(attr(&rest[i]));
                            i += 1;
                        }
                    }
                    libretifs::Request::RecordSet { ns, id, attrs, unset, data }
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
            let rest = resolve_froms(&mut client, it.collect()).await;
            let froms = |rest: &[String]| -> Vec<String> {
                rest.windows(2).filter(|w| w[0] == "--from").map(|w| w[1].clone()).collect()
            };
            let req = match sub.as_str() {
                "address" => libretifs::Request::NsAddress { ns },
                "info" => libretifs::Request::NsInfo { ns },
                "checkpoint" => libretifs::Request::NsCheckpoint { ns },
                "keep" => libretifs::Request::NsKeep { ns, mode: rest.first().cloned().unwrap_or_else(|| usage()) },
                "verify" => libretifs::Request::NsVerify { ns },
                "search" => libretifs::Request::NsSearch { ns },
                "link" => {
                    // A read link (ADR-0020): the address, this node to fetch from, a label, a query.
                    let address = match client.call(libretifs::Request::NsAddress { ns: ns.clone() }).await.unwrap_or_else(|e| fail(e)) {
                        libretifs::Response::Channel { address } => address,
                        libretifs::Response::Error { message } => fail(message),
                        _ => fail("unexpected response"),
                    };
                    let (node, _, _) = client.ping().await.unwrap_or_else(|e| fail(e));
                    let opt = |flag: &str| rest.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone());
                    let label = opt("--name").unwrap_or_else(|| ns.clone());
                    let mut link = libretifs::link::Link::namespace(&address, &[node], Some(&label));
                    if let Some(q) = opt("--q") {
                        link.params.push(("q".into(), q));
                    }
                    println!("{link}");
                    if rest.iter().any(|a| a == "--qr") {
                        print_qr(&link.to_string());
                    }
                    eprintln!("(anyone with this link can read all of {ns}; to give only part of it, make a share)");
                    return;
                }
                "join" => {
                    let what = rest.first().cloned().unwrap_or_else(|| usage());
                    let (address, mut from) = match libretifs::link::Link::parse(&what) {
                        Ok(link) => (
                            link.ns_address().unwrap_or_else(|| fail(format!("a retifs:{} link isn't a namespace", link.kind))),
                            link.params_named("from").map(String::from).collect::<Vec<_>>(),
                        ),
                        Err(_) => (what, Vec::new()),
                    };
                    from.extend(froms(&rest));
                    libretifs::Request::NsJoin { ns, address, from, lazy: rest.iter().any(|a| a == "--lazy") }
                }
                "grant" => libretifs::Request::NsGrant {
                    ns,
                    writer: rest.first().cloned().unwrap_or_else(|| usage()),
                    grant: rest.iter().any(|a| a == "--grant"),
                    from: froms(&rest),
                    keys: rest
                        .windows(2)
                        .find(|w| w[0] == "--keys")
                        .map(|w| w[1].split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect())
                        .unwrap_or_default(),
                    until: rest.windows(2).find(|w| w[0] == "--until").map(|w| parse_time(&w[1]).unwrap_or_else(|e| fail(e))),
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
                    if v.lazy {
                        println!("  lazy       only records needed are held (fetched on demand)");
                    }
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
        "share" => {
            let sub = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            let opt = |flag: &str| -> Vec<String> { rest.windows(2).filter(|w| w[0] == flag).map(|w| w[1].clone()).collect() };
            match sub.as_str() {
                "create" => {
                    let name = rest.first().cloned().unwrap_or_else(|| usage());
                    let source = opt("--from").pop().unwrap_or_else(|| usage());
                    // Terms: what isn't a flag or a flag's value.
                    let mut terms = Vec::new();
                    let mut i = 1;
                    while i < rest.len() {
                        if rest[i] == "--qr" {
                            i += 1;
                        } else if rest[i].starts_with("--") {
                            i += 2;
                        } else {
                            terms.push(rest[i].clone());
                            i += 1;
                        }
                    }
                    let req = libretifs::Request::ShareCreate { source, name, terms, ids: opt("--id"), omit: opt("--omit") };
                    match client.call(req).await.unwrap_or_else(|e| fail(e)) {
                        libretifs::Response::Namespace(v) => {
                            let (node, _, _) = client.ping().await.unwrap_or_else(|e| fail(e));
                            println!("share {}: {} record(s)", v.name, v.records);
                            let link = libretifs::link::Link::namespace(&v.address, &[node], Some(&v.name)).to_string();
                            println!("  link {link}");
                            if rest.iter().any(|a| a == "--qr") {
                                print_qr(&link);
                            }
                            println!("  (whoever has the link reads the share: retifs open LINK)");
                        }
                        libretifs::Response::Error { message } => fail(message),
                        _ => fail("unexpected response"),
                    }
                }
                "list" => {
                    let source = rest.first().cloned().unwrap_or_else(|| usage());
                    let req = libretifs::Request::Query { ns: source, terms: vec!["type=retifs.share".into()], at: None };
                    let records = client.records(req).await.unwrap_or_else(|e| fail(e));
                    for r in &records {
                        let get = |k: &str| r.attrs.iter().find(|(key, _)| key == k).map(|(_, v)| v);
                        let text = |v: Option<&libretifs::AttrValue>| match v {
                            Some(libretifs::AttrValue::Str(s)) => s.clone(),
                            Some(libretifs::AttrValue::List(items)) => items
                                .iter()
                                .filter_map(|i| if let libretifs::AttrValue::Str(s) = i { Some(s.as_str()) } else { None })
                                .collect::<Vec<_>>()
                                .join(", "),
                            _ => String::new(),
                        };
                        let select = match (text(get("select")), text(get("ids"))) {
                            (q, _) if !q.is_empty() => q,
                            (_, ids) => format!("records {ids}"),
                        };
                        let omit = text(get("omit"));
                        println!("{}  {}  {select}{}", r.id, text(get("name")), if omit.is_empty() { String::new() } else { format!("  (without {omit})") });
                    }
                    println!("{} share(s)", records.len());
                }
                "rm" => {
                    let source = rest.first().cloned().unwrap_or_else(|| usage());
                    let id = rest.get(1).cloned().unwrap_or_else(|| usage());
                    match client.call(libretifs::Request::ShareDelete { source, id }).await.unwrap_or_else(|e| fail(e)) {
                        libretifs::Response::Done => println!("share ended: its updates stop"),
                        libretifs::Response::Error { message } => fail(message),
                        _ => fail("unexpected response"),
                    }
                }
                _ => usage(),
            }
        }
        "me" => {
            // This node, to give to others as a contact (ADR-0020).
            let rest: Vec<String> = it.collect();
            let (node, _, _) = client.ping().await.unwrap_or_else(|e| fail(e));
            let words = node_words(&node);
            if rest.first().map(String::as_str) == Some("link") {
                let name = rest.windows(2).find(|w| w[0] == "--name").map(|w| w[1].clone());
                let link = libretifs::link::Link {
                    kind: "node".into(),
                    what: node.clone(),
                    params: name.map(|n| vec![("name".to_string(), n)]).unwrap_or_default(),
                };
                println!("{link}");
                if rest.iter().any(|a| a == "--qr") {
                    print_qr(&link.to_string());
                }
                eprintln!("(they add you with retifs open LINK; read these words to each other to be sure: {words})");
            } else {
                println!("node   {node}");
                println!("words  {words}");
            }
        }
        "contact" => {
            // Petnames (ADR-0020): records in this user's own namespace `me`,
            // so every device of the user has the same address book.
            let sub = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            match sub.as_str() {
                "add" => {
                    let name = rest.first().cloned().unwrap_or_else(|| usage());
                    let what = rest.get(1).cloned().unwrap_or_else(|| usage());
                    let node = match libretifs::link::Link::parse(&what) {
                        Ok(l) if l.kind == "node" => l.what,
                        Ok(l) => fail(format!("a retifs:{} link isn't a node", l.kind)),
                        Err(_) => what,
                    };
                    add_contact(&mut client, &name, &node).await;
                }
                "list" => {
                    let contacts = contacts(&mut client).await;
                    for (name, node, _) in &contacts {
                        println!("{name:<16} {node}  {}", node_words(node));
                    }
                    println!("{} contact(s)", contacts.len());
                }
                "rm" => {
                    let name = rest.first().cloned().unwrap_or_else(|| usage());
                    let found: Vec<_> = contacts(&mut client).await.into_iter().filter(|(n, _, _)| n.eq_ignore_ascii_case(&name)).collect();
                    if found.is_empty() {
                        fail(format!("no contact {name}"));
                    }
                    for (_, _, id) in found {
                        let req = libretifs::Request::RecordDelete { ns: ME.into(), id };
                        if let libretifs::Response::Error { message } = client.call(req).await.unwrap_or_else(|e| fail(e)) {
                            fail(message);
                        }
                    }
                    println!("removed {name}");
                }
                _ => usage(),
            }
        }
        "invite" => {
            let sub = it.next().unwrap_or_else(|| usage());
            let ns = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            let opt = |flag: &str| rest.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone());
            let req = match sub.as_str() {
                "create" => libretifs::Request::InviteCreate {
                    ns: ns.clone(),
                    grant: rest.iter().any(|a| a == "--grant"),
                    keys: opt("--keys").map(|k| k.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect()).unwrap_or_default(),
                    until: opt("--until").map(|u| parse_time(&u).unwrap_or_else(|e| fail(e))),
                    expires_ms: opt("--expires").map(|e| parse_duration_ms(&e).unwrap_or_else(|| fail(format!("--expires takes e.g. 30m, 2h or 7d, not {e}")))),
                    q: opt("--q"),
                    label: opt("--name"),
                },
                "list" => libretifs::Request::InviteList { ns: ns.clone() },
                "cancel" => libretifs::Request::InviteCancel { ns: ns.clone(), id: rest.first().cloned().unwrap_or_else(|| usage()) },
                _ => usage(),
            };
            match client.call(req).await.unwrap_or_else(|e| fail(e)) {
                libretifs::Response::Link { link } => {
                    println!("{link}");
                    if rest.iter().any(|a| a == "--qr") {
                        print_qr(&link);
                    }
                    eprintln!("(the first to open it may write to {ns}; anyone who sees it can read {ns}: pass it in person or end to end)");
                }
                libretifs::Response::Invites { invites } => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
                    for i in &invites {
                        let state = if i.spent { "used".to_string() } else if i.expires < now { "expired".to_string() } else { format!("pending, {} min left", (i.expires - now) / 60_000) };
                        let mut rights = if i.grant { "write+grant".to_string() } else { "write".to_string() };
                        if !i.keys.is_empty() {
                            rights.push_str(&format!(" keys {}", i.keys.join(",")));
                        }
                        println!("{}  {rights}  {state}", i.id);
                    }
                    println!("{} invitation(s)", invites.len());
                }
                libretifs::Response::Done => println!("invitation withdrawn"),
                libretifs::Response::Error { message } => fail(message),
                _ => fail("unexpected response"),
            }
        }
        "open" => {
            // Opens a retifs: link (ADR-0020). A namespace link joins the
            // namespace (reading) under the link's name or --as NAME.
            let text = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            let link = libretifs::link::Link::parse(&text).unwrap_or_else(|e| fail(e));
            let name = rest
                .windows(2)
                .find(|w| w[0] == "--as")
                .map(|w| w[1].clone())
                .unwrap_or_else(|| libretifs::link::suggest_name(link.param("name").unwrap_or("shared")));
            if link.kind == "node" {
                // A contact: the name as written (a petname), --as first.
                let petname = rest
                    .windows(2)
                    .find(|w| w[0] == "--as")
                    .map(|w| w[1].clone())
                    .or_else(|| link.param("name").map(String::from))
                    .unwrap_or_else(|| fail("this node link has no name: give one with --as NAME"));
                add_contact(&mut client, &petname, &link.what).await;
                return;
            }
            if link.kind == "invite" {
                match client.call(libretifs::Request::InviteAccept { ns: name.clone(), link: text.clone() }).await.unwrap_or_else(|e| fail(e)) {
                    libretifs::Response::Namespace(v) => {
                        let can_write = v.writers.iter().any(|(w, r)| *w == v.own_writer && r.iter().any(|r| r == "write"));
                        println!("joined {name}: {}", if can_write { "you may write to it" } else { "reading now; writing once the invitation's node grants it (on its own, when reachable)" });
                    }
                    libretifs::Response::Error { message } => fail(message),
                    _ => fail("unexpected response"),
                }
                return;
            }
            let Some(address) = link.ns_address() else {
                println!("a retifs:{} link ({}); this version of retifs opens namespace links", link.kind, link.what);
                for (k, v) in &link.params {
                    println!("  {k} = {v}");
                }
                return;
            };
            let req = libretifs::Request::NsJoin { ns: name.clone(), address, from: link.params_named("from").map(String::from).collect(), lazy: false };
            match client.call(req).await.unwrap_or_else(|e| fail(e)) {
                libretifs::Response::Namespace(_) | libretifs::Response::Done => {}
                libretifs::Response::Error { message } => fail(message),
                _ => {}
            }
            println!("joined {name}: it fills in as it syncs (retifs query {name})");
            if let Some(q) = link.param("q") {
                println!("the link opens on: retifs query {name} {}", q.split(',').map(|t| format!("'{}'", t.trim())).collect::<Vec<_>>().join(" "));
            }
        }
        "app" => {
            let sub = it.next().unwrap_or_else(|| usage());
            let rest: Vec<String> = it.collect();
            let req = match sub.as_str() {
                "add" => libretifs::Request::AppAdd {
                    name: rest.first().cloned().unwrap_or_else(|| usage()),
                    namespaces: rest
                        .windows(2)
                        .find(|w| w[0] == "--ns")
                        .map(|w| w[1].split(',').map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).collect())
                        .unwrap_or_else(|| usage()),
                    write: rest.iter().any(|a| a == "--write"),
                    device: rest.windows(2).find(|w| w[0] == "--device").map(|w| w[1].clone()),
                },
                "list" => libretifs::Request::AppList,
                "remove" => libretifs::Request::AppRemove { name: rest.first().cloned().unwrap_or_else(|| usage()) },
                _ => usage(),
            };
            match client.call(req).await.unwrap_or_else(|e| fail(e)) {
                libretifs::Response::AppToken { token } => {
                    println!("{token}");
                    eprintln!("(shown once: give it to the app; it connects with this token on the app socket)");
                }
                libretifs::Response::Apps { apps } => {
                    for a in apps {
                        println!(
                            "{}  {}  {}{}",
                            a.name,
                            if a.write { "read+write" } else { "read" },
                            a.namespaces.join(","),
                            a.exe
                                .map(|e| format!("  pinned to {e}"))
                                .or(a.device.map(|n| format!("  device <{n}> over a Link")))
                                .unwrap_or_default()
                        );
                    }
                }
                libretifs::Response::Done => println!("ok"),
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
            // Through a search node's blind index (ADR-0019).
            if let Some(i) = terms.iter().position(|t| t == "--search") {
                let node = terms.get(i + 1).cloned().unwrap_or_else(|| usage());
                terms.drain(i..=i + 1);
                match client.call(libretifs::Request::SearchQuery { ns, node, terms }).await.unwrap_or_else(|e| fail(e)) {
                    libretifs::Response::Searched { records, unresolved, as_of_ms } => {
                        for r in &records {
                            print_record(r);
                        }
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
                        println!("{} record(s) (index built {} s ago)", records.len(), now.saturating_sub(as_of_ms) / 1000);
                        if !unresolved.is_empty() {
                            println!("{} more match(es) not held here yet: {}", unresolved.len(), unresolved.join(" "));
                        }
                    }
                    libretifs::Response::Error { message } => fail(message),
                    _ => fail("unexpected response"),
                }
                return;
            }
            // Several namespaces (NS1,NS2): each contributor writes its own,
            // and a query combines them (instead of record filters in grants).
            let names: Vec<String> = ns.split(',').map(str::trim).filter(|n| !n.is_empty()).map(String::from).collect();
            let mut total = 0;
            for n in &names {
                let req = libretifs::Request::Query { ns: n.clone(), terms: terms.clone(), at };
                let found = client.records(req).await.unwrap_or_else(|e| fail(format!("{n}: {e}")));
                for r in &found {
                    if names.len() > 1 {
                        print!("{n}/");
                    }
                    print_record(r);
                }
                total += found.len();
            }
            println!("{total} record(s)");
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

/// A point in time for `--until`: `YYYY-MM-DD` (UTC midnight), `+30d` /
/// `+12h` / `+90m` from now, or milliseconds since the epoch.
/// The user's own namespace: contacts, saved queries, settings (ADR-0020).
const ME: &str = "me";

/// A node address as fingerprint words, to read aloud when it matters.
fn node_words(node: &str) -> String {
    let bytes: Vec<u8> = (0..node.len()).step_by(2).filter_map(|i| node.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect();
    retifs_core::words::fingerprint(&bytes, retifs_core::words::DEFAULT_WORDS).join(" ")
}

fn is_node(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The contacts in `me`: (name, node, record ID). None yet: no `me` yet.
async fn contacts(client: &mut libretifs::Client) -> Vec<(String, String, String)> {
    let req = libretifs::Request::Query { ns: ME.into(), terms: vec!["type=contact".into()], at: None };
    let Ok(libretifs::Response::Records { records }) = client.call(req).await else { return Vec::new() };
    let s = |r: &libretifs::RecordView, k: &str| {
        r.attrs.iter().find_map(|(key, v)| match v {
            libretifs::AttrValue::Str(s) if key == k => Some(s.clone()),
            _ => None,
        })
    };
    let mut out: Vec<_> = records.iter().filter_map(|r| Some((s(r, "name")?, s(r, "retifs:node")?, r.id.clone()))).collect();
    out.sort();
    out
}

/// Adds (or renames) a contact for `node` in `me`.
async fn add_contact(client: &mut libretifs::Client, name: &str, node: &str) {
    if !is_node(node) {
        fail(format!("{node} isn't a node address (32 hex digits) or a retifs:node link"));
    }
    if is_node(name) {
        fail("a contact's name can't look like a node address");
    }
    let existing = contacts(client).await;
    if existing.iter().any(|(n, other, _)| n.eq_ignore_ascii_case(name) && other != node) {
        fail(format!("you already have a contact {name}; remove it first or choose another name"));
    }
    let attrs = vec![("name".to_string(), libretifs::AttrValue::Str(name.into()))];
    let req = match existing.iter().find(|(_, n, _)| n == node) {
        Some((_, _, id)) => libretifs::Request::RecordSet { ns: ME.into(), id: id.clone(), attrs, unset: vec![], data: None },
        None => {
            let mut attrs = attrs;
            attrs.push(("type".into(), libretifs::AttrValue::Str("contact".into())));
            attrs.push(("retifs:node".into(), libretifs::AttrValue::Str(node.into())));
            libretifs::Request::RecordCreate { ns: ME.into(), attrs, data: None }
        }
    };
    if let libretifs::Response::Error { message } = client.call(req).await.unwrap_or_else(|e| fail(e)) {
        fail(message);
    }
    println!("contact {name}: {node}");
    println!("  words {}  (compare them with what {name}'s retifs me shows)", node_words(node));
}

/// `--from NAME` with a contact's name: its node.
async fn resolve_froms(client: &mut libretifs::Client, mut rest: Vec<String>) -> Vec<String> {
    let mut known: Option<Vec<(String, String, String)>> = None;
    for i in 1..rest.len() {
        if rest[i - 1] == "--from" && !is_node(&rest[i]) {
            if known.is_none() {
                known = Some(contacts(client).await);
            }
            match known.as_ref().unwrap().iter().find(|(n, _, _)| n.eq_ignore_ascii_case(&rest[i])) {
                Some((_, node, _)) => rest[i] = node.clone(),
                None => fail(format!("--from {}: not a node address, and no contact of that name", rest[i])),
            }
        }
    }
    rest
}

/// A link as a QR code in the terminal (two rows per line), for showing
/// on one screen and scanning with another (ADR-0020). Error correction L:
/// the smallest code, for screens rather than print.
fn print_qr(text: &str) {
    use qrcode::{render::unicode::Dense1x2, EcLevel, QrCode};
    match QrCode::with_error_correction_level(text, EcLevel::L) {
        Ok(code) => eprintln!("{}", code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).quiet_zone(true).build()),
        Err(e) => eprintln!("(no QR code: {e})"),
    }
}

/// `30m`, `2h`, `7d` (or plain seconds) as milliseconds.
fn parse_duration_ms(s: &str) -> Option<u64> {
    let (n, unit) = s.trim().split_at(s.trim().find(|c: char| !c.is_ascii_digit()).unwrap_or(s.trim().len()));
    let n: u64 = n.parse().ok()?;
    let secs = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    Some(n * secs * 1000)
}

fn parse_time(s: &str) -> Result<u64, String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    if let Some(rel) = s.strip_prefix('+') {
        let (n, unit) = rel.split_at(rel.len().saturating_sub(1));
        let n: u64 = n.parse().map_err(|_| format!("bad duration {s}"))?;
        let ms = match unit {
            "d" => 86_400_000,
            "h" => 3_600_000,
            "m" => 60_000,
            _ => return Err(format!("bad duration {s} (d, h or m)")),
        };
        return Ok(now + n * ms);
    }
    if let [y, m, d] = s.split('-').collect::<Vec<_>>()[..]
        && let (Ok(y), Ok(m), Ok(d)) = (y.parse::<i64>(), m.parse::<i64>(), d.parse::<i64>())
    {
        // Days since 1970-01-01 (civil calendar, Howard Hinnant's algorithm).
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        return u64::try_from(days * 86_400_000).map_err(|_| format!("{s} is before 1970"));
    }
    s.parse().map_err(|_| format!("bad time {s}: YYYY-MM-DD, +30d or milliseconds"))
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

#[cfg(test)]
mod tests {
    #[test]
    fn until_times() {
        for (s, ms) in [("1970-01-01", 0), ("2000-02-29", 951_782_400_000), ("2026-10-20", 1_792_454_400_000), ("2026-12-31", 1_798_675_200_000), ("2100-03-01", 4_107_542_400_000)] {
            assert_eq!(super::parse_time(s), Ok(ms), "{s}");
        }
        assert_eq!(super::parse_time("1792454400000"), Ok(1_792_454_400_000));
        let in_a_day = super::parse_time("+1d").unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        assert!(in_a_day >= now + 86_399_000 && in_a_day <= now + 86_401_000);
        assert!(super::parse_time("+3w").is_err());
        assert!(super::parse_time("tomorrow").is_err());
    }
}
