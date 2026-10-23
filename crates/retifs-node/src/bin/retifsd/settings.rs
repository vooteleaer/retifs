//! `<store>/retifs.toml`: a node's settings, so they needn't all be flags.
//! Every setting is one of `retifsd`'s flags; flags given on the command line
//! override the file. Made with every setting commented out (the defaults)
//! when a node first starts, as Reticulum makes `~/.reticulum/config`.

use std::path::{Path, PathBuf};

pub const FILE: &str = "retifs.toml";

enum Kind {
    Value,
    Switch,
    List,
}

/// (section, key, flag, kind): the settings the file may hold.
const SETTINGS: &[(&str, &str, &str, Kind)] = &[
    ("store", "max_store", "--max-store", Kind::Value),
    ("store", "min_free", "--min-free", Kind::Value),
    ("store", "cache_max", "--cache-max", Kind::Value),
    ("store", "db_cache", "--db-cache", Kind::Value),
    ("node", "device", "--device", Kind::Value),
    ("node", "announce_every", "--announce-every", Kind::Value),
    ("node", "private_requests", "--private-requests", Kind::Switch),
    ("placement", "hold_for_others", "--hold-for-others", Kind::Value),
    ("placement", "lease_term", "--lease-term", Kind::Value),
    ("placement", "loss_target", "--loss-target", Kind::Value),
    ("placement", "min_copies", "--min-copies", Kind::Value),
    ("node", "site", "--site", Kind::Value),
    ("placement", "stamp_cost", "--stamp-cost", Kind::Value),
    ("placement", "max_stamp_cost", "--max-stamp-cost", Kind::Value),
    ("placement", "slow_link_budget", "--slow-link-budget", Kind::Value),
    ("placement", "treat_as_slow", "--treat-as-slow", Kind::List),
    ("nomadnet", "namespace", "--nomadnet", Kind::Value),
    ("nomadnet", "name", "--nomadnet-name", Kind::Value),
];

const TEMPLATE: &str = r#"# retifs node settings. Flags given to retifsd override these.
# Remove the # in front of a setting to change it; the values shown are the defaults.
# SIZE: bytes, or with K/M/G/T (powers of 1024). DURATION: seconds, or with m/h/d.

[store]
# max_store = "..."          # store limit (default: half the volume)
# min_free = "..."           # always leave this free on the volume (default: max(10 %, 5G))
# cache_max = "..."          # cache for others' content read here (default: 20 % of the limit)
# db_cache = "64M"           # the index's page cache in RAM

[node]
# device = "..."             # this device's name for keep tags and rules (default: the hostname)
# announce_every = "10m"     # how often to announce retifs.node (the announces say so)
# private_requests = false   # one item per have/get request when seeking: slower, less to correlate
# site = "..."               # where this node is (e.g. "prangli-home"): one copy of its files is kept at another site

[placement]
# hold_for_others = "..."    # hold others' encrypted copies up to this (default: up to the store limit; 0 opts out)
# lease_term = "30d"         # how long others hold this node's copies before renewal
# loss_target = 0.001        # place copies until the chance of losing a file is below this
# min_copies = 3             # and until there are at least this many copies, this node's own included
# stamp_cost = 20            # proof-of-work bits asked of others' lease offers
# max_stamp_cost = 24        # at most this many bits paid for an offer
# slow_link_budget = "10m"   # transfers over a slow link (LoRa) take at most this
# treat_as_slow = []         # nodes to treat as behind a slow link

[nomadnet]
# namespace = "..."          # serve this namespace's micron pages as a NomadNet node
# name = "retifs site"       # the node name it announces
"#;

/// The flags `<store>/retifs.toml` stands for, and its path. A missing file
/// is made (all defaults, commented out); an unknown section or key, or a
/// value of the wrong kind, is an error.
pub fn flags(store: &Path) -> Result<(PathBuf, Vec<String>), String> {
    let path = store.join(FILE);
    if !path.exists() {
        std::fs::create_dir_all(store).map_err(|e| format!("{}: {e}", store.display()))?;
        std::fs::write(&path, TEMPLATE).map_err(|e| format!("{}: {e}", path.display()))?;
        return Ok((path, Vec::new()));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map(|f| (path.clone(), f)).map_err(|e| format!("{}: {e}", path.display()))
}

fn parse(text: &str) -> Result<Vec<String>, String> {
    let table: toml::Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
    let mut out = Vec::new();
    for (section, body) in &table {
        let toml::Value::Table(body) = body else { return Err(format!("{section} should be a [section]")) };
        for (key, value) in body {
            let Some((_, _, flag, kind)) = SETTINGS.iter().find(|(s, k, _, _)| s == section && k == key) else {
                return Err(format!("unknown setting [{section}] {key}"));
            };
            let scalar = |v: &toml::Value| match v {
                toml::Value::String(s) => Ok(s.clone()),
                toml::Value::Integer(i) => Ok(i.to_string()),
                toml::Value::Float(f) => Ok(f.to_string()),
                _ => Err(format!("[{section}] {key} should be a number or a string")),
            };
            match kind {
                Kind::Switch => match value {
                    toml::Value::Boolean(true) => out.push(flag.to_string()),
                    toml::Value::Boolean(false) => {}
                    _ => return Err(format!("[{section}] {key} should be true or false")),
                },
                Kind::Value => out.extend([flag.to_string(), scalar(value)?]),
                Kind::List => {
                    let toml::Value::Array(items) = value else { return Err(format!("[{section}] {key} should be a list")) };
                    for v in items {
                        out.extend([flag.to_string(), scalar(v)?]);
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_is_all_defaults() {
        assert_eq!(parse(TEMPLATE).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn settings_become_flags() {
        let f = parse(
            r#"
            [store]
            min_free = "100M"
            db_cache = 33554432
            [node]
            device = "laptop"
            private_requests = true
            [placement]
            loss_target = 0.0001
            treat_as_slow = ["aa", "bb"]
            "#,
        )
        .unwrap();
        // Sections and keys in name order (toml's tables are sorted).
        assert_eq!(
            f,
            [
                "--device", "laptop", "--private-requests", "--loss-target", "0.0001", "--treat-as-slow", "aa",
                "--treat-as-slow", "bb", "--db-cache", "33554432", "--min-free", "100M"
            ]
        );
    }

    #[test]
    fn mistakes_are_named() {
        assert!(parse("[store]\nmax_stor = \"1G\"").unwrap_err().contains("unknown setting [store] max_stor"));
        assert!(parse("[node]\nprivate_requests = \"yes\"").unwrap_err().contains("true or false"));
        assert!(parse("max_store = \"1G\"").unwrap_err().contains("[section]"));
        assert!(parse("[store\n").is_err());
    }
}
