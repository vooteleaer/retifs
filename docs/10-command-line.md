# Using retifs from the command line

Everything the apps do goes through `retifsd`'s local API ([native API](07-api.md)); the `retifs` command is the same API on a terminal. `retifs` with no arguments prints every command.

## Installing

retifs runs on Linux, Windows and Haiku. The daemon, `retifsd`, attaches to the machine's Reticulum shared instance, so start [prnsd](https://github.com/KenAKAFrosty/Prns) (or Python `rnsd`) first. retifs never brings its own.

**Debian, Ubuntu, Raspberry Pi OS (amd64, arm64):** install a `retifs_*.deb` (built by `packaging/deb/build-deb.sh`) with `sudo apt install ./retifs_*.deb`. It starts `retifsd` in every user's session once Reticulum is up; see `/usr/share/doc/retifs/README.Debian`. It needs glibc 2.36 or newer (Debian 12).

**Windows 10 and 11:** run `retifs-setup-*.exe` (built by `packaging\windows\build-setup.ps1`). It installs for the current user, no administrator needed: the programs in `%LOCALAPPDATA%\Programs\retifs`, `retifs` on the PATH, and a utility in the notification area, started at login, which starts `retifsd` once Reticulum is up. Uninstall from Apps & features; your data stays.

**From source:** retifs builds against Prns 0.3.8, which isn't on crates.io yet. Check it out next to retifs (Cargo can't fetch the Prns repository on Windows: its paths are too long):

```sh
git clone https://github.com/KenAKAFrosty/Prns.git Prns-0.3.8
git -C Prns-0.3.8 checkout v0.3.8-hotfix.1
```

```sh
cargo install --path crates/retifs-node      # retifsd and the retifs CLI
cargo install --path crates/retifs-fuse      # retifs-mount (needs fuse3)
cargo install --path crates/retifs-gateway   # retifs-gateway
cargo install --path crates/retifs-extract   # retifs-extractd
cargo install --path crates/retifs-cloudfiles   # on Windows: retifs-cloudfiles
cp packaging/systemd/*.service ~/.config/systemd/user/
systemctl --user enable --now retifsd
```

**Settings** live in `retifs.toml` in the store (`~/.local/share/retifs/` on Linux, `%LOCALAPPDATA%\retifs\` on Windows, `~/config/var/retifs` on Haiku), made with every setting commented out on first start: disk budget, device name, how often to announce, how much to hold for others, and so on. Flags given to `retifsd` override the file.

## Records, attributes and queries

```sh
retifs rec add photos album="Prangli 2026" --file boat.jpg
retifs query photos 'album=Prangli 2026'
retifs rec history photos <id>
retifs query '*' type=image/jpeg --save Photos   # saved in your library me: every device has it
retifs saved run Photos --watch                  # live: again whenever it changes
```

## As a file tree

On Linux and Windows alike:

```sh
retifs mount photos            # ~/retifs/photos (or give a folder)
retifs mount                   # what's mounted where
retifs unmount photos
retifs mount photos --via home # a library your home node holds, nothing of it kept here
```

(For `--via`, the home node admits this one first: `retifs app add laptop --ns photos --write --device <this node>`; `home` is a contact or a node address.)

- **Linux:** a FUSE mount. Attributes are `user.retifs.*` xattrs; `.query/<terms>/` lists matches (`ls ~/retifs/photos/.query/album=Prangli\ 2026/`); `systemctl --user enable --now retifs-mount@photos` mounts it at login.
- **Windows:** a folder in Explorer. Files are fetched when opened, "Always keep on this device" keeps them here, **Share with retifs…** is in the context menu, and a library you may only read is a read-only folder. `retifs unmount photos --forget` also removes it from Explorer.
- **Haiku:** each library is a volume in `~/retifs`, with its attributes as Haiku attributes and live queries in Tracker.
- Photos in albums also show under `Albums/<album>/`: the same files, and deleting one there only takes it out of the album.

As websites, one origin per library, read-only: `systemctl --user enable --now retifs-gateway`, then open <http://localhost:8740/>.

## Attributes from what's in files

As BeOS gave files theirs when they arrived, `retifs-extractd` watches your libraries and describes new content, whatever route it came in by: `mime` and `type`, a photo's size, `camera`, `taken` and `geo`, a recording's `audio.artist`, `audio.title` and `duration`, a document's `doc.title`, `doc.author` and `doc.pages`. Then `retifs query photos has:camera` or `type=audio/mpeg audio.artist=Bach` finds them. It's an app that may write only those keys:

```sh
retifs app add extract --ns photos,music --write \
  --keys mime,width,height,taken,camera,geo,duration,'exif.*','audio.*','doc.*','block:*',@content,type,extracted \
  > ~/.config/retifs/extract.token
systemctl --user enable --now retifs-extractd
```

One of your nodes running it is enough ([ADR-0023](adr/0023-attribute-extraction.md)).

## Sharing

**A whole library** with another device or person:
1. `retifs ns link photos` prints a `retifs:ns/…` link (the address and your node). Whoever has it can read.
2. On their side, `retifs open <link>` joins it.
3. To let them write too, give them an invitation instead: `retifs invite create photos` prints a one-use `retifs:invite/…` link; `retifs open <link>` joins and gets the grant in one step (or as soon as your node is reachable).

**Part of a library** (an album, a folder): `retifs share create prangli --from photos 'album=Prangli 2026' --omit geo` makes a library `prangli` holding just those records (without `geo`), kept up to date by your nodes, and prints its link. `retifs share list photos` and `share rm` list and end shares.

**Contacts:** `retifs me link --name Alice` gives a link others add you with (`retifs open <link>`), and `retifs me` shows six words to compare in person. Contacts live in your library `me`, and their names work in place of node addresses (`--from Alice`).

## Copies and devices

Every file has three copies by default, yours and two on nearby nodes (encrypted). `retifs ns copies photos 4` sets a library's own number; `retifs nodes` shows the storage nodes this one knows. Give each node its site (`site = "prangli-home"` in `retifs.toml`) and one copy is always kept at another site. Each node keeps everything by default; for a small device, `retifs ns keep photos rules` and tag what it should keep: `keep:<device>=true`, or a keep-rule record.

## Leaving and deleting

- `retifs ns leave photos` removes a library from this device; others keep theirs. One made on this device needs `--mine`: if no other device has it, it's gone.
- `retifs ns delete photos --yes` deletes it on every member's device ([ADR-0034](adr/0034-deleting-a-library.md)): only a member who may invite others can.
