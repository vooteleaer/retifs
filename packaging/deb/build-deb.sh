#!/bin/bash
# Builds retifs_<version>_<arch>.deb for amd64 and arm64 (Debian, Ubuntu,
# Raspberry Pi OS), with the prnsd it needs bundled.
#
#     packaging/deb/build-deb.sh [OUT_DIR] [ARCH...]
#
# On a Debian or Ubuntu x86_64 machine (WSL works) with Rust, dpkg-deb and
# `rustup target add aarch64-unknown-linux-gnu`. With cargo-zigbuild (and
# zig) the binaries are linked against glibc $GLIBC (default 2.36: Debian 12,
# Raspberry Pi OS bookworm), whatever the build machine has; without it,
# against the build machine's glibc, and arm64 needs gcc-aarch64-linux-gnu.
# Prns 0.3.8 is expected next to retifs (`../Prns-0.3.8`, see the README), or
# at $PRNS.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PRNS=${PRNS:-$(cd "$ROOT/../Prns-0.3.8" && pwd)}
OUT=${1:-$ROOT/target/deb}
shift || true
ARCHS=${*:-amd64 arm64}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/retifs-node/Cargo.toml" | head -1 | tr -d '\r')
COMMIT=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE=$(git -C "$ROOT" log -1 --format=%cd --date=format:%Y%m%d 2>/dev/null || date +%Y%m%d)
DEBVER="$VERSION~git$DATE.$COMMIT"
PRNS_VERSION=$(cat "$PRNS/VERSION" 2>/dev/null || echo 0.3.8)
BINS="retifsd retifs retifs-mount retifs-gateway retifs-extractd"
GLIBC=${GLIBC:-2.36}
if command -v cargo-zigbuild >/dev/null; then
    BUILD="cargo zigbuild"; SUFFIX=".$GLIBC"
else
    BUILD="cargo build"; SUFFIX=""; GLIBC=$(ldd --version | sed -n '1s/.* //p')
    # zig links for any target itself; without it, arm64 needs the cross gcc.
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}
fi
mkdir -p "$OUT"

for ARCH in $ARCHS; do
    case $ARCH in
        amd64) TARGET=x86_64-unknown-linux-gnu ;;
        arm64) TARGET=aarch64-unknown-linux-gnu ;;
        *) echo "unknown arch $ARCH" >&2; exit 2 ;;
    esac
    echo "== $ARCH: building retifs"
    $BUILD --release --locked --target $TARGET$SUFFIX --manifest-path "$ROOT/Cargo.toml" \
        -p retifs-node -p retifs-fuse -p retifs-gateway -p retifs-extract
    echo "== $ARCH: building prnsd $PRNS_VERSION"
    $BUILD --release --locked --target $TARGET$SUFFIX --manifest-path "$PRNS/prnsd/Cargo.toml" \
        --no-default-features --features tokio-host,observability
    BIN=$CARGO_TARGET_DIR/$TARGET/release

    STAGE=$(mktemp -d)
    chmod 0755 "$STAGE"
    trap 'rm -rf "$STAGE"' EXIT
    install -d "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/lib/retifs" "$STAGE/usr/lib/systemd/user" "$STAGE/usr/share/doc/retifs"
    for b in $BINS; do
        install -m 0755 "$BIN/$b" "$STAGE/usr/bin/$b"
    done
    install -m 0755 "$BIN/prnsd" "$STAGE/usr/lib/retifs/prnsd"
    install -m 0755 "$HERE/no-shared-instance" "$HERE/wait-shared-instance" "$STAGE/usr/lib/retifs/"
    # The user units, pointed at the installed binaries.
    for u in "$ROOT"/packaging/systemd/*.service; do
        sed -e 's|%h/.cargo/bin/|/usr/bin/|g' -e '/^#   cp packaging/d' "$u" > "$STAGE/usr/lib/systemd/user/$(basename "$u")"
    done
    # retifsd waits for Reticulum, and brings the bundled one where none runs.
    # PartOf: restarted with it, as retifsd does not attach to a new shared instance by itself.
    sed -i -e 's|^After=network-online.target|After=network-online.target retifs-prnsd.service\nWants=retifs-prnsd.service\nPartOf=retifs-prnsd.service|' \
        -e 's|^ExecStart=/usr/bin/retifsd|ExecStartPre=/usr/lib/retifs/wait-shared-instance\nExecStart=/usr/bin/retifsd|' \
        "$STAGE/usr/lib/systemd/user/retifsd.service"
    install -m 0644 "$HERE/retifs-prnsd.service" "$STAGE/usr/lib/systemd/user/"
    # Licenses: retifs's, and Prns's for the bundled prnsd.
    DOC=$STAGE/usr/share/doc/retifs
    install -m 0644 "$ROOT/LICENSE" "$DOC/copyright"
    install -m 0644 "$PRNS/LICENSE-MIT" "$DOC/prns-LICENSE-MIT"
    install -m 0644 "$PRNS/LICENSE-APACHE" "$DOC/prns-LICENSE-APACHE"
    install -m 0644 "$PRNS/THIRD_PARTY_NOTICES.md" "$DOC/prns-THIRD_PARTY_NOTICES.md"
    install -m 0644 "$HERE/README.Debian" "$DOC/"

    SIZE=$(du -sk "$STAGE/usr" | cut -f1)
    cat > "$STAGE/DEBIAN/control" <<EOF
Package: retifs
Version: $DEBVER
Architecture: $ARCH
Maintainer: retifs <https://github.com/vooteleaer/retifs>
Installed-Size: $SIZE
Depends: libc6 (>= $GLIBC), fuse3
Section: net
Priority: optional
Homepage: https://github.com/vooteleaer/retifs
Description: distributed, always-encrypted data over Reticulum (prototype)
 Records and libraries instead of files, synced between your devices and
 others' over Reticulum, encrypted end to end. A working prototype: the
 formats still change, keep no data in it you can't lose.
 .
 Includes retifsd, the retifs command, the FUSE mount, the local web
 gateway, the attribute extractor, and prnsd $PRNS_VERSION (Prns, MIT or
 Apache-2.0), started only where no Reticulum shared instance runs yet.
EOF
    install -m 0755 "$HERE/postinst" "$HERE/prerm" "$STAGE/DEBIAN/"
    DEB="$OUT/retifs_${DEBVER}_${ARCH}.deb"
    dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$DEB" >/dev/null
    rm -rf "$STAGE"
    trap - EXIT
    echo "== $DEB ($(du -h "$DEB" | cut -f1))"
done
