"""Verifies test-vectors/recovery-v1.json (ADR-0033, the recovery kit) with
Python RNS (HKDF, Identity) and hashlib/hmac only. The words are read the
BIP-39 way here, from the word list, apart from the Rust code.

    python crates/retifs-core/test-vectors/verify_recovery_rns.py
"""

import hashlib
import hmac
import json
import sys
from pathlib import Path

import RNS
from RNS.Cryptography.HKDF import hkdf

HERE = Path(__file__).parent
WORDS = [w.strip() for w in (HERE.parent / "src" / "bip39-english.txt").read_text().split() if w.strip()]


def bip39_words(seed):
    bits = int.from_bytes(seed + hashlib.sha256(seed).digest()[:1], "big")
    return [WORDS[(bits >> (11 * (23 - i))) & 0x7FF] for i in range(24)]


def k(seed, info):
    return hkdf(32, seed, b"retifs/v1/recovery", info.encode())


def main():
    vectors = json.loads((HERE / "recovery-v1.json").read_text())
    failed = 0
    for c in vectors["cases"]:
        seed = bytes.fromhex(c["seed"])
        secret = k(seed, "x25519") + k(seed, "ed25519")
        ident = RNS.Identity.from_bytes(secret)
        writer = ident.get_public_key()[32:]
        locator = k(seed, "keyring-locator")
        node = bytes.fromhex(c["node"])
        checks = {
            "words": " ".join(bip39_words(seed)) == c["words"],
            "secret": secret.hex() == c["identity_secret"],
            "public": ident.get_public_key().hex() == c["identity_public"],
            "hash": ident.hash.hex() == c["identity_hash"],
            "ns_id": hashlib.sha256(b"retifs/v1/ns" + writer).digest()[:16].hex() == c["keyring_ns_id"],
            "read key": k(seed, "keyring-read").hex() == c["keyring_read_key"],
            "locator": locator.hex() == c["locator"],
            "tag": hmac.new(locator, node, hashlib.sha256).digest()[:16].hex() == c["node_tag"],
        }
        bad = [name for name, ok in checks.items() if not ok]
        failed += bool(bad)
        print(("ok  " if not bad else "FAIL"), c["seed"][:8], c["words"].split()[0], "…", c["identity_hash"], *bad)
    print(f"{len(vectors['cases']) - failed}/{len(vectors['cases'])} recovery cases match")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
