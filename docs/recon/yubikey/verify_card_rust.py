"""Checks card_check's output (crates/retifs-card) with Python RNS:
cargo run -p retifs-card --example card_check | python verify_card_rust.py"""
import sys
import RNS

vals = dict(line.split(None, 1) for line in sys.stdin if len(line.split(None, 1)) == 2)
ident = RNS.Identity(create_keys=False)
ident.load_public_key(bytes.fromhex(vals["public"].strip()))
assert ident.hash.hex() == vals["identity"].strip(), "identity hash"
assert RNS.Destination.hash_from_name_and_identity("retifs.node", ident).hex() == vals["retifs.node"].strip(), "retifs.node"
assert ident.validate(bytes.fromhex(vals["signature"].strip()), bytes.fromhex(vals["message"].strip())), "signature"
print("RNS: identity, destination and the card's signature check out")
