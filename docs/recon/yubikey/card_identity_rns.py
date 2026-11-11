# Generates an Ed25519 (signature) and X25519 (decryption) key on the
# YubiKey's OpenPGP application and checks them against Python RNS.
import sys
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.openpgp import OpenPgpSession, KEY_REF, OID, EcAttributes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

ADMIN, PIN = "12345678", "123456"
raw = lambda k: k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

dev, _ = list_all_devices()[0]
with dev.open_connection(SmartCardConnection) as conn:
    s = OpenPgpSession(conn)
    s.verify_admin(ADMIN)
    if "--generate" in sys.argv:
        s.set_algorithm_attributes(KEY_REF.SIG, EcAttributes.create(KEY_REF.SIG, OID.Ed25519))
        s.set_algorithm_attributes(KEY_REF.DEC, EcAttributes.create(KEY_REF.DEC, OID.X25519))
        sig_pub = s.generate_ec_key(KEY_REF.SIG, OID.Ed25519)
        dec_pub = s.generate_ec_key(KEY_REF.DEC, OID.X25519)
    else:
        sig_pub = s.get_public_key(KEY_REF.SIG)
        dec_pub = s.get_public_key(KEY_REF.DEC)
    ed, x = raw(sig_pub), raw(dec_pub)
    print("ed25519", ed.hex()); print("x25519 ", x.hex())

    import RNS
    ident = RNS.Identity(create_keys=False)
    ident.load_public_key(x + ed)          # RNS: X25519 public ‖ Ed25519 public
    print("RNS identity hash", ident.hash.hex())
    print("retifs.node dest ", RNS.Destination.hash_from_name_and_identity("retifs.node", ident).hex())

    # Signing: the card signs the message itself (pure Ed25519), as RNS does.
    s.verify_pin(PIN)
    for n in (32, 400):
        msg = bytes(range(256)) * 2
        msg = msg[:n]
        sig = s.sign(msg, None)
        print(f"sign {n} B: RNS validates:", ident.validate(sig, msg))

    # Key agreement: RNS encrypts to the identity; the card's ECDH opens it.
    token = ident.encrypt(b"hello from RNS")
    eph = token[:32]
    s.verify_pin(PIN, extended=True)
    shared = s.decrypt(x25519.X25519PublicKey.from_public_bytes(eph))
    from RNS.Cryptography import hkdf
    from RNS.Cryptography.Token import Token
    key = hkdf(length=64, derive_from=shared, salt=ident.get_salt(), context=ident.get_context())
    print("RNS token opened with the card's ECDH:", Token(key).decrypt(token[32:]))
