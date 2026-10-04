#!/usr/bin/env python3
"""radio-fw crypto vs independent implementations: the C CCM against tools/pulsar_host.py's
ccm_encrypt and pulsar_crypto.ccm_decrypt (the decode tool), the C X25519 against `cryptography`."""
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
exe = os.path.abspath(sys.argv[1])

from pulsar_crypto import ccm_decrypt, nonce_from_fields  # noqa: E402
from pulsar_host import ccm_encrypt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

rnd = random.Random(11)
rb = lambda n: bytes(rnd.randrange(256) for _ in range(n))  # noqa: E731

cases = []
for i in range(400):
    key = rb(16)
    nonce = nonce_from_fields(rnd.getrandbits(39), rnd.randrange(2), rb(8))
    pt = rb(rnd.randrange(0, 140))
    cases.append((key, nonce, pt))
inp = "".join(f"{k.hex()} {n.hex()} 00 {p.hex() or '-'}\n" for k, n, p in cases)
out = subprocess.run([exe, "ccm"], input=inp, capture_output=True, text=True, check=True).stdout.split()
assert len(out) == len(cases)
for (key, nonce, pt), got in zip(cases, out):
    got = bytes.fromhex(got)
    assert got == ccm_encrypt(key, nonce, pt), (key.hex(), nonce.hex(), pt.hex())
    back, ok = ccm_decrypt(key, nonce, got)
    assert ok and back == pt
print(f"ccm: {len(cases)} random packets match pulsar_host.ccm_encrypt and decrypt with pulsar_crypto")

lines, want = [], []
for i in range(40):
    s = rb(32)
    peer = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    lines.append(f"{s.hex()} {peer.hex()}\n")
    want.append(X25519PrivateKey.from_private_bytes(s).exchange(X25519PublicKey.from_public_bytes(peer)))
out = subprocess.run([exe, "x25519"], input="".join(lines), capture_output=True, text=True, check=True).stdout.split()
assert [bytes.fromhex(o) for o in out] == want
print(f"x25519: {len(want)} random exchanges match the cryptography package")
