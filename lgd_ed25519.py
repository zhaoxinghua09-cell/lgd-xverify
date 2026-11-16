"""Ed25519 signature verification, pure Python, no dependencies.

Why this exists: the cross-format verdict cannot report PASS until a signature is
actually checked, and this project will not install a crypto library just to
claim it checked one. RFC 8032 verification is arithmetic, not a supply chain.

Correctness is established against the RFC's own test vectors, embedded below,
not against a round-trip with my own signing code. A signature scheme that only
agrees with itself proves nothing.

  python lgd_ed25519.py --selftest

Scope: Ed25519 only (no ctx / ph variants). Cofactorless verification, S < L
enforced, point decoding strict. What this does NOT do: constant-time execution.
This is a verifier for evidence, not a signing oracle for secrets.
"""

import hashlib
import sys

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I % P
    if (x * x - x2) % P != 0:
        return None
    if x & 1 != sign:
        x = P - x
    return x


def _decode_point(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    if x == 0 and sign:
        return None
    return (x, y)


def _add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return (x3, y3)


def _mul(p1, n):
    """Double-and-add. Slow, and that is acceptable for a verifier."""
    q = (0, 1)  # neutral element
    while n > 0:
        if n & 1:
            q = _add(q, p1)
        p1 = _add(p1, p1)
        n >>= 1
    return q


BASE_Y = 4 * pow(5, P - 2, P) % P
BASE_X = _recover_x(BASE_Y, 0)
BASE = (BASE_X, BASE_Y)


def verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    a = _decode_point(pubkey)
    if a is None:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    r = _decode_point(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + pubkey + message).digest(), "little") % L
    lhs = _mul(BASE, s)
    rhs = _add(r, _mul(a, k))
    return lhs == rhs


def _encode_point(p):
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def public_key(secret: bytes) -> bytes:
    if len(secret) != 32:
        raise ValueError("an Ed25519 secret is 32 bytes")
    h = hashlib.sha512(secret).digest()
    s = int.from_bytes(h[:32], "little")
    s &= (1 << 254) - 8
    s |= 1 << 254
    return _encode_point(_mul(BASE, s))


def sign(secret: bytes, message: bytes) -> bytes:
    """Deterministic signing, per RFC 8032 §5.1.6. Used only to make corpus
    fixtures; the secret in this repository is a public test value."""
    if len(secret) != 32:
        raise ValueError("an Ed25519 secret is 32 bytes")
    h = hashlib.sha512(secret).digest()
    s = int.from_bytes(h[:32], "little")
    s &= (1 << 254) - 8
    s |= 1 << 254
    prefix = h[32:]
    a = _encode_point(_mul(BASE, s))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    rr = _encode_point(_mul(BASE, r))
    k = int.from_bytes(hashlib.sha512(rr + a + message).digest(), "little") % L
    ss = (r + k * s) % L
    return rr + ss.to_bytes(32, "little")


# ------------------------------------------------------- RFC 8032 §7.1 vectors# (name, pubkey_hex, message_hex, signature_hex)
VECTORS = [
    ("TEST 1 · empty message",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("TEST 2 · 1 byte",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("TEST 3 · 2 bytes",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("TEST SHA(abc) · 64 bytes",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
     "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]

SECRETS = [
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
]


def selftest():
    print("lgd_ed25519 --selftest  (vectors: RFC 8032 §7.1)")
    print("---------------------------------------------")
    bad = 0
    for name, pk, msg, sig in VECTORS:
        ok = verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig))
        bad += 0 if ok else 1
        print("  %-4s %-34s verify=%s" % ("ok" if ok else "FAIL", name, ok))

    # The signing path is checked against the same vectors: if our sign() did not
    # reproduce the RFC's bytes exactly, it would agree with itself and prove
    # nothing about interoperability.
    for (name, pk, msg, sig), secret in zip(VECTORS, SECRETS):
        derived = public_key(bytes.fromhex(secret)).hex()
        produced = sign(bytes.fromhex(secret), bytes.fromhex(msg)).hex()
        ok = derived == pk and produced == sig
        bad += 0 if ok else 1
        print("  %-4s %-34s pubkey=%s signature=%s"
              % ("ok" if ok else "FAIL", name + " (sign)",
                 derived == pk, produced == sig))

    # Negative controls: each must be rejected. A verifier that accepts everything
    # passes every positive vector above.
    pk, msg, sig = (bytes.fromhex(VECTORS[1][1]), bytes.fromhex(VECTORS[1][2]),
                    bytes.fromhex(VECTORS[1][3]))
    flipped = bytearray(sig)
    flipped[5] ^= 0x01
    controls = [
        ("one signature byte flipped", verify(pk, msg, bytes(flipped))),
        ("message altered", verify(pk, b"r" + msg, sig)),
        ("wrong public key", verify(bytes.fromhex(VECTORS[2][1]), msg, sig)),
        ("S not below L", verify(pk, msg, sig[:32] + (L + 1).to_bytes(32, "little"))),
        ("truncated signature", verify(pk, msg, sig[:63])),
    ]
    for name, accepted in controls:
        ok = accepted is False
        bad += 0 if ok else 1
        print("  %-4s %-34s accepted=%s (must be False)" % ("ok" if ok else "FAIL", name, accepted))

    print()
    if bad:
        print("FAIL — %d check(s) wrong; do not use this verifier" % bad)
        return 1
    print("PASS — %d RFC vectors verified, %d negative controls rejected" % (len(VECTORS), len(controls)))
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    print(__doc__)
    sys.exit(2)
