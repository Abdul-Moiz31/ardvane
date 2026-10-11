"""Ed25519 signature verification (RFC 8032), standard library only.

Part of Ardvane (MIT License). Used to check that the detection feed was signed by Ardvane's feed workflow before a
single indicator from it is used. Verification only: nothing here ever holds a private key. Follows the reference
implementation in RFC 8032 section 6; correctness is pinned by the RFC's own test vectors in the tests.
"""
import hashlib

P = 2 ** 255 - 19                                          # the field
Q = 2 ** 252 + 27742317777372353535851937790883648493     # the group order
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    """Point addition in extended coordinates (x, y, z, t)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa, pb = (y1 - x1) * (y2 - x2) % P, (y1 + x1) * (y2 + x2) % P
    pc, pd = 2 * t1 * t2 * D % P, 2 * z1 * z2 % P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return e * f % P, g * h % P, f * g % P, e * h % P


def _mul(s, point):
    result = (0, 1, 1, 0)                                  # the neutral element
    while s > 0:
        if s & 1:
            result = _add(result, point)
        point = _add(point, point)
        s >>= 1
    return result


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)


def verify(public_key, message, signature):
    """True only if `signature` (64 bytes) is a valid Ed25519 signature of `message` by `public_key` (32 bytes)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public_key), _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:                                             # rejects malleable signatures
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % Q
    return _equal(_mul(s, BASE), _add(r, _mul(h, a)))
