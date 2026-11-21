"""Generates the MeshCore Local API conformance vectors in ../*.json.

Run from anywhere:

    uv run --with cryptography python vectors/gen/generate.py

The output is deterministic: the test key is derived from a fixed label and the
signatures use RFC 6979 deterministic ECDSA. Each signature is produced twice,
by `cryptography` (OpenSSL) and by the small pure-Python RFC 6979 signer below,
and the script stops if they differ. The pure-Python signer is first checked
against the P-256/SHA-256 "sample" vector from RFC 6979 appendix A.2.5.

The key pair is for tests only. Never pair it with a real server.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

OUT = Path(__file__).resolve().parent.parent

# --- P-256 arithmetic (only what RFC 6979 signing needs) --------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], -1, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return (x, (lam * (p1[0] - x) - p1[1]) % P)


def _mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _on_curve(x, y):
    return x < P and y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _int2octets(x):
    return x.to_bytes(32, "big")


def _bits2octets(h):
    return _int2octets(int.from_bytes(h, "big") % N)


def rfc6979_sign(d: int, message: bytes) -> tuple[int, int]:
    """Deterministic ECDSA (RFC 6979 section 3.2) with SHA-256 on P-256."""
    h1 = hashlib.sha256(message).digest()
    e = int.from_bytes(h1, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + _int2octets(d) + _bits2octets(h1), "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    k = hmac.new(k, v + b"\x01" + _int2octets(d) + _bits2octets(h1), "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    while True:
        v = hmac.new(k, v, "sha256").digest()
        kk = int.from_bytes(v, "big")
        if 1 <= kk < N:
            r = _mul(kk, G)[0] % N
            s = pow(kk, -1, N) * (e + r * d) % N
            if r and s:
                return r, s
        k = hmac.new(k, v + b"\x00", "sha256").digest()
        v = hmac.new(k, v, "sha256").digest()


def _self_test():
    # RFC 6979 appendix A.2.5, P-256, SHA-256, message "sample".
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    r, s = rfc6979_sign(d, b"sample")
    assert r == 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716, hex(r)
    assert s == 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8, hex(s)


# --- helpers ----------------------------------------------------------------


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64url_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode()


def raw_sig(r: int, s: int) -> bytes:
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def fingerprint(raw_xy: bytes) -> str:
    h = hashlib.sha256(raw_xy).digest()[:8].hex().upper()
    return " ".join(h[i : i + 4] for i in range(0, 16, 4))


def der_int(v: int, pad: bool = False) -> bytes:
    body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if body[0] & 0x80 or pad:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def der_seq(*parts: bytes, long_len: bool = False) -> bytes:
    body = b"".join(parts)
    length = bytes([0x81, len(body)]) if long_len else bytes([len(body)])
    return b"\x30" + length + body


def verify(pub: ec.EllipticCurvePublicKey, sig_der: bytes, message: bytes) -> bool:
    try:
        pub.verify(sig_der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# --- the test key -----------------------------------------------------------

KEY_LABEL = "meshcore-local-api test vector key 1 (TEST ONLY, never pair it)"
OTHER_LABEL = "meshcore-local-api test vector key 2 (TEST ONLY, never pair it)"


def derive_key(label: str) -> int:
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % (N - 1) + 1


def key_material(d: int):
    priv = ec.derive_private_key(d, ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    assert _mul(d, G) == (nums.x, nums.y)
    return priv, raw


def pairing_vectors():
    d = derive_key(KEY_LABEL)
    priv, raw = key_material(d)
    pub = priv.public_key()
    _, other_raw = key_material(derive_key(OTHER_LABEL))

    pkcs8 = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    spki = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    nonce_bytes = hashlib.sha256(b"meshcore-local-api test nonce 1").digest()[:16]
    nonce_nopad = b64url_nopad(nonce_bytes)
    nonce_pad = b64url_pad(nonce_bytes)
    assert len(nonce_nopad) == 22 and len(nonce_pad) == 24

    prefixes = {
        "canonical": "meshcore-local-api-pair-v1:",
    }

    signatures = []
    for nonce_name, nonce in (("unpadded", nonce_nopad), ("padded", nonce_pad)):
        for form, prefix in prefixes.items():
            msg = prefix + nonce
            r, s = rfc6979_sign(d, msg.encode())
            der = priv.sign(msg.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
            assert decode_dss_signature(der) == (r, s), "OpenSSL and RFC 6979 disagree"
            assert der == encode_dss_signature(r, s)
            assert verify(pub, der, msg.encode())
            high_s = N - s
            assert verify(pub, encode_dss_signature(r, high_s), msg.encode())
            signatures.append(
                {
                    "nonce": nonce,
                    "nonceForm": nonce_name,
                    "messageForm": form,
                    "message": msg,
                    "messageUtf8Hex": msg.encode().hex(),
                    "sha256Hex": hashlib.sha256(msg.encode()).hexdigest(),
                    "rHex": f"{r:064x}",
                    "sHex": f"{s:064x}",
                    "derBase64": b64(der),
                    "rawBase64": b64(raw_sig(r, s)),
                    "sIsLow": s <= N // 2,
                    "highSRawBase64": b64(raw_sig(r, high_s)),
                    "highSDerBase64": b64(encode_dss_signature(r, high_s)),
                }
            )

    # Signatures that MUST be refused for the first canonical message.
    base = signatures[0]
    msg = base["message"]
    r, s = int(base["rHex"], 16), int(base["sHex"], 16)
    der = base64.b64decode(base["derBase64"])
    other_msg = ("meshcore-open-pair-v1:" + base["nonce"]).encode()
    other_der = priv.sign(other_msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    invalid = [
        {
            "why": "signature over another string with the same nonce (meshcore-open-pair-v1:<nonce>)",
            "signatureBase64": b64(other_der),
        },
        {"why": "one bit of s flipped (raw r||s)", "signatureBase64": b64(raw_sig(r, s ^ 1))},
        {"why": "r = 0 (raw r||s)", "signatureBase64": b64(raw_sig(0, s))},
        {"why": "s = 0 (raw r||s)", "signatureBase64": b64(raw_sig(r, 0))},
        {"why": "s = n (raw r||s)", "signatureBase64": b64(raw_sig(r, N))},
        {"why": "r = n + r (raw r||s; out of range, only correct mod n)", "signatureBase64": None},
        {"why": "DER with a trailing byte", "signatureBase64": b64(der + b"\x00")},
        {
            "why": "DER with a non-minimal INTEGER (extra leading zero on r)",
            "signatureBase64": b64(der_seq(der_int(r, pad=True), der_int(s))),
        },
        {
            "why": "DER with a long-form SEQUENCE length (BER, not DER)",
            "signatureBase64": b64(der_seq(der_int(r), der_int(s), long_len=True)),
        },
        {"why": "63 bytes (raw r||s truncated)", "signatureBase64": b64(raw_sig(r, s)[:63])},
        {"why": "65 bytes (raw r||s with an extra byte)", "signatureBase64": b64(raw_sig(r, s) + b"\x00")},
        {"why": "not base64", "signatureBase64": "!!not base64!!"},
        {"why": "empty", "signatureBase64": ""},
    ]
    # r + n does not fit in 32 bytes for most r; drop the case when it does not.
    if r + N < 2**256:
        invalid[5]["signatureBase64"] = b64(raw_sig(r + N, s))
    else:
        invalid.pop(5)
    for case in invalid:
        sig = base64.b64decode(case["signatureBase64"]) if case["signatureBase64"] not in ("", "!!not base64!!") else b""
        if len(sig) == 64:
            rr, ss = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            ok = 0 < rr < N and 0 < ss < N and verify(pub, encode_dss_signature(rr, ss), msg.encode())
            assert not ok, case
    flipped_y = bytearray(raw)
    flipped_y[63] ^= 1
    assert not _on_curve(int.from_bytes(flipped_y[:32], "big"), int.from_bytes(flipped_y[32:], "big"))
    x_ge_p = (P).to_bytes(32, "big") + raw[32:]

    public_keys_invalid = [
        {"why": "last bit of Y flipped: not on the curve", "publicKey": b64(bytes(flipped_y))},
        {"why": "65-byte SEC1 form with the 0x04 prefix (the API takes X||Y only)", "publicKey": b64(b"\x04" + raw)},
        {"why": "33-byte compressed form", "publicKey": b64(bytes([2 + (raw[63] & 1)]) + raw[:32])},
        {"why": "X equal to the field prime", "publicKey": b64(x_ge_p)},
        {"why": "all zeros (the point at infinity has no X||Y form)", "publicKey": b64(bytes(64))},
        {"why": "32 bytes", "publicKey": b64(raw[:32])},
        {"why": "not base64", "publicKey": "not base64 !"},
    ]

    zero_fp = fingerprint(bytes(64))
    return {
        "description": "Pairing vectors for MeshCore Local API protocol 1 (SPEC.md section 5).",
        "warning": "TEST ONLY. This key pair is public. Never pair it with a server that talks to a real radio.",
        "curve": "P-256 (secp256r1, prime256v1)",
        "signatureAlgorithm": "ECDSA with SHA-256 over the UTF-8 bytes of the message (SHA256withECDSA)",
        "deterministic": "RFC 6979; verifiers must not depend on it, any valid ECDSA signature is accepted",
        "testKey": {
            "label": KEY_LABEL,
            "derivation": "d = (SHA-256(UTF-8 label) as a big-endian integer) mod (n - 1) + 1",
            "privateScalarHex": f"{d:064x}",
            "privateKeyPkcs8DerBase64": b64(pkcs8),
            "publicKeySpkiDerBase64": b64(spki),
            "publicKeySec1UncompressedHex": "04" + raw.hex(),
            "publicKeyXHex": raw[:32].hex(),
            "publicKeyYHex": raw[32:].hex(),
            "publicKey": b64(raw),
            "fingerprintInputSha256Hex": hashlib.sha256(raw).hexdigest(),
            "fingerprint": fingerprint(raw),
            "fingerprintNormalized": fingerprint(raw).replace(" ", ""),
        },
        "otherKey": {
            "label": OTHER_LABEL,
            "publicKey": b64(other_raw),
            "fingerprint": fingerprint(other_raw),
            "note": "Any signature in this file must fail against this key.",
        },
        "fingerprintOfZeroBytes": {
            "input": "64 zero bytes (not a valid key; tests the fingerprint function alone)",
            "fingerprint": zero_fp,
        },
        "nonce": {
            "bytesHex": nonce_bytes.hex(),
            "unpadded": nonce_nopad,
            "padded": nonce_pad,
            "note": "The client signs the challenge's nonce exactly as sent; it never re-encodes it.",
        },
        "validSignatures": signatures,
        "invalidSignatures": {
            "publicKey": b64(raw),
            "message": msg,
            "cases": invalid,
        },
        "invalidPublicKeys": public_keys_invalid,
        "challengeMessageCheck": {
            "description": "A client accepts the challenge's message only when it equals this, built from the challenge's own nonce.",
            "nonce": nonce_nopad,
            "accept": [
                "meshcore-local-api-pair-v1:" + nonce_nopad,
            ],
            "reject": [
                "meshcore-open-pair-v1:" + nonce_nopad,
                "meshcore-local-api-pair-v1:" + nonce_pad,
                "meshcore-local-api-pair-v2:" + nonce_nopad,
                "meshcore-local-api-pair-v1: " + nonce_nopad,
                "meshcore-local-api-pair-v1:" + nonce_nopad + "\n",
                "MESHCORE-LOCAL-API-PAIR-V1:" + nonce_nopad,
                "please sign this: meshcore-local-api-pair-v1:" + nonce_nopad,
                nonce_nopad,
                "",
            ],
        },
        "nonceShape": {
            "regex": "^[A-Za-z0-9_-]{16,128}={0,2}$",
            "accept": [nonce_nopad, nonce_pad, "A" * 16, "A" * 128, "abcd_efgh-ijkl_mn"],
            "reject": ["A" * 15, "A" * 129, "abc+defghijklmnop", "abc/defghijklmnop", "abcdefghijklmnop===", "abcdefgh ijklmnop", ""],
        },
    }


# --- validators ---------------------------------------------------------------


def hashtag_ok(s: str) -> bool:
    if not s.startswith("#"):
        return False
    rest = s[1:]
    return 1 <= len(rest) <= 31 and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in rest)


def region_ok(s: str) -> bool:
    return 1 <= len(s) <= 30 and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in s)


def path_check(path, size):
    """Returns ("flood"|"zero_hop"|"direct", hops) or ("bad_request", reason)."""
    if path is None:
        return {"result": "flood"}
    if not isinstance(path, str):
        return {"error": "bad_request", "reason": "path is not a string"}
    if size is None:
        hs = 1
    elif isinstance(size, int) and not isinstance(size, bool) and 1 <= size <= 3:
        hs = size
    else:
        return {"error": "bad_request", "reason": "pathHashSize is not 1, 2 or 3"}
    try:
        if len(path) % 2:
            raise ValueError
        raw = bytes.fromhex(path)
        if any(c not in "0123456789abcdefABCDEF" for c in path):
            raise ValueError
    except ValueError:
        return {"error": "bad_request", "reason": "path is not hex"}
    if len(raw) % hs:
        return {"error": "bad_request", "reason": "length is not a multiple of pathHashSize"}
    hops = len(raw) // hs
    if hops > 63 or len(raw) > 64:
        return {"error": "bad_request", "reason": "more than 63 hops or 64 bytes"}
    if hops == 0:
        return {"result": "zero_hop", "hops": 0, "pathLenByte": (hs - 1) << 6}
    return {"result": "direct", "hops": hops, "pathLenByte": ((hs - 1) << 6) | hops}


def since_ms(v):
    from datetime import datetime

    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        if v < 0:
            return None
        return v if v > 100_000_000_000 else v * 1000
    if isinstance(v, str):
        try:
            if "T" not in v and "t" not in v:
                return None
            dt = datetime.fromisoformat(v.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            return None
        import calendar

        utc = dt.utctimetuple()
        return calendar.timegm(utc) * 1000 + dt.microsecond // 1000
    return None


def validator_vectors():
    hashtags = [
        "#roadstr", "#a", "#a-1", "#0", "#-", "#nostr", "#" + "a" * 31,
        "roadstr", "#", "#Road", "#road str", "#road_str", "#road.str", "#" + "a" * 32,
        "##a", "#ä", "#roadstr ", " #roadstr", "",
    ]
    hashtag_cases = [{"name": h, "valid": hashtag_ok(h)} for h in hashtags]

    key_names = ["#roadstr", "#libretag", "#nostr", "#test", "#a", "#" + "z" * 31]
    keys = []
    for name in key_names:
        digest = hashlib.sha256(name.encode()).digest()
        keys.append({"name": name, "sha256Hex": digest.hex(), "keyHex": digest[:16].hex(), "keyBase64": b64(digest[:16])})

    regions = ["sk", "sk-ba", "eu", "0", "a" * 30, "", "!sk", "SK", "sk_ba", "sk ba", "a" * 31, "#sk", "sk-á"]
    region_cases = [{"name": r, "wellFormed": region_ok(r)} for r in regions]

    since_inputs = [
        "2026-10-26T12:00:00.000Z",
        "2026-10-26T12:00:00Z",
        "2026-10-26T14:00:00.000+02:00",
        "2026-10-26T12:00:00.123456Z",
        1_793_016_000,
        1_793_016_000_123,
        0,
        100_000_000_000,
        100_000_000_001,
        "2026-10-26T12:00:00",
        "2026-10-26",
        "yesterday",
        "",
        -1,
        1.5,
        True,
        None,
        ["2026-10-26T12:00:00Z"],
    ]
    since_cases = []
    for v in since_inputs:
        ms = since_ms(v)
        case = {"since": v}
        if ms is None:
            case["error"] = "bad_request"
        else:
            case["epochMs"] = ms
        since_cases.append(case)
    # Truncation, not rounding: microseconds fall to the millisecond below.
    assert since_cases[3]["epochMs"] == 1_793_016_000_123

    p63 = "".join(f"{i:02x}" for i in range(63))
    p64 = p63 + "40"
    p66 = p64 + "4142"
    path_inputs = [
        (None, None), ("", None), ("", 1), ("", 2), ("", 3), ("a1", None), ("a1b2c3", 1),
        ("A1B2C3", 1), ("a1b2c3", 2), ("a1b2c3", 3), ("a1b2c3d4", 2), ("a1b", 1), ("zz", 1),
        ("0x a1", 1), (p63, 1), (p64, 1), (p64, 2), (p63, 3), (p66, 3), ("a1", 0), ("a1", 4),
        ("a1", "1"), ("a1", 1.5), (123, 1), (["a1"], 1),
    ]
    path_cases = []
    for path, size in path_inputs:
        case = {"path": path}
        if size is not None:
            case["pathHashSize"] = size
        case.update(path_check(path, size))
        path_cases.append(case)

    def payload_case(n, why):
        return {"why": why, "bytes": n, "payload": b64(bytes(range(256))[:n] if n <= 256 else bytes(n))}

    payload_cases = []
    for n, why, expect in [
        (1, "smallest payload", "ok"),
        (163, "the recommended maxPayloadBytes", "ok"),
        (164, "one byte over 163", "payload_too_large"),
        (165, "MeshCore's radio-side limit, still over the API's 163", "payload_too_large"),
    ]:
        c = payload_case(n, why)
        c["expect"] = expect
        payload_cases.append(c)
    payload_cases += [
        {"why": "empty string", "payload": "", "expect": "bad_request"},
        {"why": "not base64", "payload": "***", "expect": "bad_request"},
        {"why": "base64url alphabet; clients MUST NOT send it, servers MAY accept it", "payload": "-_-_", "expect": "either"},
        {"why": "unpadded standard base64 of 1 byte; clients MUST NOT send it, servers MAY accept it", "payload": "AA", "expect": "either"},
        {"why": "payload is a number", "payload": 12, "expect": "bad_request"},
    ]

    data_type_cases = [
        {"dataType": 1, "expect": "ok"},
        {"dataType": 336, "expect": "ok"},
        {"dataType": 65535, "expect": "ok"},
        {"dataType": 0, "expect": "invalid_data_type"},
        {"dataType": -1, "expect": "invalid_data_type"},
        {"dataType": 65536, "expect": "invalid_data_type"},
        {"dataType": "336", "expect": "bad_request"},
        {"dataType": 336.5, "expect": "bad_request"},
        {"dataType": None, "expect": "bad_request"},
    ]

    emoji = "\U0001F600"
    text_cases = [
        {"why": "one character", "text": "a", "expect": "ok"},
        {"why": "2000 code points", "textRepeat": {"unit": "a", "count": 2000}, "expect": "ok"},
        {"why": "2001 code points", "textRepeat": {"unit": "a", "count": 2001}, "expect": "bad_request"},
        {
            "why": "2000 code points outside the BMP (4000 UTF-16 code units, 8000 UTF-8 bytes)",
            "textRepeat": {"unit": emoji, "count": 2000},
            "expect": "ok",
        },
        {"why": "empty", "text": "", "expect": "bad_request"},
        {"why": "not a string", "text": 5, "expect": "bad_request"},
    ]

    client_identity_cases = [
        {"name": "Roadbeacon", "version": "0.4.0", "expect": "ok"},
        {"name": "  Roadbeacon  ", "version": "", "expect": "ok", "storedName": "Roadbeacon"},
        {"name": "a" * 64, "version": "v" * 32, "expect": "ok"},
        {"name": "a" * 65, "version": "1", "expect": "bad_request"},
        {"name": "a", "version": "v" * 33, "expect": "bad_request"},
        {"name": "   ", "version": "1", "expect": "bad_request"},
        {"name": "", "version": "1", "expect": "bad_request"},
        {"name": "Road\nbeacon", "version": "1", "expect": "bad_request"},
        {"name": "Roadbeacon", "version": "1\u0007", "expect": "bad_request"},
        {"name": "Roadbeacon", "version": None, "expect": "bad_request"},
        {"name": emoji * 64, "version": "1", "expect": "ok", "note": "64 code points"},
    ]

    return {
        "description": "Validator vectors for MeshCore Local API protocol 1. 'error' and 'expect' values are API error codes; 'ok' means accepted.",
        "hashtagChannelNames": {
            "rule": "'#' followed by 1 to 31 characters from a-z, 0-9 and '-'",
            "cases": hashtag_cases,
        },
        "hashtagChannelKeys": {
            "rule": "key = first 16 bytes of SHA-256 over the UTF-8 name including the leading '#'",
            "cases": keys,
        },
        "regionNames": {
            "rule": "1 to 30 characters from a-z, 0-9 and '-'. A well-formed name that the server does not know is unknown_region; anything else is bad_request.",
            "cases": region_cases,
        },
        "since": {
            "rule": "RFC 3339 date-time with 'Z' or an offset, or a non-negative integer: epoch seconds, or epoch milliseconds when greater than 100000000000. Fractions below a millisecond are truncated.",
            "cases": since_cases,
        },
        "paths": {
            "rule": "hex, even length, upper or lower case; pathHashSize 1, 2 or 3 (default 1); length a multiple of pathHashSize; at most 63 hops and 64 bytes. Absent or null path: flood. Empty path: zero-hop. pathLenByte is the firmware's packed path_len: (pathHashSize - 1) << 6 | hops.",
            "cases": path_cases,
        },
        "payloads": {
            "rule": "standard base64 with padding (RFC 4648 section 4) of 1 to limits.maxPayloadBytes bytes; these cases assume maxPayloadBytes = 163. 'either' means ok or bad_request are both conformant.",
            "maxPayloadBytes": 163,
            "cases": payload_cases,
        },
        "dataTypes": {"rule": "integer 1 to 65535", "cases": data_type_cases},
        "texts": {"rule": "string of 1 to 2000 Unicode code points", "cases": text_cases},
        "clientIdentity": {
            "rule": "hello.client.name: 1 to 64 code points after trimming, no control characters; version: 0 to 32 code points, no control characters",
            "cases": client_identity_cases,
        },
    }


# --- regions --------------------------------------------------------------------


def haversine(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(a))


def region_vectors():
    catalogue = [
        {"name": "xx-city", "label": "Test City", "kind": "city", "lat": 48.70, "lon": 21.25, "radiusKm": 20},
        {"name": "xx-east", "label": "Test East", "kind": "city", "lat": 48.72, "lon": 21.45, "radiusKm": 20},
        {"name": "xx", "label": "Test Country", "kind": "country", "lat": 48.70, "lon": 19.70, "radiusKm": 300},
    ]
    points = [
        (48.70, 21.25, "centre of xx-city"),
        (48.71, 21.33, "inside both cities, nearer to xx-city"),
        (48.72, 21.40, "inside both cities, nearer to xx-east"),
        (48.70, 20.50, "outside both cities, inside the country"),
        (48.70, 24.50, "outside everything"),
        (0.0, 0.0, "far away"),
    ]
    cases = []
    for lat, lon, why in points:
        best = None
        for r in catalogue:
            dist = haversine(lat, lon, r["lat"], r["lon"])
            if dist <= r["radiusKm"] and (best is None or dist < best[1]):
                best = (r["name"], dist)
        cases.append(
            {
                "why": why,
                "lat": lat,
                "lon": lon,
                "region": best[0] if best else None,
                "distanceKm": round(best[1], 6) if best else None,
            }
        )
    errors = [
        {"params": {"lat": 91, "lon": 0}, "error": "coordinate_range"},
        {"params": {"lat": 0, "lon": -180.5}, "error": "coordinate_range"},
        {"params": {"lat": 90, "lon": 180}, "region": None},
        {"params": {"lat": "48.70", "lon": 21.25}, "error": "bad_request"},
        {"params": {"lon": 21.25}, "error": "bad_request"},
    ]
    return {
        "description": "regions.resolve vectors (SPEC.md section 8.3) on a synthetic catalogue. Distances use the haversine formula on a sphere of radius 6371 km; compare with a tolerance of 0.001 km.",
        "earthRadiusKm": 6371.0,
        "catalogue": catalogue,
        "cases": cases,
        "errors": errors,
    }


def main():
    _self_test()
    files = {
        "pairing.json": pairing_vectors(),
        "validators.json": validator_vectors(),
        "regions.json": region_vectors(),
    }
    for name, data in files.items():
        (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        print("wrote", OUT / name)


if __name__ == "__main__":
    main()
