"""The client's P-256 identity key, the pairing signature, and pluggable storage for the key and
the replay cursors."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .errors import PairingError

PAIRING_PREFIX = "meshcore-local-api-pair-v1:"
LEGACY_PAIRING_PREFIX = "meshcore-open-pair-v1:"
PAIRING_PREFIXES = (PAIRING_PREFIX, LEGACY_PAIRING_PREFIX)
NONCE_SHAPE = re.compile(r"^[A-Za-z0-9_-]{16,128}={0,2}$")


def pairing_message(challenge: dict) -> str:
    """The exact string to sign for a `pairing.challenge`, or PairingError.

    The challenge's `message` must be one of the two pairing prefixes followed by this challenge's
    own `nonce`; anything else is refused, so a server cannot make the client sign arbitrary text.
    A challenge without `message` (older servers) gets the legacy string the protocol defines.
    """
    nonce = challenge.get("nonce")
    if not isinstance(nonce, str) or not NONCE_SHAPE.match(nonce):
        raise PairingError("malformed pairing nonce")
    message = challenge.get("message")
    if message is None:
        return LEGACY_PAIRING_PREFIX + nonce
    if isinstance(message, str) and message in (p + nonce for p in PAIRING_PREFIXES):
        return message
    raise PairingError("the challenge asks to sign something other than the pairing string")


def fingerprint(public_raw: bytes) -> str:
    """First 8 bytes of SHA-256(X||Y) as "AB12 CD34 5678 9ABC", what the user compares in the dialog."""
    h = hashlib.sha256(public_raw).digest()[:8].hex().upper()
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


class PairingKey:
    """A P-256 private key. `public_key_b64` is base64 of the raw 64-byte X||Y point."""

    def __init__(self, private_key):
        from cryptography.hazmat.primitives.asymmetric import ec

        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != "secp256r1":
            raise ValueError("the pairing key must be a P-256 private key")
        self._key = private_key
        nums = private_key.public_key().public_numbers()
        self.public_raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    @classmethod
    def generate(cls) -> "PairingKey":
        from cryptography.hazmat.primitives.asymmetric import ec

        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_der(cls, der: bytes) -> "PairingKey":
        """From PKCS#8 (or SEC1) DER."""
        from cryptography.hazmat.primitives import serialization

        return cls(serialization.load_der_private_key(der, None))

    def to_der(self) -> bytes:
        """PKCS#8 DER, unencrypted."""
        from cryptography.hazmat.primitives import serialization

        return self._key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_raw).decode()

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_raw)

    def sign(self, message: str) -> str:
        """SHA256withECDSA over the UTF-8 message, base64 of the DER signature."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        return base64.b64encode(self._key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))).decode()

    def sign_challenge(self, challenge: dict) -> str:
        """Checks the challenge (see `pairing_message`) and signs it."""
        return self.sign(pairing_message(challenge))


# ---------------------------------------------------------------------------------------------- storage

@dataclass
class Cursor:
    """Where a replay starts: the `receivedAt` of the last event handled and the ids of the events
    that share that timestamp (`since` is inclusive, so those come again and are skipped)."""
    received_at: str
    ids: list[str] = field(default_factory=list)


class KeyStore(Protocol):
    def load_key(self) -> bytes | None: ...
    def save_key(self, der: bytes) -> None: ...


class CursorStore(Protocol):
    def get_cursor(self, key: str) -> Cursor | None: ...
    def set_cursor(self, key: str, cursor: Cursor) -> None: ...
    def flush(self) -> None: ...


class MemoryStore:
    """Key and cursors in memory only (tests, short-lived tools)."""

    def __init__(self, der: bytes | None = None):
        self._der = der
        self._cursors: dict[str, Cursor] = {}

    def load_key(self) -> bytes | None:
        return self._der

    def save_key(self, der: bytes) -> None:
        self._der = der

    def get_cursor(self, key: str) -> Cursor | None:
        return self._cursors.get(key)

    def set_cursor(self, key: str, cursor: Cursor) -> None:
        self._cursors[key] = cursor

    def flush(self) -> None:
        pass


class JsonFileStore:
    """Key and cursors in one JSON file, mode 0600, written atomically:
    `{"private": "<base64 PKCS#8 DER>", "cursor": {"<key>": {"receivedAt": "...", "ids": [...]}}}`.

    A cursor stored as a bare `receivedAt` string is read as one with no ids. Cursor writes are
    batched: at most one write per `save_interval` seconds, plus `flush()` (the client flushes on
    every disconnect and on close). Other top-level fields in the file are kept.
    """

    def __init__(self, path: Path | str, save_interval: float = 10.0):
        self.path = Path(path).expanduser()
        self.save_interval = save_interval
        self._lock = threading.Lock()
        self._dirty = False
        self._saved_at = 0.0
        self.state: dict = json.loads(self.path.read_text()) if self.path.exists() else {}
        if not isinstance(self.state, dict):
            raise ValueError(f"{self.path} does not hold a JSON object")

    def _write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(self.state))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        self._dirty = False
        self._saved_at = time.monotonic()

    def load_key(self) -> bytes | None:
        v = self.state.get("private")
        return base64.b64decode(v) if isinstance(v, str) else None

    def save_key(self, der: bytes) -> None:
        with self._lock:
            self.state["private"] = base64.b64encode(der).decode()
            self._write()

    def get_cursor(self, key: str) -> Cursor | None:
        v = (self.state.get("cursor") or {}).get(key)
        if isinstance(v, str):
            return Cursor(v)
        if isinstance(v, dict) and isinstance(v.get("receivedAt"), str):
            ids = [i for i in v.get("ids") or [] if isinstance(i, str)]
            return Cursor(v["receivedAt"], ids)
        return None

    def set_cursor(self, key: str, cursor: Cursor) -> None:
        with self._lock:
            self.state.setdefault("cursor", {})[key] = {"receivedAt": cursor.received_at, "ids": list(cursor.ids)}
            self._dirty = True
            if time.monotonic() - self._saved_at >= self.save_interval:
                self._write()

    def flush(self) -> None:
        with self._lock:
            if self._dirty:
                self._write()


def load_or_create_key(store: KeyStore) -> PairingKey:
    """The stored key, or a new one saved to `store`."""
    der = store.load_key()
    if der is not None:
        return PairingKey.from_der(der)
    key = PairingKey.generate()
    store.save_key(key.to_der())
    return key
