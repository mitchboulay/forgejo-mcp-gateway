"""Keys derived from SECRET_KEY: one for hashing stored secrets, one for encrypting Forgejo tokens.

Nothing secret is stored in the clear. Bearer tokens, refresh tokens, codes and
browser secrets are stored as HMAC-SHA256 under a derived key, so a copy of the
database cannot be replayed. Forgejo tokens must be recoverable, so they are
sealed with AES-256-GCM under a second derived key, bound to the connection row
they belong to.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MIN_SECRET_BYTES = 32
_NONCE_BYTES = 12
_VERSION = b"\x01"


class InvalidSecretKey(ValueError):
    """SECRET_KEY is not base64 or hex, or decodes to fewer than 32 bytes."""


def decode_secret_key(raw: str) -> bytes:
    """Decode SECRET_KEY, accepting hex or (url-safe) base64."""
    text = raw.strip()
    candidates: list[bytes] = []
    with contextlib.suppress(ValueError):
        candidates.append(bytes.fromhex(text))
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidates.append(decoder(text + "=" * (-len(text) % 4)))
        except (binascii.Error, ValueError):
            continue
    for key in candidates:
        if len(key) >= MIN_SECRET_BYTES:
            return key
    raise InvalidSecretKey(f"SECRET_KEY must decode (hex or base64) to at least {MIN_SECRET_BYTES} bytes")


def _derive(master: bytes, purpose: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"forgejo-mcp-gateway/" + purpose).derive(master)


class Keyring:
    """The derived keys. Construct once at startup."""

    def __init__(self, master: bytes) -> None:
        if len(master) < MIN_SECRET_BYTES:
            raise InvalidSecretKey(f"secret key must be at least {MIN_SECRET_BYTES} bytes")
        self._hash_key = _derive(master, b"hash")
        self._aead = AESGCM(_derive(master, b"seal"))

    def digest(self, value: str) -> str:
        """A keyed, non-reversible fingerprint of a secret, for lookup by equality."""
        return hmac.new(self._hash_key, value.encode(), hashlib.sha256).hexdigest()

    def seal(self, plaintext: str, *, bound_to: str) -> bytes:
        nonce = secrets.token_bytes(_NONCE_BYTES)
        return _VERSION + nonce + self._aead.encrypt(nonce, plaintext.encode(), bound_to.encode())

    def open(self, sealed: bytes, *, bound_to: str) -> str:
        if not sealed.startswith(_VERSION):
            raise ValueError("unknown sealed-value version")
        nonce = sealed[1 : 1 + _NONCE_BYTES]
        return self._aead.decrypt(nonce, sealed[1 + _NONCE_BYTES :], bound_to.encode()).decode()


def fingerprint(value: str) -> str:
    """An unkeyed SHA-256 of a secret, for in-memory cache keys only. Never stored."""
    return hashlib.sha256(value.encode()).hexdigest()


def new_secret(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(32)
