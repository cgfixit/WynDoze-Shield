"""Symmetric encryption for deferred / isolated-machine bundles.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from ``cryptography``. The key is a
URL-safe base64 32-byte value, supplied via the environment. We never generate
a key silently at rest — the caller must provide or explicitly mint one.

This protects scan bundles that must sit on disk (isolated machine, or failed
upload awaiting retry) so hostnames, process lists, and service inventories are
not left in cleartext on the endpoint.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class CryptoError(RuntimeError):
    """Raised on key or token errors."""


def generate_key() -> str:
    """Mint a new Fernet key (URL-safe base64, 32 bytes)."""
    return Fernet.generate_key().decode("ascii")


def _fernet(key: str) -> Fernet:
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as exc:
        msg = "invalid Fernet key (expected URL-safe base64, 32 bytes)"
        raise CryptoError(msg) from exc


def encrypt_bytes(data: bytes, key: str) -> bytes:
    """Encrypt ``data`` with ``key``."""
    return _fernet(key).encrypt(data)


def decrypt_bytes(token: bytes, key: str) -> bytes:
    """Decrypt ``token`` with ``key``. Raises :class:`CryptoError` if invalid."""
    try:
        return _fernet(key).decrypt(token)
    except InvalidToken as exc:
        msg = "could not decrypt bundle (wrong key or corrupted data)"
        raise CryptoError(msg) from exc


__all__ = ["CryptoError", "decrypt_bytes", "encrypt_bytes", "generate_key"]
