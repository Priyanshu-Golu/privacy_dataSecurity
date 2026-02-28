"""
ethos.privacy._core.vault.backends.memory_backend
==================================================
In-memory vault backend.
All entries stored in a Python dict. Data is lost on process restart.
Intended for development, demo, and testing only.

All stored values are AES-256-GCM encrypted.
Encryption key is derived from session_id + framework_secret via PBKDF2.
Even direct inspection of the dict cannot reveal real values.
"""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ethos.privacy._core.vault.backends.base_backend import BaseVaultBackend


# Framework-level secret (in production, load from env / HSM)
_FRAMEWORK_SECRET = os.environ.get(
    "ETHOS_VAULT_SECRET",
    "ethos-ai-framework-vault-secret-v1-changeme-in-production",
)


def _derive_key(session_id: str) -> bytes:
    """
    Derive a 32-byte AES-256 encryption key from session_id + framework secret.
    Uses PBKDF2-HMAC-SHA256 with 100 000 iterations.
    Key is deterministic for a given session_id — no key storage needed.
    """
    return hashlib.pbkdf2_hmac(
        hash_name   = "sha256",
        password    = _FRAMEWORK_SECRET.encode(),
        salt        = session_id.encode(),
        iterations  = 100_000,
        dklen       = 32,
    )


def encrypt_value(plaintext: str, session_id: str) -> bytes:
    """
    Encrypt a plaintext string with AES-256-GCM.
    Returns: nonce (12 bytes) + ciphertext bytes, base64-encoded.
    """
    key    = _derive_key(session_id)
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)
    ct     = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct)


def decrypt_value(encrypted_b64: bytes, session_id: str) -> str:
    """
    Decrypt a value previously encrypted with encrypt_value().
    Returns the original plaintext string.

    Raises
    ------
    ValueError
        If decryption fails (wrong session key or tampered data).
    """
    key    = _derive_key(session_id)
    aesgcm = AESGCM(key)
    raw    = base64.b64decode(encrypted_b64)
    nonce, ct = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


class MemoryBackend(BaseVaultBackend):
    """
    Dict-based in-memory vault backend with AES-256-GCM encryption.

    Thread-safety: not thread-safe by default (demo/testing only).
    For concurrent use, wrap in a threading.Lock.
    """

    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}

    def store(self, token: str, entry: Dict[str, Any]) -> None:
        """Store entry. Raises ValueError if token already exists."""
        if token in self._store:
            # Idempotent: same token, same session → no-op
            existing = self._store[token]
            if existing.get("session_id") == entry.get("session_id"):
                return
            raise ValueError(f"Token collision: {token!r} already exists.")
        self._store[token] = entry

    def retrieve(self, token: str) -> Optional[Dict[str, Any]]:
        """Return the entry dict for the token, or None if absent."""
        return self._store.get(token)

    def revoke(self, token: str) -> None:
        """Mark a specific token as revoked."""
        if token in self._store:
            self._store[token]["revoked"] = True

    def purge(self, session_id: str) -> int:
        """Hard-delete all entries for the session. Returns count deleted."""
        tokens_to_delete = [
            t for t, e in self._store.items()
            if e.get("session_id") == session_id
        ]
        for t in tokens_to_delete:
            del self._store[t]
        return len(tokens_to_delete)

    def list_tokens_for_session(self, session_id: str) -> List[str]:
        """Return all token strings belonging to a session."""
        return [
            t for t, e in self._store.items()
            if e.get("session_id") == session_id
        ]

    def __len__(self) -> int:
        return len(self._store)

    def __repr__(self) -> str:
        return f"MemoryBackend(entries={len(self._store)})"
