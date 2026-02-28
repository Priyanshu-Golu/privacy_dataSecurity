"""
ethos.privacy._core.vault.vault
================================
Step 12: The Secure Vault — main vault orchestrator.
Wires together token_engine, access_control, audit_log,
alert_engine, and the configured backend.

Public operations:
  store(real_value, data_type, family, alert_level, session_id) → token
  retrieve(token, session_id, caller)                            → real_value
  revoke(session_id)
  purge(session_id)
  get_audit_entries(session_id)                                  → list
  get_alerts()                                                   → list

The vault NEVER exposes get_all() or list_tokens() to external callers.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from ethos.core.exceptions import VaultAccessError, TokenExpiredError
from ethos.privacy._core.vault.token_engine import generate_token
from ethos.privacy._core.vault.access_control import AccessControl, Caller
from ethos.privacy._core.vault.audit_log import AuditLog
from ethos.privacy._core.vault.alert_engine import AlertEngine
from ethos.privacy._core.vault.backends.base_backend import BaseVaultBackend
from ethos.privacy._core.vault.backends.memory_backend import (
    MemoryBackend, encrypt_value, decrypt_value
)


class Vault:
    """
    Secure vault for storing and retrieving confidential values.

    Parameters
    ----------
    backend : BaseVaultBackend or None
        Storage backend. Defaults to MemoryBackend if None.
    token_expiry_minutes : int
        Token lifetime in minutes. 0 = never expire.
    alert_config : dict or None
        Alert engine config (enabled, critical_families, recommend_rotation).
    on_alert : callable or None
        Callback(alert_dict) fired when a CRITICAL item is vaulted.
    """

    def __init__(
        self,
        backend: Optional[BaseVaultBackend] = None,
        token_expiry_minutes: int = 60,
        alert_config: Optional[Dict[str, Any]] = None,
        on_alert: Optional[Callable] = None,
    ):
        self._backend      = backend or MemoryBackend()
        self._expiry_mins  = token_expiry_minutes
        self._audit        = AuditLog()

        alert_cfg = alert_config or {}
        self._alerts = AlertEngine(
            on_alert           = on_alert,
            enabled            = alert_cfg.get("enabled", True),
            critical_families  = alert_cfg.get("critical_families"),
            recommend_rotation = alert_cfg.get("recommend_rotation", True),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def store(
        self,
        real_value:  str,
        data_type:   str,
        family:      str,
        alert_level: str,
        session_id:  str,
    ) -> str:
        """
        Encrypt and store a confidential value. Return opaque token.

        Parameters
        ----------
        real_value  : The actual confidential string to vault.
        data_type   : e.g. "AADHAAR", "OPENAI_KEY"
        family      : e.g. "PII", "SECRETS"
        alert_level : "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
        session_id  : Session that owns this vault entry.

        Returns
        -------
        str
            Token in ⟨TKN_{TYPE}_{HEX}⟩ format.
        """
        token = generate_token(data_type)

        encrypted = encrypt_value(real_value, session_id)

        now    = datetime.now(timezone.utc)
        expiry = None
        if self._expiry_mins > 0:
            from datetime import timedelta
            expiry = (now + timedelta(minutes=self._expiry_mins)).isoformat()

        entry: Dict[str, Any] = {
            "encrypted_value": encrypted,
            "session_id":      session_id,
            "data_type":       data_type,
            "family":          family,
            "alert_level":     alert_level,
            "created_at":      now.isoformat(),
            "expires_at":      expiry,
            "revoked":         False,
        }
        self._backend.store(token, entry)

        self._audit.record(
            "store",
            token      = token,
            session_id = session_id,
            caller     = Caller.OWNER,
            result     = "success",
            data_type  = data_type,
            family     = family,
        )

        # Fire alert for CRITICAL types
        self._alerts.check(data_type, family, alert_level, token, session_id)

        return token

    def retrieve(
        self,
        token:      str,
        session_id: str,
        caller:     str = Caller.RESOLVER,
    ) -> str:
        """
        Retrieve and decrypt the real value for a token.

        Parameters
        ----------
        token      : The opaque token string.
        session_id : Must match the session that created the token.
        caller     : Should be Caller.OWNER or Caller.RESOLVER.

        Returns
        -------
        str
            The decrypted real value.

        Raises
        ------
        VaultAccessError
            If session mismatch, caller not allowed, or token not found.
        TokenExpiredError
            If the token has passed its expiry time.
        """
        entry = self._backend.retrieve(token)

        if entry is None:
            self._audit.record("retrieve", token=token, session_id=session_id,
                               caller=caller, result="not_found")
            raise VaultAccessError(
                f"Token not found in vault: {token[:16]}...",
                details={"token": token[:16], "reason": "not_found"},
            )

        token_session = entry["session_id"]

        # Access control check
        try:
            AccessControl.check(caller, session_id, token_session, token)
        except VaultAccessError:
            self._audit.record("retrieve", token=token, session_id=session_id,
                               caller=caller, result="denied")
            raise

        # Revocation check
        if entry.get("revoked"):
            self._audit.record("retrieve", token=token, session_id=session_id,
                               caller=caller, result="revoked")
            raise VaultAccessError(
                f"Token has been revoked: {token[:16]}...",
                details={"token": token[:16], "reason": "revoked"},
            )

        # Expiry check
        expiry = entry.get("expires_at")
        if expiry:
            exp_dt = datetime.fromisoformat(expiry)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                self._audit.record("retrieve", token=token, session_id=session_id,
                                   caller=caller, result="expired")
                raise TokenExpiredError(
                    f"Token expired: {token[:16]}...",
                    details={"token": token[:16], "reason": "expired"},
                )

        # Decrypt and return
        real_value = decrypt_value(entry["encrypted_value"], token_session)

        self._audit.record("retrieve", token=token, session_id=session_id,
                           caller=caller, result="success",
                           data_type=entry.get("data_type"))

        return real_value

    def revoke(self, session_id: str) -> int:
        """
        Soft-revoke all tokens for a session.
        Future retrieve() calls for these tokens will raise VaultAccessError.
        Data is NOT deleted — kept for audit trail.

        Returns
        -------
        int
            Number of tokens revoked.
        """
        tokens = self._backend.list_tokens_for_session(session_id)
        for t in tokens:
            self._backend.revoke(t)
        self._audit.record("revoke", session_id=session_id,
                           caller=Caller.OWNER, result="success",
                           count=len(tokens))
        return len(tokens)

    def purge(self, session_id: str) -> int:
        """
        PERMANENTLY delete all vault entries for a session (GDPR erasure).
        This is irreversible. Returns count of entries deleted.

        Returns
        -------
        int
            Number of entries hard-deleted.
        """
        count = self._backend.purge(session_id)
        self._audit.record("purge", session_id=session_id,
                           caller=Caller.OWNER, result="success",
                           count=count)
        return count

    # ── Audit access ──────────────────────────────────────────────────────────

    def get_audit_entries(
        self,
        session_id: Optional[str] = None,
        operation:  Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return audit log entries for a session."""
        return self._audit.get_entries(session_id=session_id, operation=operation)

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Return all security alerts fired in this vault instance."""
        return self._alerts.get_alerts()

    def __repr__(self) -> str:
        backend_name = type(self._backend).__name__
        return f"Vault(backend={backend_name}, expiry={self._expiry_mins}min)"
