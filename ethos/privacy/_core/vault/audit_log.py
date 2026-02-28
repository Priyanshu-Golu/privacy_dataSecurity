"""
ethos.privacy._core.vault.audit_log
====================================
Step 10: Append-only audit log for all vault operations.

Every store, retrieve, revoke, and purge is recorded with:
  timestamp, operation, token, session_id, caller, result
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


class AuditLog:
    """
    In-memory append-only audit log.
    Every vault operation is stored as a structured dict entry.

    Usage
    -----
    log = AuditLog()
    log.record("store", token="⟨TKN_AADHAAR_A3F2⟩", session_id="sess_abc",
                caller="OWNER", result="success", data_type="AADHAAR")
    entries = log.get_entries(session_id="sess_abc")
    """

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []

    def record(
        self,
        operation: str,
        token: str = "",
        session_id: str = "",
        caller: str = "",
        result: str = "success",
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Append one audit log entry.

        Parameters
        ----------
        operation  : "store" | "retrieve" | "revoke" | "purge" | "alert"
        token      : The token involved (may be empty for purge).
        session_id : Session that performed the operation.
        caller     : Caller identity (OWNER, RESOLVER, etc.).
        result     : "success" | "denied" | "expired" | "not_found"
        **kwargs   : Extra fields (data_type, family, alert_level, etc.)

        Returns
        -------
        dict
            The log entry that was recorded.
        """
        entry: Dict[str, Any] = {
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "operation":  operation,
            "token":      _mask_token(token),
            "session_id": _mask_session(session_id),
            "caller":     caller,
            "result":     result,
        }
        entry.update(kwargs)
        self._entries.append(entry)
        return entry

    def get_entries(
        self,
        session_id: Optional[str] = None,
        operation:  Optional[str] = None,
        result:     Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return audit log entries, optionally filtered.

        Parameters
        ----------
        session_id : Filter by (masked) session ID prefix.
        operation  : Filter by operation type.
        result     : Filter by result ("success", "denied", etc.)
        """
        entries = self._entries
        if session_id:
            masked = _mask_session(session_id)
            entries = [e for e in entries if e.get("session_id") == masked]
        if operation:
            entries = [e for e in entries if e.get("operation") == operation]
        if result:
            entries = [e for e in entries if e.get("result") == result]
        return list(entries)

    def count(self, session_id: Optional[str] = None) -> int:
        """Return total number of audit entries (optionally filtered by session)."""
        return len(self.get_entries(session_id=session_id))

    def clear(self) -> None:
        """Remove all audit entries (TEST USE ONLY)."""
        self._entries.clear()

    def __repr__(self) -> str:
        return f"AuditLog(entries={len(self._entries)})"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mask_token(token: str) -> str:
    """Mask middle of token for log safety."""
    return token[:16] + "..." if len(token) > 16 else token


def _mask_session(session_id: str) -> str:
    """Return first 12 chars + ellipsis."""
    return session_id[:12] + "..." if len(session_id) > 12 else session_id
