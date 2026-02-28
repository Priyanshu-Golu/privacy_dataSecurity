"""
ethos.privacy._core.vault.access_control
=========================================
Step 8: Hard-coded access control rules for the vault.

ALLOWED   : OWNER (session owner), RESOLVER (internal token resolver)
DENIED    : AI, EXTERNAL, ANONYMOUS, OTHER_SESSION

All denial → immediate VaultAccessError.
These rules are NEVER configurable. Security is not a config option.
"""

from __future__ import annotations

from ethos.core.exceptions import VaultAccessError


# ── Caller identity constants ─────────────────────────────────────────────────
class Caller:
    OWNER      = "OWNER"       # Authenticated session owner
    RESOLVER   = "RESOLVER"    # Internal TokenResolver component
    AI         = "AI"          # Any AI / LLM system
    EXTERNAL   = "EXTERNAL"    # External API or service
    ANONYMOUS  = "ANONYMOUS"   # Unauthenticated / unknown caller
    OTHER      = "OTHER"       # Any other caller type


# ── Allowed callers ───────────────────────────────────────────────────────────
_ALLOWED_CALLERS = {Caller.OWNER, Caller.RESOLVER}


class AccessControl:
    """
    Enforces hard-coded vault access rules.

    Rules (HARD-CODED — not configurable):
      ✓ OWNER   + matching session_id   → ALLOWED
      ✓ RESOLVER + matching session_id  → ALLOWED
      ✗ AI                              → DENIED (always)
      ✗ EXTERNAL                        → DENIED (always)
      ✗ ANONYMOUS                       → DENIED (always)
      ✗ OTHER                           → DENIED (always)
      ✗ Any caller + session mismatch   → DENIED

    Note: the vault NEVER exposes get_all() or list_tokens().
    Retrieval is only by exact token + matching session_id.
    """

    @staticmethod
    def check(
        caller: str,
        request_session_id: str,
        token_session_id: str,
        token: str = "",
    ) -> None:
        """
        Validate access. Raises VaultAccessError if denied.

        Parameters
        ----------
        caller : str
            One of the Caller.* constants.
        request_session_id : str
            The session ID presented by the caller.
        token_session_id : str
            The session ID stored in the vault record for this token.
        token : str
            The token being accessed (for error messages only).

        Raises
        ------
        VaultAccessError
            With a descriptive message on any denial.
        """
        # Rule 1: Caller must be in the allowed set
        if caller not in _ALLOWED_CALLERS:
            raise VaultAccessError(
                f"Vault access DENIED: caller type '{caller}' is not permitted.",
                details={
                    "caller":      caller,
                    "token":       _mask_token(token),
                    "reason":      "caller_not_allowed",
                    "allowed":     list(_ALLOWED_CALLERS),
                },
            )

        # Rule 2: Session ID must match the token's session
        if request_session_id != token_session_id:
            raise VaultAccessError(
                "Vault access DENIED: session ID mismatch. "
                "A session cannot access tokens from another session.",
                details={
                    "caller":          caller,
                    "token":           _mask_token(token),
                    "reason":          "session_mismatch",
                    "expected_prefix": token_session_id[:8] + "...",
                },
            )

    @staticmethod
    def check_store(caller: str, session_id: str) -> None:
        """
        Validate that a caller is allowed to store to the vault.
        Only OWNER can store. Raises VaultAccessError if denied.
        """
        if caller != Caller.OWNER:
            raise VaultAccessError(
                f"Vault store DENIED: only the session OWNER may store values. "
                f"Got caller='{caller}'.",
                details={"caller": caller, "reason": "store_not_allowed"},
            )


def _mask_token(token: str) -> str:
    """Return a safe, partially masked token string for error messages."""
    if not token:
        return "<no token>"
    return token[:12] + "..." if len(token) > 12 else token
