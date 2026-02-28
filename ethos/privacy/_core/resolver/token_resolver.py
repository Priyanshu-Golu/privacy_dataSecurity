"""
ethos.privacy._core.resolver.token_resolver
============================================
Step 14: The Token Resolver.
Scans AI responses for ⟨TKN_*⟩ tokens, looks up each in the vault,
and substitutes real values. Only the authorized session may resolve.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from ethos.core.exceptions import VaultAccessError
from ethos.privacy._core.resolver.pattern_matcher import find_tokens
from ethos.privacy._core.vault.access_control import Caller


class TokenResolver:
    """
    Resolves ⟨TKN_*⟩ tokens in AI responses back to real values.

    Session-bound: the session_id passed to resolve() must match the
    session_id that was used during the original protect() call.
    Any mismatch causes VaultAccessError.

    Parameters
    ----------
    vault : Vault
        The vault instance holding the encrypted values.
    strict_session : bool
        If True (default), mismatching sessions always raise.
        If False, a warning is logged but resolution is skipped.
    leave_unresolved : bool
        If True (default), tokens not found in the vault are left in place.
        If False, a VaultAccessError is raised for missing tokens.
    """

    def __init__(
        self,
        vault,                           # Vault — avoid circular import
        strict_session:   bool = True,
        leave_unresolved: bool = True,
    ):
        self._vault            = vault
        self._strict_session   = strict_session
        self._leave_unresolved = leave_unresolved
        self._resolved_log: List[Dict[str, str]] = []

    def resolve(
        self,
        content:    Union[str, Dict[str, Any]],
        session_id: str,
    ) -> Union[str, Dict[str, Any]]:
        """
        Replace all ⟨TKN_*⟩ tokens in content with their real values.

        Parameters
        ----------
        content    : str or dict
            The AI response (or any text/dict) containing tokens.
        session_id : str
            Must match the session that originally vaulted the data.

        Returns
        -------
        str or dict
            The content with all resolvable tokens replaced.

        Raises
        ------
        VaultAccessError
            If strict_session=True and a session mismatch occurs,
            or if leave_unresolved=False and a token is not found.
        """
        self._resolved_log.clear()

        if isinstance(content, dict):
            return self._resolve_dict(content, session_id)
        return self._resolve_text(str(content), session_id)

    # ── Text resolution ───────────────────────────────────────────────────────

    def _resolve_text(self, text: str, session_id: str) -> str:
        """Replace tokens in a text string."""
        token_matches = find_tokens(text)

        if not token_matches:
            return text

        # Work backwards to preserve positions
        result = text
        processed = set()

        for token_str, start, end in reversed(token_matches):
            if token_str in processed:
                continue
            processed.add(token_str)

            real_value = self._lookup(token_str, session_id)
            if real_value is None:
                # Leave token in place
                continue

            # Replace ALL occurrences of this token in the text
            result = result.replace(token_str, real_value)

        return result

    # ── Dict resolution ───────────────────────────────────────────────────────

    def _resolve_dict(
        self,
        data:       Dict[str, Any],
        session_id: str,
    ) -> Dict[str, Any]:
        """Recursively resolve tokens in all string values of a dict."""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self._resolve_text(value, session_id)
            elif isinstance(value, dict):
                result[key] = self._resolve_dict(value, session_id)
            elif isinstance(value, list):
                result[key] = [
                    self._resolve_text(v, session_id) if isinstance(v, str)
                    else v
                    for v in value
                ]
            else:
                result[key] = value
        return result

    # ── Vault lookup ──────────────────────────────────────────────────────────

    def _lookup(self, token_str: str, session_id: str) -> Optional[str]:
        """
        Look up a single token in the vault.
        Returns the real value, or None if unresolvable.
        Raises VaultAccessError if strict_session=True and access denied.
        """
        try:
            real_value = self._vault.retrieve(
                token      = token_str,
                session_id = session_id,
                caller     = Caller.RESOLVER,
            )
            self._resolved_log.append({
                "token":   token_str[:20] + "...",
                "result":  "resolved",
            })
            return real_value

        except VaultAccessError as e:
            self._resolved_log.append({
                "token":  token_str[:20] + "...",
                "result": "denied",
                "error":  str(e),
            })
            if self._strict_session:
                raise
            return None  # leave token as-is

        except Exception as e:
            self._resolved_log.append({
                "token":  token_str[:20] + "...",
                "result": "error",
                "error":  str(e),
            })
            if not self._leave_unresolved:
                raise VaultAccessError(
                    f"Failed to resolve token {token_str[:16]}...: {e}"
                )
            return None

    def get_resolution_log(self) -> List[Dict[str, str]]:
        """Return the log of token resolution outcomes from the last resolve() call."""
        return list(self._resolved_log)
