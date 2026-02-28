"""Abstract backend interface."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseVaultBackend(ABC):
    """
    Abstract interface that all vault storage backends must implement.

    A backend is responsible for:
      - Storing encrypted vault entries
      - Retrieving them by token
      - Marking entries as revoked (soft delete)
      - Purging entries permanently (hard delete for GDPR)

    The backend stores ENCRYPTED data only.
    Encryption/decryption is handled by the caller (Vault).
    """

    @abstractmethod
    def store(self, token: str, entry: Dict[str, Any]) -> None:
        """
        Store an encrypted vault entry indexed by token.

        Parameters
        ----------
        token : str
            The token string (vault key).
        entry : dict
            Must contain at minimum:
              encrypted_value : bytes
              session_id      : str
              data_type       : str
              family          : str
              alert_level     : str
              created_at      : str  (ISO timestamp)
              expires_at      : str or None
              revoked         : bool
        """
        ...

    @abstractmethod
    def retrieve(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a vault entry by token.

        Returns
        -------
        dict or None
            The entry dict if found, None if no such token exists.
        """
        ...

    @abstractmethod
    def revoke(self, token: str) -> None:
        """
        Mark a token as revoked (soft delete).
        Future retrieve() calls for this token will return the entry
        but with revoked=True, allowing the caller to deny access.
        """
        ...

    @abstractmethod
    def purge(self, session_id: str) -> int:
        """
        Hard delete all entries for a session (GDPR erasure).

        Parameters
        ----------
        session_id : str
            The session whose entries should be permanently deleted.

        Returns
        -------
        int
            Number of entries deleted.
        """
        ...

    @abstractmethod
    def list_tokens_for_session(self, session_id: str) -> list[str]:
        """
        Return all token strings belonging to a session.
        Used only by revoke(session_id) in the vault.
        NOT exposed to external callers through the public API.
        """
        ...

    def close(self) -> None:
        """Optional: release any resources (connections, file handles)."""
        pass
