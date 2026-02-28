"""
ethos.privacy._core.vault.backends.encrypted_db
================================================
Enterprise encrypted SQL backend stub.

IMPLEMENTATION GUIDE
---------------------
To implement this backend:
1. Install: pip install sqlalchemy cryptography
2. Set config: vault: {backend: encrypted_db, backend_config: {url: "postgresql://..."}}
3. Create a table: vault_entries(token, encrypted_value, session_id, data_type,
   family, alert_level, created_at, expires_at, revoked)
4. Store encrypted_value as BYTEA / BLOB.
5. Add indexes on session_id for fast revoke/purge queries.
6. Full SQL audit trail is automatic via database transaction logs.
"""

from __future__ import annotations
from ethos.privacy._core.vault.backends.base_backend import BaseVaultBackend


class EncryptedDBBackend(BaseVaultBackend):
    """
    Enterprise AES-256 encrypted SQL vault backend (NOT YET IMPLEMENTED).
    Follow the implementation guide above.
    """

    def __init__(self, url: str, **kwargs):
        raise NotImplementedError(
            "EncryptedDBBackend is not yet implemented. "
            "Use MemoryBackend for development/testing. "
            "To implement: use SQLAlchemy with a table storing encrypted BLOBs. "
            "Index on session_id. Keep full SQL audit trail."
        )

    def store(self, token, entry):         raise NotImplementedError
    def retrieve(self, token):             raise NotImplementedError
    def revoke(self, token):               raise NotImplementedError
    def purge(self, session_id):           raise NotImplementedError
    def list_tokens_for_session(self, s):  raise NotImplementedError
