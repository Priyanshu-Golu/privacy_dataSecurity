"""
ethos.privacy._core.vault.backends.redis_backend
=================================================
Production Redis backend stub.

IMPLEMENTATION GUIDE
---------------------
To implement this backend:
1. Install: pip install redis
2. Set config: vault: {backend: redis, backend_config: {url: "redis://..."}}
3. Each vault entry is stored as a Redis HASH with a TTL.
4. Use HSET token field1 val1 field2 val2 ...
5. EXPIRE token <ttl_seconds>
6. For revocation: HSET token revoked 1

Example production implementation sketch:
    import redis
    self._client = redis.from_url(url)
    self._client.hset(token, mapping=entry)
    self._client.expire(token, ttl_seconds)
"""

from __future__ import annotations
from ethos.privacy._core.vault.backends.base_backend import BaseVaultBackend


class RedisBackend(BaseVaultBackend):
    """
    Production-ready Redis vault backend (NOT YET IMPLEMENTED).
    Install `redis` package and follow the implementation guide above.
    """

    def __init__(self, url: str = "redis://localhost:6379/0", **kwargs):
        raise NotImplementedError(
            "RedisBackend is not yet implemented. "
            "Use MemoryBackend for development/testing. "
            "To implement: install redis-py, connect via redis.from_url(url), "
            "and store each entry as a HASH with TTL support."
        )

    def store(self, token, entry):         raise NotImplementedError
    def retrieve(self, token):             raise NotImplementedError
    def revoke(self, token):               raise NotImplementedError
    def purge(self, session_id):           raise NotImplementedError
    def list_tokens_for_session(self, s):  raise NotImplementedError
