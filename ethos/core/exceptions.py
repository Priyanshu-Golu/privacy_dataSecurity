"""
ethos.core.exceptions
=====================
All custom exceptions for the EthosAI framework.
"""


class EthosBaseError(Exception):
    """Base class for all EthosAI exceptions."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in self.details.items())
            return f"{self.message} [{detail_str}]"
        return self.message


class VaultAccessError(EthosBaseError):
    """
    Raised when vault access is denied.

    Causes:
      - Session ID mismatch (token belongs to a different session)
      - Token has expired
      - Caller is not authorized (AI, external API, anonymous, etc.)
      - Token does not exist in vault
    """
    pass


class TokenExpiredError(VaultAccessError):
    """Raised specifically when a vault token has passed its expiry time."""
    pass


class ConfidentialDataError(EthosBaseError):
    """
    Raised when confidential data is detected in an unexpected location
    or when a security policy is violated.

    Example: trying to log raw confidential data, or passing real PII
    to an AI system without going through protect() first.
    """
    pass


class ConfigError(EthosBaseError):
    """
    Raised when a configuration is invalid, missing required fields,
    or contains unsupported values.
    """
    pass


class ScannerError(EthosBaseError):
    """Raised when the scanner encounters an unrecoverable processing error."""
    pass


class ResolverError(EthosBaseError):
    """Raised when the token resolver cannot process a response."""
    pass


class BackendError(EthosBaseError):
    """Raised when the vault storage backend encounters an error."""
    pass
