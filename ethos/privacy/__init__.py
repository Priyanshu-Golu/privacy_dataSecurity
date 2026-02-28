"""
ethos.privacy — THE BOUNDARY FILE
===================================
Step 17: Package boundary. Exports public API only.
Everything inside _core/ is private and should NOT be imported directly.

PUBLIC API:
  PrivacyDataSecurity  — main gateway class (3 public methods)
  PrivacyConfig        — typed config builder
  ProtectResult        — returned by protect()
  BaseDetector         — base class for custom detector plugins
  BaseVaultBackend     — base class for custom storage backends
  VaultAccessError     — raised on any vault access denial
  ConfidentialDataError— raised on security policy violations

PRIVATE (do NOT import from outside this package):
  ethos.privacy._core.*   → import will raise AttributeError
"""

from ethos.privacy.privacy_data_security import PrivacyDataSecurity
from ethos.privacy.config.privacy_config import PrivacyConfig
from ethos.core.data_types import ProtectResult
from ethos.core.exceptions import VaultAccessError, ConfidentialDataError
from ethos.privacy._core.vault.backends.base_backend import BaseVaultBackend


# ── Stub for BaseDetector (extension point) ───────────────────────────────────

class BaseDetector:
    """
    Base class for custom confidential data detectors.

    Inherit this class to add a new type of confidential data detection
    that the framework doesn't natively support.

    Usage
    -----
    from ethos.privacy import BaseDetector
    from ethos.core.data_types import ScanResult, AlertLevel, DataFamily

    class EmployeeIDDetector(BaseDetector):
        type_name  = "EMPLOYEE_ID"
        family     = DataFamily.BUSINESS
        alert_level = AlertLevel.HIGH

        def detect(self, text: str) -> list[ScanResult]:
            # Your detection logic here
            ...

    Then register in config:
      scanner:
        custom_detectors:
          - "myapp.detectors.EmployeeIDDetector"
    """

    type_name:   str = "CUSTOM"
    family:      str = "BUSINESS"
    alert_level: str = "HIGH"

    def detect(self, text: str) -> list:
        """
        Scan text and return a list of ScanResult objects.
        Must be overridden by subclasses.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement detect(text) "
            "and return a list of ScanResult objects."
        )


# ── Public exports ────────────────────────────────────────────────────────────

__all__ = [
    "PrivacyDataSecurity",
    "PrivacyConfig",
    "ProtectResult",
    "BaseDetector",
    "BaseVaultBackend",
    "VaultAccessError",
    "ConfidentialDataError",
]
