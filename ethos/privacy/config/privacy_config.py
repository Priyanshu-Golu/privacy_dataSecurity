"""
ethos.privacy.config.privacy_config
====================================
Step 15: PrivacyConfig class.
Provides a typed, validated configuration object for PrivacyDataSecurity.
Can be initialized from:
  - A preset name string ("banking", "medical", etc.)
  - A YAML file path
  - A raw dict
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from ethos.core.config_loader import load_config
from ethos.privacy.config.validator import ConfigValidator


class PrivacyConfig:
    """
    Typed configuration for PrivacyDataSecurity.

    Usage
    -----
    # From preset
    cfg = PrivacyConfig("banking")

    # From dict
    cfg = PrivacyConfig({
        "scanner": {"families": ["PII", "SECRETS"], "sensitivity": "high"},
        "vault":   {"backend": "memory", "token_expiry_minutes": 30},
    })

    # From YAML file
    cfg = PrivacyConfig("/path/to/my_config.yaml")
    """

    def __init__(self, source: Union[str, Dict[str, Any], None] = None):
        raw = load_config(source) if source is not None else {}
        raw = ConfigValidator.validate(raw)
        self._raw = raw

        # ── Scanner config ─────────────────────────────────────────────────
        scanner_cfg = raw.get("scanner", {})
        self.families: List[str] = scanner_cfg.get(
            "families", ["PII", "SECRETS", "FINANCIAL", "INFRA", "BUSINESS"]
        )
        self.sensitivity: str = scanner_cfg.get("sensitivity", "medium")
        self.safe_fields: List[str] = scanner_cfg.get("safe_fields", [])

        entropy_cfg = scanner_cfg.get("entropy", {})
        self.entropy_enabled: bool          = entropy_cfg.get("enabled", True)
        self.entropy_threshold: float       = float(entropy_cfg.get("threshold", 3.5))
        self.entropy_min_length: int        = int(entropy_cfg.get("min_length", 16))
        self.entropy_max_length: int        = int(entropy_cfg.get("max_length", 512))
        self.entropy_require_context: bool  = entropy_cfg.get("require_context_word", True)

        self.custom_detectors: List[str] = scanner_cfg.get("custom_detectors", [])

        # ── Vault config ───────────────────────────────────────────────────
        vault_cfg = raw.get("vault", {})
        self.backend: str                   = vault_cfg.get("backend", "memory")
        self.backend_config: Dict[str, Any] = vault_cfg.get("backend_config", {})
        self.token_expiry_minutes: int      = int(vault_cfg.get("token_expiry_minutes", 60))
        self.encryption_enabled: bool       = vault_cfg.get("encryption", True)

        alerts_cfg = vault_cfg.get("alerts", {})
        self.alerts_enabled: bool           = alerts_cfg.get("enabled", True)
        self.critical_families: List[str]   = alerts_cfg.get(
            "critical_families", ["SECRETS", "FINANCIAL"]
        )
        self.on_critical: str              = alerts_cfg.get("on_critical", "log")
        self.recommend_rotation: bool      = alerts_cfg.get("recommend_rotation", True)

        # ── Resolver config ────────────────────────────────────────────────
        resolver_cfg = raw.get("resolver", {})
        self.strict_session: bool       = resolver_cfg.get("strict_session", True)
        self.leave_unresolved: bool     = resolver_cfg.get("leave_unresolved_tokens", True)

    def to_dict(self) -> Dict[str, Any]:
        """Return the raw config dict."""
        return dict(self._raw)

    def scanner_config(self) -> Dict[str, Any]:
        """Return scanner sub-config for UniversalScanner."""
        return {
            "families":    self.families,
            "sensitivity": self.sensitivity,
            "safe_fields": self.safe_fields,
            "entropy": {
                "enabled":              self.entropy_enabled,
                "threshold":            self.entropy_threshold,
                "min_length":           self.entropy_min_length,
                "max_length":           self.entropy_max_length,
                "require_context_word": self.entropy_require_context,
            },
        }

    def vault_config(self) -> Dict[str, Any]:
        """Return vault alert sub-config for AlertEngine."""
        return {
            "enabled":            self.alerts_enabled,
            "critical_families":  self.critical_families,
            "recommend_rotation": self.recommend_rotation,
        }

    def __repr__(self) -> str:
        return (
            f"PrivacyConfig(families={self.families}, "
            f"sensitivity={self.sensitivity!r}, "
            f"backend={self.backend!r})"
        )
