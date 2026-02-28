"""
ethos.privacy.config.validator
================================
Config validation. Raises ConfigError with descriptive messages
when required fields are missing or have unsupported values.
"""

from __future__ import annotations

from typing import Any, Dict

from ethos.core.exceptions import ConfigError


_VALID_FAMILIES     = {"PII", "SECRETS", "FINANCIAL", "INFRA", "BUSINESS"}
_VALID_SENSITIVITY  = {"low", "medium", "high", "paranoid"}
_VALID_BACKENDS     = {"memory", "redis", "encrypted_db"}
_VALID_ON_CRITICAL  = {"log", "notify", "block"}


class ConfigValidator:
    """
    Validates a privacy config dict.
    All fields are optional (defaults are applied in PrivacyConfig).
    Raises ConfigError for invalid enum values or type mismatches.
    """

    @staticmethod
    def validate(config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate the config dict. Returns the same dict if valid.
        Raises ConfigError if any value is invalid.
        """
        if not isinstance(config, dict):
            raise ConfigError(
                f"Config must be a dict, got {type(config).__name__}",
                details={"type": type(config).__name__},
            )

        scanner = config.get("scanner", {})
        vault   = config.get("vault", {})
        resolver = config.get("resolver", {})

        # ── Scanner validation ─────────────────────────────────────────────
        if "families" in scanner:
            families = scanner["families"]
            if not isinstance(families, list):
                raise ConfigError(
                    "scanner.families must be a list",
                    details={"got": type(families).__name__},
                )
            bad = set(families) - _VALID_FAMILIES
            if bad:
                raise ConfigError(
                    f"Unknown family/families in scanner.families: {bad}",
                    details={"valid": sorted(_VALID_FAMILIES)},
                )

        if "sensitivity" in scanner:
            s = scanner["sensitivity"]
            if s not in _VALID_SENSITIVITY:
                raise ConfigError(
                    f"Invalid scanner.sensitivity: {s!r}",
                    details={"valid": sorted(_VALID_SENSITIVITY)},
                )

        if "entropy" in scanner:
            e = scanner["entropy"]
            if not isinstance(e, dict):
                raise ConfigError("scanner.entropy must be a dict")
            if "threshold" in e:
                t = e["threshold"]
                if not isinstance(t, (int, float)) or t <= 0:
                    raise ConfigError(
                        f"scanner.entropy.threshold must be a positive number, got {t!r}"
                    )

        # ── Vault validation ───────────────────────────────────────────────
        if "backend" in vault:
            b = vault["backend"]
            if b not in _VALID_BACKENDS:
                raise ConfigError(
                    f"Invalid vault.backend: {b!r}",
                    details={"valid": sorted(_VALID_BACKENDS)},
                )

        if "token_expiry_minutes" in vault:
            exp = vault["token_expiry_minutes"]
            if not isinstance(exp, int) or exp < 0:
                raise ConfigError(
                    f"vault.token_expiry_minutes must be a non-negative int, got {exp!r}"
                )

        if "alerts" in vault:
            alerts = vault["alerts"]
            if not isinstance(alerts, dict):
                raise ConfigError("vault.alerts must be a dict")
            if "on_critical" in alerts:
                oc = alerts["on_critical"]
                if oc not in _VALID_ON_CRITICAL:
                    raise ConfigError(
                        f"Invalid vault.alerts.on_critical: {oc!r}",
                        details={"valid": sorted(_VALID_ON_CRITICAL)},
                    )

        # ── Resolver validation ────────────────────────────────────────────
        if "strict_session" in resolver:
            if not isinstance(resolver["strict_session"], bool):
                raise ConfigError("resolver.strict_session must be a bool")

        return config
