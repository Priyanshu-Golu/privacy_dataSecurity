"""
ethos.privacy._core.vault.alert_engine
=======================================
Step 11: Alert engine.
Fires an alert whenever a CRITICAL-level type is vaulted.
Alerts are emitted:
  - Written to the audit log
  - Delivered to any registered on_alert callback
  - Rotation recommendation appended for API keys / DB urls

CRITICAL families: SECRETS, FINANCIAL
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from ethos.core.data_types import AlertLevel, DataFamily


# ── Types that trigger rotation recommendations ───────────────────────────────
_ROTATION_TYPES = {
    "OPENAI_KEY", "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN",
    "GOOGLE_API_KEY", "STRIPE_KEY", "SLACK_TOKEN", "TWILIO_KEY",
    "JWT_TOKEN", "BEARER_TOKEN", "OAUTH_TOKEN", "GENERIC_PASSWORD",
    "PRIVATE_RSA_KEY", "SSH_PRIVATE_KEY", "DB_CONNECTION_STRING",
    "REDIS_URL", "DOCKER_SECRET", "KUBERNETES_SECRET",
}

_CRITICAL_FAMILIES = {DataFamily.SECRETS, DataFamily.FINANCIAL}


class AlertEngine:
    """
    Checks whether a vaulted item requires a security alert.
    Fires synchronous callbacks for CRITICAL-level items.

    Usage
    -----
    alerts = AlertEngine(on_alert=my_callback)
    alert  = alerts.check(scan_result, token)

    Callback signature: callback(alert_dict: dict) -> None
    """

    def __init__(
        self,
        on_alert: Optional[Callable[[Dict[str, Any]], None]] = None,
        enabled: bool = True,
        critical_families: Optional[List[str]] = None,
        recommend_rotation: bool = True,
    ):
        self._on_alert          = on_alert
        self.enabled            = enabled
        self._critical_families = set(critical_families or _CRITICAL_FAMILIES)
        self._recommend_rotation = recommend_rotation
        self._fired_alerts: List[Dict[str, Any]] = []

    def check(
        self,
        data_type: str,
        family: str,
        alert_level: str,
        token: str,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate whether an alert should fire for the given item.
        If alert_level is CRITICAL or family is in critical_families → fires.

        Parameters
        ----------
        data_type   : Type label (e.g. "OPENAI_KEY").
        family      : Data family (e.g. "SECRETS").
        alert_level : The alert level from the ScanResult.
        token       : The token assigned in the vault.
        session_id  : The owning session.

        Returns
        -------
        dict or None
            The alert dict if fired, None otherwise.
        """
        if not self.enabled:
            return None

        is_critical = (
            alert_level == AlertLevel.CRITICAL
            or family in self._critical_families
        )
        if not is_critical:
            return None

        alert: Dict[str, Any] = {
            "timestamp":   datetime.utcnow().isoformat() + "Z",
            "type":        "SECURITY_ALERT",
            "severity":    "CRITICAL",
            "data_type":   data_type,
            "family":      family,
            "token":       token[:16] + "...",
            "session_id":  session_id[:12] + "...",
            "message":     (
                f"⚠ CRITICAL: {data_type} intercepted and vaulted. "
                f"This type should never appear in plaintext messages."
            ),
        }

        if self._recommend_rotation and data_type in _ROTATION_TYPES:
            alert["recommendation"] = (
                f"Rotate your {data_type.replace('_', ' ').title()} immediately. "
                f"Its presence in a chat message is a potential data exposure incident."
            )

        self._fired_alerts.append(alert)

        if self._on_alert:
            try:
                self._on_alert(alert)
            except Exception:
                # Never let a bad callback crash the vault
                pass

        return alert

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Return all alerts that have fired in this session."""
        return list(self._fired_alerts)

    def clear(self) -> None:
        self._fired_alerts.clear()
