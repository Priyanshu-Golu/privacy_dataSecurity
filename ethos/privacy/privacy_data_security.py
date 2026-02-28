"""
ethos.privacy.privacy_data_security
=====================================
Step 16: PrivacyDataSecurity — the main module class.
Wires together the Universal Scanner, Secure Vault, and Token Resolver.

Public API (frozen — never add more public methods):
  protect(user_input)                           → ProtectResult
  restore(ai_response, session_id)              → str | dict
  audit(session_id)                             → list[AuditEntry]
  run(data_record)                              → ProcessedRecord  [framework]
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union

from ethos.core.base_module import BaseModule
from ethos.core.data_types import (
    AuditEntry, DataRecord, DataFamily, ProcessedRecord, ProtectResult, ScanResult
)
from ethos.core.exceptions import VaultAccessError
from ethos.privacy.config.privacy_config import PrivacyConfig
from ethos.privacy._core.scanner.universal_scanner import UniversalScanner
from ethos.privacy._core.vault.vault import Vault
from ethos.privacy._core.vault.backends.memory_backend import MemoryBackend
from ethos.privacy._core.resolver.token_resolver import TokenResolver


class PrivacyDataSecurity(BaseModule):
    """
    Universal Confidential Data Gateway — Layer 2 of EthosAI.

    Intercepts confidential data BEFORE it reaches the AI,
    stores it in an encrypted vault, replaces it with opaque tokens,
    and restores real values AFTER the AI responds.

    The AI never sees real values. Only the authorized session can restore.

    Usage
    -----
    # Simple (preset)
    pds = PrivacyDataSecurity(config="banking")

    # Advanced (dict)
    pds = PrivacyDataSecurity(config={
        "scanner": {"families": ["PII", "SECRETS"], "sensitivity": "high"},
        "vault":   {"token_expiry_minutes": 30},
    })

    result = pds.protect("My Aadhaar is 4512-8934-2301")
    print(result.safe_content)   # → "My Aadhaar is ⟨TKN_AADHAAR_...⟩"

    final = pds.restore(ai_response, result.session_id)
    print(final)                 # → AI response with real values restored

    log = pds.audit(result.session_id)
    """

    # ── Layer Manifest ────────────────────────────────────────────────────────
    layer_name    = "privacy"
    layer_version = "1.0.0"
    depends_on    = []
    provides_to   = ["fairness", "model", "transparency"]

    def __init__(
        self,
        config: Union[str, Dict[str, Any], PrivacyConfig, None] = None,
        on_alert: Optional[Callable] = None,
    ):
        """
        Parameters
        ----------
        config : str, dict, PrivacyConfig, or None
            str  → preset name ("banking", "medical", "developer", "legal")
                   or path to a YAML config file
            dict → raw config dict
            PrivacyConfig → already-built config object
            None → default config (all families, medium sensitivity)
        on_alert : callable or None
            Optional callback(alert_dict) fired when CRITICAL data is vaulted.
            Signature: def my_callback(alert: dict) -> None
        """
        super().__init__(config)

        # Resolve to PrivacyConfig
        if isinstance(config, PrivacyConfig):
            self._cfg = config
        else:
            self._cfg = PrivacyConfig(config)

        self._on_alert = on_alert

        # Lazy-init flag — components built on first use
        self._scanner:  Optional[UniversalScanner]  = None
        self._vault:    Optional[Vault]             = None
        self._resolver: Optional[TokenResolver]     = None

    def initialize(self) -> "PrivacyDataSecurity":
        """Build all internal components. Called automatically on first protect()."""
        cfg = self._cfg

        self._scanner = UniversalScanner(
            config={"scanner": cfg.scanner_config()}
        )

        self._vault = Vault(
            backend              = MemoryBackend(),
            token_expiry_minutes = cfg.token_expiry_minutes,
            alert_config         = cfg.vault_config(),
            on_alert             = self._on_alert,
        )

        self._resolver = TokenResolver(
            vault             = self._vault,
            strict_session    = cfg.strict_session,
            leave_unresolved  = cfg.leave_unresolved,
        )

        self._initialized = True
        return self

    # ── Public API ────────────────────────────────────────────────────────────

    def protect(self, user_input: Union[str, Dict[str, Any]]) -> ProtectResult:
        """
        Scan user_input for confidential data, vault each item,
        and return tokenized content that's safe to send to any AI.

        Parameters
        ----------
        user_input : str or dict
            The user's raw message or structured data.

        Returns
        -------
        ProtectResult
            .safe_content   → tokenized text/dict, safe for AI
            .session_id     → use this when calling restore()
            .items_vaulted  → how many confidential items were intercepted
            .audit_summary  → dict summary of what was found
            .alerts         → list of CRITICAL alerts fired
            .scan_results   → full ScanResult list
        """
        if not self._initialized:
            self.initialize()

        session_id = f"sess_{uuid.uuid4().hex[:8]}"

        # Step 1: Scan
        scan_results: List[ScanResult] = self._scanner.scan(user_input)

        if not scan_results:
            return ProtectResult(
                safe_content  = user_input,
                session_id    = session_id,
                items_vaulted = 0,
                audit_summary = {"families": {}, "total": 0},
                alerts        = [],
                scan_results  = [],
            )

        # Step 2: Vault each finding and build token map {real_value → token}
        # Using a dict to avoid vaulting the same value twice
        value_to_token: Dict[str, str] = {}

        for result in scan_results:
            real = result.value
            if real in value_to_token:
                continue  # already vaulted

            token = self._vault.store(
                real_value  = real,
                data_type   = result.type,
                family      = result.family,
                alert_level = result.alert_level,
                session_id  = session_id,
            )
            value_to_token[real] = token

        # Step 3: Replace real values with tokens in content
        safe_content = _substitute(user_input, value_to_token)

        # Step 4: Build audit summary
        families: Dict[str, int] = {}
        for r in scan_results:
            families[r.family] = families.get(r.family, 0) + 1

        audit_summary = {
            "total":        len(value_to_token),
            "families":     families,
            "types":        list({r.type for r in scan_results}),
            "session_id":   session_id,
            "timestamp":    datetime.utcnow().isoformat() + "Z",
        }

        alerts = self._vault.get_alerts()

        return ProtectResult(
            safe_content  = safe_content,
            session_id    = session_id,
            items_vaulted = len(value_to_token),
            audit_summary = audit_summary,
            alerts        = alerts,
            scan_results  = scan_results,
        )

    def restore(
        self,
        ai_response: Union[str, Dict[str, Any]],
        session_id: str,
    ) -> Union[str, Dict[str, Any]]:
        """
        Restore real values in the AI's response by replacing tokens.

        Parameters
        ----------
        ai_response : str or dict
            The AI's response (may contain ⟨TKN_*⟩ tokens).
        session_id : str
            Must be result.session_id from the matching protect() call.

        Returns
        -------
        str or dict
            The response with all resolvable tokens replaced by real values.

        Raises
        ------
        VaultAccessError
            If session_id does not match (wrong user, wrong session).
        """
        if not self._initialized:
            self.initialize()

        return self._resolver.resolve(ai_response, session_id)

    def audit(self, session_id: str) -> List[AuditEntry]:
        """
        Return an audit trail for a session.

        Parameters
        ----------
        session_id : str
            The session to audit.

        Returns
        -------
        list[AuditEntry]
            One entry per vault operation in the session.
        """
        if not self._initialized:
            self.initialize()

        raw_entries = self._vault.get_audit_entries(session_id=session_id)

        return [
            AuditEntry(
                type        = e.get("data_type", "UNKNOWN"),
                token       = e.get("token", ""),
                timestamp   = datetime.fromisoformat(
                    e.get("timestamp", datetime.utcnow().isoformat()).rstrip("Z")
                ),
                access_log  = [e],
                family      = e.get("family", ""),
                alert_level = "",
                session_id  = session_id,
            )
            for e in raw_entries
        ]

    # ── Framework integration ─────────────────────────────────────────────────

    def run(self, record: DataRecord) -> ProcessedRecord:
        """
        Framework pipeline entry point.
        Calls protect() on the DataRecord content.

        Parameters
        ----------
        record : DataRecord
            Input data record from the pipeline.

        Returns
        -------
        ProcessedRecord
        """
        result = self.protect(record.content)
        return ProcessedRecord(
            original       = record,
            safe_content   = result.safe_content,
            protect_result = result,
            metadata       = {
                "session_id":    result.session_id,
                "items_vaulted": result.items_vaulted,
                "alerts":        len(result.alerts),
            },
        )

    def revoke_session(self, session_id: str) -> int:
        """Revoke all tokens for a session (e.g., on user logout)."""
        if not self._initialized:
            self.initialize()
        return self._vault.revoke(session_id)

    def purge_session(self, session_id: str) -> int:
        """GDPR right-to-erasure — permanently delete all session data."""
        if not self._initialized:
            self.initialize()
        return self._vault.purge(session_id)


# ── Token substitution helper ─────────────────────────────────────────────────

def _substitute(
    content: Union[str, Dict[str, Any]],
    value_to_token: Dict[str, str],
) -> Union[str, Dict[str, Any]]:
    """
    Replace each real value with its token in content.
    For text: string replace (longest values first to avoid substring issues).
    For dict: recurse.
    """
    if isinstance(content, dict):
        return {k: _substitute(v, value_to_token) for k, v in content.items()}

    if not isinstance(content, str):
        return content

    result = content
    # Sort by length descending to prevent shorter values replacing substrings
    for real_value in sorted(value_to_token.keys(), key=len, reverse=True):
        token = value_to_token[real_value]
        result = result.replace(real_value, token)

    return result
