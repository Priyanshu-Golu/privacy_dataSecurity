"""
ethos.core.data_types
=====================
Core data structures used throughout the EthosAI framework.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ── Enums (as string constants for simplicity / no extra import) ──────────────

class AlertLevel:
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class DataFamily:
    PII       = "PII"
    SECRETS   = "SECRETS"
    FINANCIAL = "FINANCIAL"
    INFRA     = "INFRA"
    BUSINESS  = "BUSINESS"


# ── Scan Result ───────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    Represents a single confidential item detected by the scanner.

    Attributes:
        value       : The actual confidential string found.
        type        : Specific type label (e.g. AADHAAR, OPENAI_KEY).
        family      : Broad family (PII / SECRETS / FINANCIAL / INFRA / BUSINESS).
        position    : (start, end) character offsets in the original text.
                      None for dict-mode scans without a flat text position.
        confidence  : Detection confidence 0.0 – 1.0.
        alert_level : LOW / MEDIUM / HIGH / CRITICAL.
        strategy    : Which detection strategy found this (PATTERN / ENTROPY /
                      CONTEXT / STRUCTURE).
        field_name  : For dict inputs, the key under which the value was found.
        context_snippet : ±40 chars around the match, for audit display.
    """
    value:           str
    type:            str
    family:          str
    position:        Optional[Tuple[int, int]] = None
    confidence:      float = 1.0
    alert_level:     str   = AlertLevel.HIGH
    strategy:        str   = "PATTERN"
    field_name:      Optional[str] = None
    context_snippet: Optional[str] = None

    def __post_init__(self):
        # Clamp confidence to [0.0, 1.0]
        self.confidence = max(0.0, min(1.0, self.confidence))


# ── Protect Result ────────────────────────────────────────────────────────────

@dataclass
class ProtectResult:
    """
    Returned by PrivacyDataSecurity.protect().

    Attributes:
        safe_content   : The tokenized text or dict — safe to send to AI.
        session_id     : Unique session identifier for this protect call.
        items_vaulted  : Count of confidential items intercepted.
        audit_summary  : Human-readable summary of what was found / vaulted.
        alerts         : List of alert dicts for CRITICAL-level findings.
        scan_results   : Full list of ScanResult objects (for advanced use).
    """
    safe_content:  Any                   # str or dict
    session_id:    str
    items_vaulted: int                   = 0
    audit_summary: Dict[str, Any]        = field(default_factory=dict)
    alerts:        List[Dict[str, Any]]  = field(default_factory=list)
    scan_results:  List[ScanResult]      = field(default_factory=list)


# ── Audit Entry ───────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    """
    Represents one entry in the vault audit log.

    Attributes:
        type        : Confidential data type (AADHAAR, OPENAI_KEY, …).
        token       : The opaque token issued for this value.
        timestamp   : When this entry was created.
        access_log  : List of access events (who, when, operation).
        family      : Data family.
        alert_level : Severity.
        session_id  : Session that owns this entry.
    """
    type:        str
    token:       str
    timestamp:   datetime            = field(default_factory=datetime.utcnow)
    access_log:  List[Dict[str, Any]]= field(default_factory=list)
    family:      str                 = ""
    alert_level: str                 = AlertLevel.HIGH
    session_id:  str                 = ""


# ── Framework Integration Types ───────────────────────────────────────────────

@dataclass
class DataRecord:
    """
    Input type for framework pipeline integration.
    Wraps raw user input with metadata.
    """
    content:    Any                  = None   # str or dict
    session_id: str                  = field(default_factory=lambda: f"sess_{uuid.uuid4().hex[:8]}")
    metadata:   Dict[str, Any]       = field(default_factory=dict)
    timestamp:  datetime             = field(default_factory=datetime.utcnow)

    def __repr__(self) -> str:
        content_preview = str(self.content)[:60] if self.content else "None"
        return (
            f"DataRecord(session_id={self.session_id!r}, "
            f"content={content_preview!r}...)"
        )


@dataclass
class ProcessedRecord:
    """
    Output type for framework pipeline integration.
    Wraps the processed result with metadata.
    """
    original:       DataRecord
    safe_content:   Any                  = None
    protect_result: Optional[ProtectResult] = None
    errors:         List[str]            = field(default_factory=list)
    metadata:       Dict[str, Any]       = field(default_factory=dict)
    timestamp:      datetime             = field(default_factory=datetime.utcnow)
