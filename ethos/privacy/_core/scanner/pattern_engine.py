"""
ethos.privacy._core.scanner.pattern_engine
==========================================
Strategy A: Pattern-based detection engine.
Runs all regex patterns from the four pattern libraries.
Validates Aadhaar via Verhoeff and credit cards via Luhn.
Returns a list of ScanResult objects.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

import regex

from ethos.core.data_types import AlertLevel, DataFamily, ScanResult
from ethos.privacy._core.scanner.patterns.pii import PII_PATTERNS, validate_aadhaar
from ethos.privacy._core.scanner.patterns.secrets import SECRETS_PATTERNS
from ethos.privacy._core.scanner.patterns.financial import FINANCIAL_PATTERNS, luhn_validate
from ethos.privacy._core.scanner.patterns.infra import INFRA_PATTERNS


# ── Family mapping ────────────────────────────────────────────────────────────
_TYPE_TO_FAMILY: Dict[str, str] = {}
for _t, _re, _conf, _al, _ in PII_PATTERNS:
    _TYPE_TO_FAMILY[_t] = DataFamily.PII
for _t, _re, _conf, _al, _ in SECRETS_PATTERNS:
    _TYPE_TO_FAMILY[_t] = DataFamily.SECRETS
for _t, _re, _conf, _al, _ in FINANCIAL_PATTERNS:
    _TYPE_TO_FAMILY[_t] = DataFamily.FINANCIAL
for _t, _re, _conf, _al, _ in INFRA_PATTERNS:
    _TYPE_TO_FAMILY[_t] = DataFamily.INFRA


# ── Families requiring extra validators ──────────────────────────────────────
_VALIDATORS = {
    "AADHAAR":     validate_aadhaar,
    "CREDIT_CARD": luhn_validate,
}

# ── All patterns merged into one list ─────────────────────────────────────────
ALL_PATTERNS = PII_PATTERNS + SECRETS_PATTERNS + FINANCIAL_PATTERNS + INFRA_PATTERNS


# ── Sensitivity → confidence threshold mapping ────────────────────────────────
_SENSITIVITY_THRESHOLD = {
    "low":      0.85,
    "medium":   0.70,
    "high":     0.55,
    "paranoid": 0.40,
}


class PatternEngine:
    """
    Runs all regex patterns against a text string.
    Returns deduplicated ScanResult list ordered by position.

    Parameters
    ----------
    sensitivity : str
        One of 'low', 'medium', 'high', 'paranoid'.
        Controls which confidence scores are included.
    enabled_families : list[str] or None
        If provided, only patterns from these families are run.
    """

    def __init__(
        self,
        sensitivity: str = "medium",
        enabled_families: Optional[List[str]] = None,
    ):
        self.sensitivity       = sensitivity
        self.enabled_families  = enabled_families
        self._threshold        = _SENSITIVITY_THRESHOLD.get(sensitivity, 0.70)

    def scan(self, text: str) -> List[ScanResult]:
        """
        Scan text and return all pattern matches.

        Parameters
        ----------
        text : str
            The raw text to scan.

        Returns
        -------
        list[ScanResult]
            All matches passing the confidence threshold,
            deduplicated and sorted by position.
        """
        results: List[ScanResult] = []

        for type_name, pattern, base_conf, alert_level, has_validator in ALL_PATTERNS:
            # Family filter
            if self.enabled_families:
                family = _TYPE_TO_FAMILY.get(type_name, "")
                if family not in self.enabled_families:
                    continue

            # Confidence below threshold → skip
            if base_conf < self._threshold:
                continue

            try:
                for match in pattern.finditer(text):
                    # Use group 1 if defined (the captured value), else full match
                    value = match.group(1) if match.lastindex else match.group(0)
                    value = value.strip()

                    if not value:
                        continue

                    # Extra validation for known types (Aadhaar, credit card)
                    conf = base_conf
                    if has_validator and type_name in _VALIDATORS:
                        passed = _VALIDATORS[type_name](value)
                        if passed:
                            conf = min(1.0, base_conf + 0.15)
                        else:
                            # Validation failed → lower confidence significantly
                            conf = base_conf * 0.3
                            if conf < self._threshold:
                                continue

                    start, end = match.span(1) if match.lastindex else match.span()
                    snippet    = _context_snippet(text, start, end)
                    family     = _TYPE_TO_FAMILY.get(type_name, "")

                    results.append(ScanResult(
                        value          = value,
                        type           = type_name,
                        family         = family,
                        position       = (start, end),
                        confidence     = conf,
                        alert_level    = alert_level,
                        strategy       = "PATTERN",
                        context_snippet= snippet,
                    ))

            except regex.error:
                # Never crash on a bad pattern — skip and continue
                continue

        return _deduplicate(results)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _context_snippet(text: str, start: int, end: int, window: int = 40) -> str:
    """Return ±window chars around the match position."""
    snip_start = max(0, start - window)
    snip_end   = min(len(text), end + window)
    return text[snip_start:snip_end].replace("\n", " ").replace("\r", "")


def _deduplicate(results: List[ScanResult]) -> List[ScanResult]:
    """
    Remove overlapping or duplicate matches.
    When two matches overlap, keep the one with higher confidence.
    Sort final list by position.
    """
    # Sort by start position, then by descending confidence
    results.sort(key=lambda r: (r.position[0] if r.position else 0, -r.confidence))

    kept: List[ScanResult] = []
    last_end = -1

    for r in results:
        if r.position is None:
            kept.append(r)
            continue
        start, end = r.position
        if start >= last_end:
            kept.append(r)
            last_end = end
        # else: overlaps with previous — discard (lower confidence guaranteed by sort)

    return kept
