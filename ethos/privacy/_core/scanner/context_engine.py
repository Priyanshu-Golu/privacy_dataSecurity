"""
ethos.privacy._core.scanner.context_engine
==========================================
Strategy C: Context-based detection.
Boosts confidence of existing matches based on surrounding context
(field names, variable assignments, proximity keywords).
Also independently flags values in key=value assignments where the
key contains a sensitive keyword.
"""

from __future__ import annotations

import regex
from typing import Dict, List

from ethos.core.data_types import AlertLevel, DataFamily, ScanResult


# ── Sensitive field/variable name keywords ────────────────────────────────────
SENSITIVE_FIELD_WORDS = [
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth", "credential", "private_key", "privatekey",
    "access_key", "accesskey", "bearer", "oauth", "jwt",
    "aadhaar", "aadhar", "pan", "passport", "phone", "mobile",
    "email", "address", "dob", "birth", "ssn", "npi",
    "credit_card", "card_number", "cvv", "cvc", "bank",
    "account_number", "ifsc", "swift", "routing",
    "db_password", "database_url", "database_password",
    "redis_url", "connection_string", "dsn",
]

_FIELD_KEYWORD_RE = regex.compile(
    r"\b(" + "|".join(regex.escape(w) for w in SENSITIVE_FIELD_WORDS) + r")\b",
    flags=regex.IGNORECASE,
)

# Key=value assignment pattern: key = "value" or key: value
# NOTE: Plain string (not VERBOSE) to avoid parenthesis-in-charclass issue
# Character class [^\s"'`\n,;)(] intentionally excludes parens and brackets
_ASSIGNMENT_RE = regex.compile(
    r"(?P<key>[a-zA-Z_][a-zA-Z0-9_]{1,60})\s*(?:=|:=?|=>)\s*[\"'`]?(?P<value>[^\s\"'\`\n,;)(]{4,})[\"'`]?"
)


class ContextEngine:
    """
    Enhances scan results using contextual signals.

    Two modes of operation:
    1. boost()  — raises confidence of existing ScanResults when a
                  sensitive keyword appears near the match position.
    2. scan()   — independently scans for key=value assignments where
                  the key is sensitive, returning new ScanResults.
    """

    # Confidence boost applied when a context word confirms a match
    BOOST_AMOUNT = 0.12

    def boost(self, results: List[ScanResult], text: str) -> List[ScanResult]:
        """
        Raise the confidence of each ScanResult if a sensitive keyword
        appears within ±80 characters of the match position.

        Parameters
        ----------
        results : list[ScanResult]
            Results from other engines to boost.
        text : str
            The original scanned text.

        Returns
        -------
        list[ScanResult]
            The same list, with confidence values adjusted in place.
        """
        for r in results:
            if r.position is None:
                continue
            start, end = r.position
            ctx_start  = max(0, start - 80)
            ctx_end    = min(len(text), end + 80)
            context    = text[ctx_start:ctx_end]

            if _FIELD_KEYWORD_RE.search(context):
                r.confidence = min(1.0, r.confidence + self.BOOST_AMOUNT)
                r.strategy   = r.strategy + "+CONTEXT"

        return results

    def scan(
        self,
        text: str,
        enabled_families: List[str] = None,
    ) -> List[ScanResult]:
        """
        Find key=value assignments where the key contains a sensitive keyword.
        Returns new ScanResults for values that aren't already flagged by the
        pattern engine (caller is responsible for deduplication).

        Parameters
        ----------
        text : str
            The raw text to scan.
        enabled_families : list[str] or None
            If provided, only return results for these families.

        Returns
        -------
        list[ScanResult]
        """
        results: List[ScanResult] = []

        for match in _ASSIGNMENT_RE.finditer(text):
            key   = match.group("key")
            value = match.group("value").strip(" \"'`")

            if not value or len(value) < 4:
                continue

            # Check if key contains a sensitive word
            if not _FIELD_KEYWORD_RE.search(key):
                continue

            # Determine best-fit family and alert level from the key name
            family, alert = _infer_family_from_key(key)

            if enabled_families and family not in enabled_families:
                continue

            start = match.start("value")
            end   = match.end("value")
            snippet = text[max(0, start - 40): min(len(text), end + 40)]

            results.append(ScanResult(
                value          = value,
                type           = _infer_type_from_key(key),
                family         = family,
                position       = (start, end),
                confidence     = 0.78,
                alert_level    = alert,
                strategy       = "CONTEXT",
                context_snippet= snippet.replace("\n", " "),
            ))

        return results


# ── Key-based inference helpers ───────────────────────────────────────────────

def _infer_family_from_key(key: str) -> tuple:
    """Return (family, alert_level) based on field name keywords."""
    key_lower = key.lower()
    if any(w in key_lower for w in ("api", "token", "secret", "password", "credential", "bearer", "oauth", "jwt", "key")):
        return DataFamily.SECRETS, AlertLevel.CRITICAL
    if any(w in key_lower for w in ("card", "cvv", "bank", "account", "ifsc", "swift")):
        return DataFamily.FINANCIAL, AlertLevel.CRITICAL
    if any(w in key_lower for w in ("db", "database", "redis", "host", "dsn", "connection")):
        return DataFamily.INFRA, AlertLevel.CRITICAL
    if any(w in key_lower for w in ("aadhaar", "aadhar", "pan", "phone", "email", "address", "passport")):
        return DataFamily.PII, AlertLevel.HIGH
    return DataFamily.SECRETS, AlertLevel.HIGH


def _infer_type_from_key(key: str) -> str:
    """Return a best-guess type label from a field name."""
    key_lower = key.lower()
    mapping = {
        "password": "GENERIC_PASSWORD",
        "passwd":   "GENERIC_PASSWORD",
        "pwd":      "GENERIC_PASSWORD",
        "api_key":  "UNKNOWN_API_KEY",
        "apikey":   "UNKNOWN_API_KEY",
        "token":    "UNKNOWN_TOKEN",
        "secret":   "UNKNOWN_SECRET",
        "email":    "EMAIL",
        "phone":    "PHONE",
        "aadhaar":  "AADHAAR",
        "pan":      "PAN",
    }
    for fragment, label in mapping.items():
        if fragment in key_lower:
            return label
    return "SENSITIVE_FIELD_VALUE"
