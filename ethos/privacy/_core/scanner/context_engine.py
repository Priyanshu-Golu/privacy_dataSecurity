"""
ethos.privacy._core.scanner.context_engine
==========================================
Strategy C: Context-based detection.
Boosts confidence of existing matches based on surrounding context
(field names, variable assignments, proximity keywords).

Also independently flags:
  1. key=value assignments where the key contains a sensitive keyword
  2. Natural language credential patterns:
       - "connect to prod-db:5432 using johndoe and P@ssw0rd123"
       - "login with user admin and password secret123"
       - "credentials: admin/s3cr3t"
"""

from __future__ import annotations

import regex
from typing import Dict, List, Optional, Tuple

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
    "otp", "one_time_password", "verification_code", "passcode",
    "auth_code", "security_code", "confirmation_code",
]

_FIELD_KEYWORD_RE = regex.compile(
    r"\b(" + "|".join(regex.escape(w) for w in SENSITIVE_FIELD_WORDS) + r")\b",
    flags=regex.IGNORECASE,
)

# ── Key=value assignment pattern ──────────────────────────────────────────────
# NOTE: Plain string (not VERBOSE) — parens inside char class break VERBOSE mode
_ASSIGNMENT_RE = regex.compile(
    r"(?P<key>[a-zA-Z_][a-zA-Z0-9_]{1,60})\s*(?:=|:=?|=>)\s*[\"'`]?(?P<value>[^\s\"'`\n,;)(]{4,})[\"'`]?"
)


# ── Natural Language Credential Patterns ──────────────────────────────────────
# These catch credentials written in plain English sentences, not key=value.
# Examples:
#   "Connect to prod-db:5432 using johndoe and P@ssw0rd123"
#   "login to mysql with user admin and password s3cr3t"
#   "credentials: admin/myp@ss"

# P1: "connect/ssh/login to <HOST[:PORT]> using <USER> and <PASS>"
_NL_CONN_USING_RE = regex.compile(
    r"(?:connect(?:ing)?|ssh|login|log\s*in)\s+to\s+"
    r"(?P<host>[a-zA-Z0-9.\-_]+(?::[0-9]{2,5})?)"
    r"\s+using\s+(?P<user>[^\s,;\"']{1,60})"
    r"\s+and\s+(?P<passwd>\S{4,})",
    flags=regex.IGNORECASE,
)

# P2: "with user/username <USER> [and] password/pass <PASS>"
_NL_WITH_USER_PASS_RE = regex.compile(
    r"with\s+(?:user(?:name)?)\s+(?P<user>[^\s,;\"']{1,60})"
    r"\s+(?:and\s+)?(?:password|pass|pwd)\s+(?P<passwd>\S{4,})",
    flags=regex.IGNORECASE,
)

# P3: "credentials: <USER>/<PASS>" or "creds: <USER>:<PASS>"
_NL_CRED_SLASH_RE = regex.compile(
    r"(?:credentials?|creds?|login)\s*[:\-]\s*"
    r"(?P<user>[^\s/:\"']{1,60})[/:](?P<passwd>[^\s,;\"'\"]{4,})",
    flags=regex.IGNORECASE,
)

# P4: bare <hostname:port> following connection verbs
# e.g. "connect to prod-db:5432", "access redis-master:6379"
_NL_HOST_PORT_RE = regex.compile(
    r"(?:connect(?:ing)?|reach|access|ssh|login|to)\s+"
    r"(?P<hostport>[a-zA-Z][a-zA-Z0-9.\-_]{2,50}:[0-9]{2,5})\b",
    flags=regex.IGNORECASE,
)

# P5: "using <USER> and <PASS>" — generic; only fires when PASS looks like password
_NL_USING_AND_RE = regex.compile(
    r"using\s+(?P<user>[^\s,;\"']{1,60})\s+and\s+(?P<passwd>[^\s,;\"']{4,})",
    flags=regex.IGNORECASE,
)


def _looks_like_password(s: str) -> bool:
    """True if the string has mixed complexity — likely a real password."""
    has_digit   = any(c.isdigit()        for c in s)
    has_upper   = any(c.isupper()        for c in s)
    has_lower   = any(c.islower()        for c in s)
    has_special = any(not c.isalnum()    for c in s)
    score = sum([has_digit, has_upper, has_lower, has_special])
    return score >= 2 and len(s) >= 4


class ContextEngine:
    """
    Enhances scan results using contextual signals.

    Three modes of operation:
    1. boost()          — raises confidence of existing ScanResults when a
                          sensitive keyword appears near the match position.
    2. scan()           — finds key=value assignments where the key is sensitive.
    3. scan_nl_creds()  — finds credentials in natural language sentences.
    """

    BOOST_AMOUNT = 0.12

    def boost(self, results: List[ScanResult], text: str) -> List[ScanResult]:
        """
        Raise the confidence of each ScanResult if a sensitive keyword
        appears within ±80 characters of the match position.
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
        Also calls scan_nl_creds() to catch natural language credentials.
        """
        results: List[ScanResult] = []

        for match in _ASSIGNMENT_RE.finditer(text):
            key   = match.group("key")
            value = match.group("value").strip(" \"'`")

            if not value or len(value) < 4:
                continue
            if not _FIELD_KEYWORD_RE.search(key):
                continue

            family, alert = _infer_family_from_key(key)
            if enabled_families and family not in enabled_families:
                continue

            start = match.start("value")
            end   = match.end("value")
            snippet = text[max(0, start - 40): min(len(text), end + 40)]

            results.append(ScanResult(
                value           = value,
                type            = _infer_type_from_key(key),
                family          = family,
                position        = (start, end),
                confidence      = 0.78,
                alert_level     = alert,
                strategy        = "CONTEXT",
                context_snippet = snippet.replace("\n", " "),
            ))

        # Also scan for natural language credential patterns
        results.extend(self.scan_nl_creds(text, enabled_families))

        return results

    def scan_nl_creds(
        self,
        text: str,
        enabled_families: List[str] = None,
    ) -> List[ScanResult]:
        """
        Detect credentials written in natural language sentences.

        Handles patterns like:
          - "connect to prod-db:5432 using johndoe and P@ssw0rd123"
          - "login with user admin and password s3cr3t"
          - "credentials: admin/mypass"

        Returns new ScanResults — caller handles deduplication.
        """
        results: List[ScanResult] = []

        def _emit(value: str, type_: str, family: str, alert: str,
                  start: int, end: int, confidence: float = 0.88) -> None:
            snippet = text[max(0, start - 40): min(len(text), end + 40)]
            results.append(ScanResult(
                value           = value,
                type            = type_,
                family          = family,
                position        = (start, end),
                confidence      = confidence,
                alert_level     = alert,
                strategy        = "CONTEXT-NL",
                context_snippet = snippet.replace("\n", " "),
            ))

        # P1: "connect to <host:port> using <user> and <pass>"
        for m in _NL_CONN_USING_RE.finditer(text):
            host   = m.group("host")
            user   = m.group("user")
            passwd = m.group("passwd")

            if not (enabled_families and DataFamily.INFRA not in enabled_families):
                _emit(host,   "DB_HOST_PORT",     DataFamily.INFRA,    AlertLevel.CRITICAL,
                      m.start("host"),   m.end("host"),   confidence=0.90)
            if not (enabled_families and DataFamily.SECRETS not in enabled_families):
                _emit(user,   "DB_USERNAME",       DataFamily.SECRETS,  AlertLevel.CRITICAL,
                      m.start("user"),   m.end("user"),   confidence=0.85)
                _emit(passwd, "DB_PASSWORD",        DataFamily.SECRETS,  AlertLevel.CRITICAL,
                      m.start("passwd"), m.end("passwd"), confidence=0.92)

        # P2: "with user <user> and password <pass>"
        for m in _NL_WITH_USER_PASS_RE.finditer(text):
            user   = m.group("user")
            passwd = m.group("passwd")
            if not (enabled_families and DataFamily.SECRETS not in enabled_families):
                _emit(user,   "DB_USERNAME",  DataFamily.SECRETS, AlertLevel.CRITICAL,
                      m.start("user"),   m.end("user"))
                _emit(passwd, "DB_PASSWORD",   DataFamily.SECRETS, AlertLevel.CRITICAL,
                      m.start("passwd"), m.end("passwd"))

        # P3: "credentials: <user>/<pass>"
        for m in _NL_CRED_SLASH_RE.finditer(text):
            user   = m.group("user")
            passwd = m.group("passwd")
            if not (enabled_families and DataFamily.SECRETS not in enabled_families):
                _emit(user,   "CREDENTIAL_USER", DataFamily.SECRETS, AlertLevel.CRITICAL,
                      m.start("user"),   m.end("user"))
                _emit(passwd, "CREDENTIAL_PASS", DataFamily.SECRETS, AlertLevel.CRITICAL,
                      m.start("passwd"), m.end("passwd"))

        # P4: bare <hostname:port> after connection verbs
        for m in _NL_HOST_PORT_RE.finditer(text):
            hp = m.group("hostport")
            if not (enabled_families and DataFamily.INFRA not in enabled_families):
                _emit(hp, "SERVICE_HOST_PORT", DataFamily.INFRA, AlertLevel.CRITICAL,
                      m.start("hostport"), m.end("hostport"), confidence=0.82)

        # P5: "using <user> and <pass>" — only when pass looks strong enough
        for m in _NL_USING_AND_RE.finditer(text):
            # Skip if P1 already matched nearby (same match start region)
            if any(abs(m.start() - r.position[0]) < 5
                   for r in results if r.position and r.strategy == "CONTEXT-NL"):
                continue
            user   = m.group("user")
            passwd = m.group("passwd")
            if _looks_like_password(passwd):
                if not (enabled_families and DataFamily.SECRETS not in enabled_families):
                    _emit(user,   "NL_USERNAME", DataFamily.SECRETS, AlertLevel.CRITICAL,
                          m.start("user"),   m.end("user"),   confidence=0.80)
                    _emit(passwd, "NL_PASSWORD", DataFamily.SECRETS, AlertLevel.CRITICAL,
                          m.start("passwd"), m.end("passwd"), confidence=0.88)

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
