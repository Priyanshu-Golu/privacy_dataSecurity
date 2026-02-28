"""
ethos.privacy._core.scanner.patterns.pii
=========================================
Regex patterns and validation routines for Personal Identity (PII) data.

Covers:
  AADHAAR, PAN, PASSPORT, PHONE (Indian + international), EMAIL, DOB,
  FULL_NAME (heuristic), ADDRESS (heuristic)
"""

from __future__ import annotations

import regex
from typing import List, Tuple

from ethos.core.data_types import AlertLevel, DataFamily


# ── Pattern Registry ──────────────────────────────────────────────────────────
# Each entry: (TYPE_NAME, compiled_regex, base_confidence, alert_level, has_validator)

PII_PATTERNS: List[Tuple[str, regex.Pattern, float, str, bool]] = []


def _reg(pattern: str, flags=regex.IGNORECASE) -> regex.Pattern:
    return regex.compile(pattern, flags)


# ── Aadhaar ───────────────────────────────────────────────────────────────────
# 12-digit number, optionally grouped as XXXX-XXXX-XXXX or XXXX XXXX XXXX
AADHAAR_RE = _reg(r"(?<![0-9])([2-9][0-9]{3})[\s\-]?([0-9]{4})[\s\-]?([0-9]{4})(?![0-9])")
PII_PATTERNS.append(("AADHAAR", AADHAAR_RE, 0.75, AlertLevel.HIGH, True))


# ── PAN (Permanent Account Number — India) ────────────────────────────────────
# Format: 5 letters, 4 digits, 1 letter. E.g. ABCDE1234F
PAN_RE = _reg(r"(?<![A-Z])([A-Z]{5}[0-9]{4}[A-Z])(?![A-Z0-9])")
PII_PATTERNS.append(("PAN", PAN_RE, 0.85, AlertLevel.HIGH, False))


# ── Passport (Indian) ─────────────────────────────────────────────────────────
# Format: One letter + 7 digits. E.g. A1234567
PASSPORT_RE = _reg(r"(?<![A-Z0-9])([A-Z][0-9]{7})(?![A-Z0-9])")
PII_PATTERNS.append(("PASSPORT", PASSPORT_RE, 0.6, AlertLevel.HIGH, False))


# ── Phone ─────────────────────────────────────────────────────────────────────
# Indian mobile (+91 / 91 prefix + 10 digits starting with 6-9)
# Or international E.164 (up to 15 digits)
PHONE_IN_RE   = _reg(r"(?:(?:\+|00)91[\s\-]?)?(?<!\d)([6-9][0-9]{9})(?!\d)")
PHONE_INTL_RE = _reg(r"(?<!\d)(\+[1-9][0-9]{7,14})(?!\d)")
PII_PATTERNS.append(("PHONE", PHONE_IN_RE,   0.80, AlertLevel.HIGH, False))
PII_PATTERNS.append(("PHONE", PHONE_INTL_RE, 0.75, AlertLevel.HIGH, False))


# ── Email ─────────────────────────────────────────────────────────────────────
EMAIL_RE = _reg(r"([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})", flags=regex.IGNORECASE)
PII_PATTERNS.append(("EMAIL", EMAIL_RE, 0.90, AlertLevel.HIGH, False))


# ── Date of Birth ─────────────────────────────────────────────────────────────
# Common formats near DOB keywords
DOB_RE = _reg(
    r"(?:dob|date.of.birth|born|birthdate|birth.date)\s*[:=\-]?\s*"
    r"(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})",
    flags=regex.IGNORECASE,
)
PII_PATTERNS.append(("DOB", DOB_RE, 0.90, AlertLevel.HIGH, False))


# ── OTP / Verification Code ────────────────────────────────────────────────────
# 4–8 digit numeric code beside an OTP/verification keyword.
# Context-driven: "OTP is 123456", "verification code: 482910", "passcode 7834"
OTP_RE = _reg(
    r"(?:otp|one.?time.?(?:password|passcode|code)|verification.?code|"
    r"passcode|auth(?:entication)?.?code|security.?code|confirm(?:ation)?.?code)"
    r"\s*(?:is|[:=\-])?\s*(\b[0-9]{4,8}\b)",
    flags=regex.IGNORECASE,
)
PII_PATTERNS.append(("OTP", OTP_RE, 0.95, AlertLevel.CRITICAL, False))




# ── Full Name (heuristic: Title Case 2-4 words, triggered by name keywords) ──
# This is pattern-based; not a true NER but works for clear contexts.
FULL_NAME_RE = _reg(
    r"(?:name|customer|patient|user|client|account.holder|beneficiary)"
    r"\s*[:=]?\s*([A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20}){1,3})(?=[^a-z]|$)"
)
PII_PATTERNS.append(("FULL_NAME", FULL_NAME_RE, 0.70, AlertLevel.HIGH, False))


# ── Address (heuristic: street number + known address words) ─────────────────
ADDRESS_RE = _reg(
    r"(?:address|addr|street|flat|apartment|apt|house|block|sector|nagar|"
    r"colony|area|pincode|pin|zip)\s*[:=]?\s*(.{10,120})"
    r"(?=\n|\r|$|,\s*(?:city|state|country|district|pin))",
    flags=regex.IGNORECASE,
)
PII_PATTERNS.append(("ADDRESS", ADDRESS_RE, 0.65, AlertLevel.HIGH, False))


# ── Verhoeff Checksum ─────────────────────────────────────────────────────────
# Used to validate Aadhaar numbers

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_validate(number: str) -> bool:
    """
    Validate a number string using the Verhoeff algorithm.
    Returns True if the number passes the Verhoeff checksum.
    Used to validate Aadhaar numbers.
    """
    digits = [int(d) for d in regex.sub(r"\D", "", number)]
    if len(digits) != 12:
        return False
    c = 0
    for i, digit in enumerate(reversed(digits)):
        p = _VERHOEFF_P[i % 8][digit]
        c = _VERHOEFF_D[c][p]
    return c == 0


def validate_aadhaar(number: str) -> bool:
    """Validate an Aadhaar number (12 digits, passes Verhoeff checksum)."""
    return verhoeff_validate(number)
