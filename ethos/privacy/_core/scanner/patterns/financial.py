"""
ethos.privacy._core.scanner.patterns.financial
===============================================
Regex patterns and validators for Financial Data (Family 3).

Covers:
  CREDIT_CARD (with Luhn), CVV (context-aware), BANK_ACCOUNT,
  IFSC_CODE, UPI_PIN, UPI_ID, TRANSACTION_ID, SWIFT_CODE
"""

from __future__ import annotations

import regex
from typing import List, Tuple

from ethos.core.data_types import AlertLevel, DataFamily


FINANCIAL_PATTERNS: List[Tuple[str, regex.Pattern, float, str, bool]] = []


def _reg(pattern: str, flags=0) -> regex.Pattern:
    return regex.compile(pattern, flags)


# ── Credit Card ───────────────────────────────────────────────────────────────
# Visa, Mastercard, Amex, Discover — with optional spaces/dashes
CREDIT_CARD_RE = _reg(
    r"""
    (?<!\d)
    (
      4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}   # Visa 16
    | 5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4} # MC 16
    | 3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}               # Amex 15
    | 6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4} # Discover
    | [2-6][0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4} # Generic 16
    )
    (?!\d)
    """,
    flags=regex.VERBOSE,
)
FINANCIAL_PATTERNS.append(("CREDIT_CARD", CREDIT_CARD_RE, 0.70, AlertLevel.CRITICAL, True))


# ── CVV ───────────────────────────────────────────────────────────────────────
# Only flag CVV when near a credit card context
CVV_RE = _reg(
    r"""
    (?:cvv|cvc|csc|cvv2|cvc2|security.code)\s*[:=]?\s*(\b[0-9]{3,4}\b)
    """,
    flags=regex.VERBOSE | regex.IGNORECASE,
)
FINANCIAL_PATTERNS.append(("CVV", CVV_RE, 0.90, AlertLevel.CRITICAL, False))


# ── Bank Account Number (Indian) ──────────────────────────────────────────────
# 9–18 digit number near bank/account context
BANK_ACCOUNT_RE = _reg(
    r"""
    (?:account.?(?:number|no|num)|a\/c|bank.?acct)\s*[:=]?\s*
    (\b[0-9]{9,18}\b)
    """,
    flags=regex.VERBOSE | regex.IGNORECASE,
)
FINANCIAL_PATTERNS.append(("BANK_ACCOUNT", BANK_ACCOUNT_RE, 0.85, AlertLevel.CRITICAL, False))


# ── IFSC Code ────────────────────────────────────────────────────────────────
# Format: 4 letters + 0 + 6 alphanumeric. E.g. SBIN0001234
IFSC_RE = _reg(r"(?<![A-Z])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])")
FINANCIAL_PATTERNS.append(("IFSC_CODE", IFSC_RE, 0.85, AlertLevel.HIGH, False))


# ── UPI ID ────────────────────────────────────────────────────────────────────
# E.g. name@okaxis, mobile@paytm
UPI_ID_RE = _reg(r"([a-z0-9.\-_+]+@(?:okaxis|okicici|okhdfcbank|okicici|paytm|ybl|upi|ibl|axl|allbank|apl|barodampay|cnrb|cosb|dbs|dlb|ezeepay|fbl|federal|finobank|hdfcbank|icici|indus|iobnet|jkb|jsb|karb|kbl|kvb|lime|mahb|nsdl|obc|postbank|psb|purz|rbl|saraswat|sbi|scb|sib|tjsb|uco|unionbank|united|utib|vijb|yesbank))",
    flags=regex.IGNORECASE,
)
FINANCIAL_PATTERNS.append(("UPI_ID", UPI_ID_RE, 0.90, AlertLevel.CRITICAL, False))


# ── UPI PIN ───────────────────────────────────────────────────────────────────
UPI_PIN_RE = _reg(
    r"(?:upi.?pin|m.?pin)\s*[:=]?\s*(\b[0-9]{4,6}\b)",
    flags=regex.IGNORECASE,
)
FINANCIAL_PATTERNS.append(("UPI_PIN", UPI_PIN_RE, 0.90, AlertLevel.CRITICAL, False))


# ── Transaction ID ────────────────────────────────────────────────────────────
TXNID_RE = _reg(
    r"""
    (?:txn.?id|transaction.?id|ref.?no|reference.?number|payment.?id)
    \s*[:=]?\s*
    ([A-Z0-9]{8,32})
    """,
    flags=regex.VERBOSE | regex.IGNORECASE,
)
FINANCIAL_PATTERNS.append(("TRANSACTION_ID", TXNID_RE, 0.80, AlertLevel.HIGH, False))


# ── SWIFT/BIC Code ────────────────────────────────────────────────────────────
# Format: 8 or 11 alphanumeric chars with specific structure
SWIFT_RE = _reg(r"(?<![A-Z])([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)(?![A-Z0-9])")
FINANCIAL_PATTERNS.append(("SWIFT_CODE", SWIFT_RE, 0.70, AlertLevel.HIGH, False))


# ── Luhn Algorithm ────────────────────────────────────────────────────────────

def luhn_validate(number: str) -> bool:
    """
    Validate a credit card number string using the Luhn algorithm.
    Returns True if the number passes.
    """
    digits = [int(d) for d in regex.sub(r"[\s\-]", "", number) if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
