"""
ethos.privacy._core.scanner.patterns.secrets
=============================================
Regex patterns for Credentials and Secrets (Family 2).

Covers:
  OPENAI_KEY, AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN,
  GOOGLE_API_KEY, STRIPE_KEY, SLACK_TOKEN, TWILIO_KEY, JWT_TOKEN,
  PRIVATE_RSA_KEY, SSH_PRIVATE_KEY, SSL_CERTIFICATE,
  GENERIC_PASSWORD, BEARER_TOKEN, OAUTH_TOKEN
"""

from __future__ import annotations

import regex
from typing import List, Tuple

from ethos.core.data_types import AlertLevel, DataFamily


SECRETS_PATTERNS: List[Tuple[str, regex.Pattern, float, str, bool]] = []


def _reg(pattern: str, flags=0) -> regex.Pattern:
    return regex.compile(pattern, flags)


# ── OpenAI ────────────────────────────────────────────────────────────────────
OPENAI_RE = _reg(r"(sk-(?:proj-|)[A-Za-z0-9_\-]{20,})")
SECRETS_PATTERNS.append(("OPENAI_KEY", OPENAI_RE, 0.95, AlertLevel.CRITICAL, False))


# ── AWS Access Key ─────────────────────────────────────────────────────────────
# AWS access keys start with AKIA, AGPA, AIPA, ANPA, ANVA, ASIA
AWS_ACCESS_RE = _reg(r"(?<![A-Z0-9])((?:AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])")
SECRETS_PATTERNS.append(("AWS_ACCESS_KEY", AWS_ACCESS_RE, 0.95, AlertLevel.CRITICAL, False))


# ── AWS Secret Key ────────────────────────────────────────────────────────────
# 40-char base64-like string near aws_secret / aws_secret_access_key context
AWS_SECRET_RE = _reg(
    r"(?:aws.?secret.?(?:access.?)?key|AWS_SECRET_ACCESS_KEY)\s*[=:\"']+\s*([A-Za-z0-9+/]{40})",
    flags=regex.IGNORECASE,
)
SECRETS_PATTERNS.append(("AWS_SECRET_KEY", AWS_SECRET_RE, 0.92, AlertLevel.CRITICAL, False))


# ── GitHub Token ──────────────────────────────────────────────────────────────
GITHUB_RE = _reg(r"((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,})")
SECRETS_PATTERNS.append(("GITHUB_TOKEN", GITHUB_RE, 0.95, AlertLevel.CRITICAL, False))


# ── Google API Key ────────────────────────────────────────────────────────────
GOOGLE_KEY_RE = _reg(r"(AIza[A-Za-z0-9_\-]{35})")
SECRETS_PATTERNS.append(("GOOGLE_API_KEY", GOOGLE_KEY_RE, 0.95, AlertLevel.CRITICAL, False))


# ── Stripe Key ────────────────────────────────────────────────────────────────
STRIPE_RE = _reg(r"((?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,})")
SECRETS_PATTERNS.append(("STRIPE_KEY", STRIPE_RE, 0.95, AlertLevel.CRITICAL, False))


# ── Slack Token ───────────────────────────────────────────────────────────────
SLACK_RE = _reg(r"(xox[baprs]-[A-Za-z0-9\-]{10,})")
SECRETS_PATTERNS.append(("SLACK_TOKEN", SLACK_RE, 0.95, AlertLevel.CRITICAL, False))


# ── Twilio ────────────────────────────────────────────────────────────────────
TWILIO_RE = _reg(r"(SK[0-9a-f]{32}|AC[0-9a-f]{32})")
SECRETS_PATTERNS.append(("TWILIO_KEY", TWILIO_RE, 0.90, AlertLevel.CRITICAL, False))


# ── JWT Token ─────────────────────────────────────────────────────────────────
# Three base64url segments separated by dots
JWT_RE = _reg(r"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)")
SECRETS_PATTERNS.append(("JWT_TOKEN", JWT_RE, 0.90, AlertLevel.CRITICAL, False))


# ── RSA Private Key (PEM) ─────────────────────────────────────────────────────
RSA_KEY_RE = _reg(
    r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{64,}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"
)
SECRETS_PATTERNS.append(("PRIVATE_RSA_KEY", RSA_KEY_RE, 0.99, AlertLevel.CRITICAL, False))


# ── SSH Private Key ───────────────────────────────────────────────────────────
SSH_KEY_RE = _reg(
    r"(-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{64,}?-----END OPENSSH PRIVATE KEY-----)"
)
SECRETS_PATTERNS.append(("SSH_PRIVATE_KEY", SSH_KEY_RE, 0.99, AlertLevel.CRITICAL, False))


# ── SSL Certificate ───────────────────────────────────────────────────────────
CERT_RE = _reg(
    r"(-----BEGIN CERTIFICATE-----[\s\S]{64,}?-----END CERTIFICATE-----)"
)
SECRETS_PATTERNS.append(("SSL_CERTIFICATE", CERT_RE, 0.90, AlertLevel.CRITICAL, False))


# ── Bearer Token ─────────────────────────────────────────────────────────────
BEARER_RE = _reg(
    r"(?:Bearer|bearer)\s+([A-Za-z0-9_\-\.]{20,})",
    flags=regex.IGNORECASE,
)
SECRETS_PATTERNS.append(("BEARER_TOKEN", BEARER_RE, 0.85, AlertLevel.CRITICAL, False))


# ── OAuth Token ───────────────────────────────────────────────────────────────
OAUTH_RE = _reg(
    r"(?:access_token|oauth_token|refresh_token)\s*[=:\"']+\s*([A-Za-z0-9_\-\.]{16,})",
    flags=regex.IGNORECASE,
)
SECRETS_PATTERNS.append(("OAUTH_TOKEN", OAUTH_RE, 0.85, AlertLevel.CRITICAL, False))


# ── Generic Password (context-driven) ────────────────────────────────────────
# Only flags when near an explicit password keyword
# NOTE: Plain string (not VERBOSE) because quotes in char class cause VERBOSE parse error
GENERIC_PASS_RE = _reg(
    r"(?:password|passwd|pass|pwd|secret|credential)\s*[:=>\"`']+\s*(?![*\s])([^\s\"'\n,;]{6,})",
    flags=regex.IGNORECASE,
)
SECRETS_PATTERNS.append(("GENERIC_PASSWORD", GENERIC_PASS_RE, 0.85, AlertLevel.CRITICAL, False))
