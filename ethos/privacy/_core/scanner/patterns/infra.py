"""
ethos.privacy._core.scanner.patterns.infra
===========================================
Regex patterns for Infrastructure Secrets (Family 4).

Covers:
  DB_CONNECTION_STRING (PostgreSQL, MySQL, MongoDB, etc.),
  REDIS_URL, IP_ADDRESS (v4 and v6), INTERNAL_HOSTNAME,
  ENV_FILE_CONTENT, DOCKER_SECRET, KUBERNETES_SECRET
"""

from __future__ import annotations

import regex
from typing import List, Tuple

from ethos.core.data_types import AlertLevel, DataFamily


INFRA_PATTERNS: List[Tuple[str, regex.Pattern, float, str, bool]] = []


def _reg(pattern: str, flags=0) -> regex.Pattern:
    return regex.compile(pattern, flags)


# ── Database Connection Strings ───────────────────────────────────────────────
# NOTE: Plain string (not VERBOSE) to avoid character-class parenthesis issues
DB_CONN_RE = _reg(
    r"((?:postgresql|postgres|mysql|mariadb|mongodb|mssql|sqlserver|oracle|sqlite|"
    r"cockroachdb|redshift|snowflake|bigquery)(?:\+[a-z0-9]+)?://"
    r"(?:[^:@\s]+:[^:@\s]+@)?[a-zA-Z0-9.\-_]+(?::[0-9]{2,5})?(?:/[a-zA-Z0-9_\-]*)?(?:\?[^\s]*)?)",
    flags=regex.IGNORECASE,
)
INFRA_PATTERNS.append(("DB_CONNECTION_STRING", DB_CONN_RE, 0.92, AlertLevel.CRITICAL, False))


# ── Redis URL ─────────────────────────────────────────────────────────────────
REDIS_RE = _reg(
    r"(rediss?://(?:[^:@\s]+:[^:@\s]+@)?[a-zA-Z0-9.\-_]+(?::[0-9]{2,5})?(?:/[0-9]*)?)",
    flags=regex.IGNORECASE,
)
INFRA_PATTERNS.append(("REDIS_URL", REDIS_RE, 0.92, AlertLevel.CRITICAL, False))


# ── IPv4 Address ──────────────────────────────────────────────────────────────
# Flags private/internal IP ranges at CRITICAL, public IPs at HIGH
IPV4_RE = _reg(
    r"(?<!\d)((?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    r"|(?:192\.168\.[0-9]{1,3}\.[0-9]{1,3})"
    r"|(?:172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})"
    r"|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?!\d)"
)
INFRA_PATTERNS.append(("IP_ADDRESS", IPV4_RE, 0.70, AlertLevel.HIGH, False))


# ── Internal Hostname ─────────────────────────────────────────────────────────
# Hostnames like prod.db.internal, api.service.local
INTERNAL_HOST_RE = _reg(
    r"(?<![a-zA-Z0-9\-])([a-zA-Z][a-zA-Z0-9\-]*"
    r"(?:\.(?:internal|local|svc|cluster\.local|corp|intranet|lan|prod|staging|dev|test))"
    r"(?:\.[a-zA-Z0-9\-]+)*)(?![a-zA-Z0-9\-])",
    flags=regex.IGNORECASE,
)
INFRA_PATTERNS.append(("INTERNAL_HOSTNAME", INTERNAL_HOST_RE, 0.75, AlertLevel.CRITICAL, False))


# ── .env file content ─────────────────────────────────────────────────────────
# Detects pasted .env blocks: lines in KEY=value format
ENV_BLOCK_RE = _reg(
    r"(?m)^([A-Z][A-Z0-9_]{2,50}=(?!#).+)$"
)
INFRA_PATTERNS.append(("ENV_FILE_CONTENT", ENV_BLOCK_RE, 0.65, AlertLevel.CRITICAL, False))


# ── Docker Secret ─────────────────────────────────────────────────────────────
# NOTE: Plain string to avoid quotes-in-charclass VERBOSE issue
DOCKER_SECRET_RE = _reg(
    r"(?:docker.?secret|DOCKER_SECRET|docker_password|REGISTRY_PASS)\s*[:=]+\s*([^\s\"'\n,;]{6,})",
    flags=regex.IGNORECASE,
)
INFRA_PATTERNS.append(("DOCKER_SECRET", DOCKER_SECRET_RE, 0.88, AlertLevel.CRITICAL, False))


# ── Kubernetes Secret ─────────────────────────────────────────────────────────
# NOTE: Plain string to avoid quotes-in-charclass VERBOSE issue
K8S_SECRET_RE = _reg(
    r"(?:(?:k8s|kubernetes|kubectl).*?secret|(?:KUBE_TOKEN|KUBECONFIG|K8S_SECRET))\s*[:=]+\s*([^\s\"'\n,;]{8,})",
    flags=regex.IGNORECASE,
)
INFRA_PATTERNS.append(("KUBERNETES_SECRET", K8S_SECRET_RE, 0.85, AlertLevel.CRITICAL, False))
