"""
ethos.privacy._core.scanner.structure_engine
=============================================
Strategy D: Structured format detection.
Parses .env blocks, JSON fragments, YAML snippets, and code assignments
that are pasted into AI chat. For each parsed key=value pair,
delegates to pattern and entropy engines to classify the value.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import regex

from ethos.core.data_types import AlertLevel, DataFamily, ScanResult


# ── .env line format: KEY=value with no quotes needed ─────────────────────────
_ENV_LINE_RE = regex.compile(
    r"""(?m)^
        ([A-Z][A-Z0-9_]{1,60})   # environment variable name
        =                         # equals sign
        (.+?)                     # value (lazy)
        \s*$                      # to end of line
    """,
    flags=regex.VERBOSE,
)

# ── Inline JSON object (rough detection — find {...} blocks) ──────────────────
_JSON_BLOCK_RE = regex.compile(r"\{[^{}]{20,2000}\}")

# ── YAML-like  "key: value" lines ────────────────────────────────────────────
_YAML_LINE_RE = regex.compile(
    r"""(?m)^
        [ \t]*
        ([a-z_][a-z0-9_]{1,60})   # key
        :\s+                       # colon + whitespace
        ([^\n]{4,})                # value to end of line
        $
    """,
    flags=regex.VERBOSE | regex.IGNORECASE,
)

# ── Sensitive key word fragments (for filtering which pairs to analyse) ────────
_SENSITIVE_KEY_FRAG = regex.compile(
    r"(?:password|passwd|pwd|secret|key|token|auth|credential|"
    r"private|bearer|api|access|aadhaar|aadhar|pan|phone|email|"
    r"card|cvv|bank|account|ifsc|swift|db|database|redis|host|dsn)",
    flags=regex.IGNORECASE,
)


class StructureEngine:
    """
    Parses structured content (pasted .env files, JSON, YAML, code)
    and returns ScanResults for each sensitive key-value pair found.

    It does NOT re-implement full pattern matching; instead it simply
    checks whether a value *looks* sensitive via:
      1. Length and character diversity (proxy for entropy)
      2. Key name containing a sensitive word fragment
    Actual pattern/entropy classification is done by the universal scanner
    on the extracted values.
    """

    def __init__(self, enabled_families: Optional[List[str]] = None):
        self.enabled_families = enabled_families

    def scan(self, text: str) -> List[ScanResult]:
        """
        Scan text for structured secrets.

        Returns
        -------
        list[ScanResult]
            One ScanResult per sensitive key-value pair found.
        """
        results: List[ScanResult] = []
        seen: set[str] = set()

        results.extend(self._scan_env(text, seen))
        results.extend(self._scan_json(text, seen))
        results.extend(self._scan_yaml(text, seen))

        return results

    # ── .env parsing ──────────────────────────────────────────────────────────

    def _scan_env(self, text: str, seen: set) -> List[ScanResult]:
        results = []
        for match in _ENV_LINE_RE.finditer(text):
            key   = match.group(1).strip()
            value = match.group(2).strip().strip("\"'")

            if not value or len(value) < 3:
                continue
            if value in seen:
                continue

            if not _SENSITIVE_KEY_FRAG.search(key):
                continue

            seen.add(value)
            start = match.start(2)
            end   = match.end(2)
            results.append(_make_result(key, value, text, start, end, "STRUCTURE/.env"))

        return results

    # ── JSON parsing ──────────────────────────────────────────────────────────

    def _scan_json(self, text: str, seen: set) -> List[ScanResult]:
        results = []
        for block_match in _JSON_BLOCK_RE.finditer(text):
            block = block_match.group(0)
            try:
                data = json.loads(block)
                pairs = _flatten(data)
            except (json.JSONDecodeError, ValueError):
                # Not valid JSON — fall through without error
                continue

            offset = block_match.start()
            for key, value in pairs:
                if not isinstance(value, str) or len(value) < 3:
                    continue
                if str(value) in seen:
                    continue
                if not _SENSITIVE_KEY_FRAG.search(str(key)):
                    continue
                seen.add(str(value))
                # Position within the block
                val_pos = block.find(f'"{value}"')
                start   = offset + val_pos + 1 if val_pos != -1 else offset
                end     = start + len(str(value))
                results.append(_make_result(str(key), str(value), text, start, end, "STRUCTURE/JSON"))

        return results

    # ── YAML-like parsing ─────────────────────────────────────────────────────

    def _scan_yaml(self, text: str, seen: set) -> List[ScanResult]:
        results = []
        for match in _YAML_LINE_RE.finditer(text):
            key   = match.group(1).strip()
            value = match.group(2).strip().strip("\"'")

            if not value or len(value) < 3:
                continue
            if value in seen:
                continue
            if not _SENSITIVE_KEY_FRAG.search(key):
                continue

            seen.add(value)
            start = match.start(2)
            end   = match.end(2)
            results.append(_make_result(key, value, text, start, end, "STRUCTURE/YAML"))

        return results


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_result(
    key: str,
    value: str,
    text: str,
    start: int,
    end: int,
    strategy: str,
) -> ScanResult:
    """Build a ScanResult for a structured key=value finding."""
    snippet = text[max(0, start - 40): min(len(text), end + 40)]
    return ScanResult(
        value          = value,
        type           = "STRUCTURED_SECRET",
        family         = DataFamily.SECRETS,
        position       = (start, end),
        confidence     = 0.72,
        alert_level    = AlertLevel.CRITICAL,
        strategy       = strategy,
        field_name     = key,
        context_snippet= snippet.replace("\n", " "),
    )


def _flatten(
    data: Any,
    prefix: str = "",
) -> List[tuple[str, Any]]:
    """Recursively flatten a dict/list into (key, value) pairs."""
    pairs = []
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            pairs.extend(_flatten(v, full_key))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            pairs.extend(_flatten(v, f"{prefix}[{i}]"))
    else:
        pairs.append((prefix, data))
    return pairs
