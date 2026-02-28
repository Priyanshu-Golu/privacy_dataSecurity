"""
ethos.privacy._core.scanner.entropy_engine
==========================================
Strategy B: Shannon Entropy analysis.
Detects high-entropy strings that look like unknown API keys or secrets,
even when no pattern matches.

A string is flagged if:
  - Its length is within [min_length, max_length]
  - Its Shannon entropy (bits/char) exceeds the threshold
  - Either: a context word appears within ±100 chars, OR
            require_context_word is False
"""

from __future__ import annotations

import math
from typing import List, Optional

import regex

from ethos.core.data_types import AlertLevel, DataFamily, ScanResult


# ── Context keywords that suggest a string is a secret ───────────────────────
CONTEXT_WORDS = [
    "key", "token", "secret", "password", "auth", "credential",
    "private", "bearer", "api", "access", "passwd", "pwd",
    "apikey", "api_key", "auth_token", "authtoken", "secret_key",
]

_CONTEXT_PATTERN = regex.compile(
    r"\b(" + "|".join(regex.escape(w) for w in CONTEXT_WORDS) + r")\b",
    flags=regex.IGNORECASE,
)

# Matches candidates: strings of reasonable length composed of diverse chars
# (letters, digits, special chars — typical of encoded secrets)
_CANDIDATE_RE = regex.compile(
    r"[A-Za-z0-9+/=_\-\.]{16,512}"
)


class EntropyEngine:
    """
    Detects high-entropy, secret-like strings in text.

    Parameters
    ----------
    threshold : float
        Minimum Shannon entropy (bits/char) to flag a string.
        Default: 3.5 (typical API keys are 4.0+; English prose is ~3.0)
    min_length : int
        Minimum string length to consider. Default: 16.
    max_length : int
        Maximum string length to consider. Default: 512.
    require_context_word : bool
        If True (default), only flag strings with a nearby context word.
        If False, flag all high-entropy strings regardless of context.
    sensitivity : str
        Adjusts the threshold: 'low' adds 0.7, 'paranoid' subtracts 0.5.
    """

    def __init__(
        self,
        threshold: float = 3.5,
        min_length: int = 16,
        max_length: int = 512,
        require_context_word: bool = True,
        sensitivity: str = "medium",
    ):
        # Adjust threshold based on sensitivity
        adjustments = {"low": 0.7, "medium": 0.0, "high": -0.3, "paranoid": -0.5}
        self.threshold           = threshold + adjustments.get(sensitivity, 0.0)
        self.min_length          = min_length
        self.max_length          = max_length
        self.require_context_word = require_context_word

    def scan(self, text: str) -> List[ScanResult]:
        """
        Scan text for high-entropy token-like strings.

        Returns
        -------
        list[ScanResult]
            One entry per detected high-entropy string.
        """
        results: List[ScanResult] = []
        seen_values: set[str] = set()

        for match in _CANDIDATE_RE.finditer(text):
            value = match.group(0)
            if len(value) < self.min_length or len(value) > self.max_length:
                continue

            entropy = _shannon_entropy(value)
            if entropy < self.threshold:
                continue

            # Context word check
            if self.require_context_word:
                start, end = match.span()
                ctx_start  = max(0, start - 100)
                ctx_end    = min(len(text), end + 100)
                context    = text[ctx_start:ctx_end]
                if not _CONTEXT_PATTERN.search(context):
                    continue

            if value in seen_values:
                continue
            seen_values.add(value)

            # Confidence scales with entropy: 3.5 → 0.60, 5.0 → 0.85
            confidence = min(0.95, 0.45 + (entropy - 3.0) * 0.15)

            start, end = match.span()
            snippet    = text[max(0, start - 40): min(len(text), end + 40)]

            results.append(ScanResult(
                value          = value,
                type           = "UNKNOWN_SECRET",
                family         = DataFamily.SECRETS,
                position       = (start, end),
                confidence     = confidence,
                alert_level    = AlertLevel.CRITICAL,
                strategy       = "ENTROPY",
                context_snippet= snippet.replace("\n", " "),
            ))

        return results


# ── Shannon Entropy ───────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string in bits per character.

    H(X) = -Σ p(x) * log2(p(x))
    """
    if not s:
        return 0.0
    length = len(s)
    freq   = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freq.values())
