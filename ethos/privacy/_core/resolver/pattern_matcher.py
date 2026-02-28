"""
ethos.privacy._core.resolver.pattern_matcher
=============================================
Step 13: Pattern matcher for the Token Resolver.
Finds all ⟨TKN_*⟩ tokens in any text string.
"""

from __future__ import annotations

from typing import List, Tuple

import regex


# ── Token scan pattern ────────────────────────────────────────────────────────
# Must match EXACTLY the format produced by token_engine.generate_token()
# ⟨TKN_{TYPE}_{8-UPPERCASE-HEX}⟩
TOKEN_SCAN_RE = regex.compile(
    r"⟨TKN_([A-Z][A-Z0-9_]*)_([A-F0-9]{8})⟩"
)


def find_tokens(text: str) -> List[Tuple[str, int, int]]:
    """
    Find all ⟨TKN_*⟩ tokens in the given text.

    Parameters
    ----------
    text : str
        The text to scan (AI response, etc.)

    Returns
    -------
    list of (token_str, start, end)
        Each tuple contains:
          - token_str : the full token string including delimiters
          - start     : start character index in text
          - end       : end character index in text
    """
    return [
        (m.group(0), m.start(), m.end())
        for m in TOKEN_SCAN_RE.finditer(text)
    ]


def count_tokens(text: str) -> int:
    """Return the number of tokens found in text."""
    return len(find_tokens(text))


def extract_unique_tokens(text: str) -> List[str]:
    """Return a list of unique token strings found in text (preserving order)."""
    seen   = set()
    result = []
    for token_str, _, _ in find_tokens(text):
        if token_str not in seen:
            seen.add(token_str)
            result.append(token_str)
    return result
