"""
ethos.privacy._core.vault.token_engine
=======================================
Step 7: Token generation and validation.
Produces cryptographically random, opaque tokens that represent
real confidential values stored in the vault.

Token format: ⟨TKN_{TYPE}_{8-UPPERCASE-HEX}⟩
Examples:
  ⟨TKN_AADHAAR_A3F2B7C1⟩
  ⟨TKN_OPENAI_KEY_X9K2M3P7⟩
  ⟨TKN_DBCONN_F4R8Q2N5⟩
"""

from __future__ import annotations

import secrets
import regex
from typing import Optional


# ── Token pattern ─────────────────────────────────────────────────────────────
TOKEN_RE = regex.compile(
    r"⟨TKN_([A-Z][A-Z0-9_]*)_([A-F0-9]{8})⟩"
)

# Opening and closing delimiters
_OPEN  = "⟨"
_CLOSE = "⟩"
_PREFIX = "TKN"


def generate_token(type_name: str) -> str:
    """
    Generate a unique, cryptographically random token for a given type.

    Parameters
    ----------
    type_name : str
        The confidential data type (e.g. "AADHAAR", "OPENAI_KEY").
        Must contain only letters, digits, and underscores.
        Will be uppercased and truncated to 20 chars.

    Returns
    -------
    str
        A token string in ⟨TKN_{TYPE}_{8-HEX}⟩ format.

    Examples
    --------
    >>> generate_token("AADHAAR")
    '⟨TKN_AADHAAR_A3F2B7C1⟩'
    """
    # Sanitise: keep only safe characters, uppercase, max 20 chars
    safe_type = regex.sub(r"[^A-Za-z0-9_]", "_", type_name).upper()[:20]
    if not safe_type:
        safe_type = "UNKNOWN"

    # 4 random bytes → 8 uppercase hex characters
    rand_hex = secrets.token_hex(4).upper()

    return f"{_OPEN}{_PREFIX}_{safe_type}_{rand_hex}{_CLOSE}"


def validate_token(token: str) -> bool:
    """
    Return True if token matches the expected ⟨TKN_*⟩ format exactly.

    Parameters
    ----------
    token : str
        String to validate.
    """
    return bool(TOKEN_RE.fullmatch(token))


def parse_token(token: str) -> Optional[tuple[str, str]]:
    """
    Parse a token and return (type_name, random_hex) or None if invalid.

    Parameters
    ----------
    token : str
        Token string to parse.

    Returns
    -------
    tuple[str, str] or None
    """
    m = TOKEN_RE.fullmatch(token)
    if not m:
        return None
    return m.group(1), m.group(2)


def find_tokens(text: str) -> list[tuple[str, int, int]]:
    """
    Find all token strings within a larger text.

    Parameters
    ----------
    text : str
        Text to search for tokens.

    Returns
    -------
    list of (token_str, start, end)
    """
    return [(m.group(0), m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
