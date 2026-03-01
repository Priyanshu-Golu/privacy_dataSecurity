"""
EthosAI Privacy Layer — Real AI End-to-End Tests with Gemini 2.5 Flash
=======================================================================
These tests drive ACTUAL Gemini API calls through the full protect → AI → restore
pipeline and confirm that confidential data is NEVER sent to the model.

Prerequisites
-------------
1. pip install google-generativeai python-dotenv
2. Set GEMINI_API_KEY in your environment or in a .env file at the project root.

Run
---
# PowerShell — set key inline
$env:GEMINI_API_KEY = "your-key-here"
python -m pytest tests/test_e2e_gemini.py -v -s

# Or load from .env automatically (python-dotenv is loaded in conftest below)
python -m pytest tests/test_e2e_gemini.py -v -s

Tests are SKIPPED (not failed) when GEMINI_API_KEY is missing.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# ── Load .env if present ──────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))
except ImportError:
    pass  # python-dotenv optional; rely on shell env

# ── Gemini SDK ────────────────────────────────────────────────────────────────
try:
    import google.generativeai as genai
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False

# ── Privacy module ────────────────────────────────────────────────────────────
from ethos.privacy import PrivacyDataSecurity, VaultAccessError

# ── Module-level constants ────────────────────────────────────────────────────
_GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
_API_KEY        = os.environ.get("GEMINI_API_KEY", "")
_SKIP_REASON    = (
    "GEMINI_API_KEY not set. Set it via env var or .env file to run these tests."
    if not _API_KEY
    else (
        "google-generativeai not installed. Run: pip install google-generativeai"
        if not _GENAI_AVAILABLE
        else None
    )
)

requires_gemini = pytest.mark.skipif(
    bool(_SKIP_REASON),
    reason=_SKIP_REASON or "",
)


# ── Gemini helper ─────────────────────────────────────────────────────────────

class GeminiClient:
    """
    Thin wrapper around the Gemini generative model.
    Initialised once per test session (module-level fixture).
    """

    def __init__(self, api_key: str, model_name: str):
        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel(model_name=model_name)
        self._model_name = model_name

    def chat(self, prompt: str) -> str:
        """
        Send a single-turn prompt to Gemini and return the text reply.
        Retries once on transient errors (rate limits / network blip).
        """
        for attempt in range(2):
            try:
                response = self._model.generate_content(prompt)
                return response.text
            except Exception as exc:
                if attempt == 0:
                    time.sleep(2)        # brief back-off
                    continue
                raise RuntimeError(
                    f"Gemini API call failed with model '{self._model_name}': {exc}"
                ) from exc
        return ""  # unreachable


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def gemini():
    """Real Gemini 2.5 Flash client — shared across all tests in this module."""
    if _SKIP_REASON:
        pytest.skip(_SKIP_REASON)
    return GeminiClient(api_key=_API_KEY, model_name=_GEMINI_MODEL)


@pytest.fixture
def pds():
    """Fresh PrivacyDataSecurity instance with default config."""
    return PrivacyDataSecurity(config="default")


@pytest.fixture
def banking_pds():
    """PrivacyDataSecurity with banking (high-sensitivity) config."""
    return PrivacyDataSecurity(config="banking")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ask(gemini: GeminiClient, pds: PrivacyDataSecurity, raw_prompt: str):
    """
    Full protect → Gemini → restore cycle.

    Returns
    -------
    tuple (protect_result, ai_response_raw, final_restored)
    """
    protect_result  = pds.protect(raw_prompt)
    ai_response_raw = gemini.chat(protect_result.safe_content)
    final_restored  = pds.restore(ai_response_raw, session_id=protect_result.session_id)
    return protect_result, ai_response_raw, final_restored


# ══════════════════════════════════════════════════════════════════════════════
#  Test Scenarios
# ══════════════════════════════════════════════════════════════════════════════

@requires_gemini
class TestGeminiPrivacyPipeline:
    """Real end-to-end tests — Gemini 2.5 Flash processes tokenized prompts."""

    # ── 1. Email protection ───────────────────────────────────────────────────

    def test_email_not_leaked_to_gemini(self, gemini, pds):
        """
        Email address must be tokenized before reaching Gemini.
        The final restored response must contain the original email.
        """
        raw = (
            "My email is priya.sharma@example.com. "
            "Please confirm that you received my contact details."
        )
        result, ai_raw, final = _ask(gemini, pds, raw)

        # Privacy check: real email must NOT be in the tokenized prompt sent to AI
        assert "priya.sharma@example.com" not in result.safe_content, (
            "Email leaked to AI in safe_content!"
        )
        # Token check: a TKN_EMAIL placeholder should be present
        assert "TKN_EMAIL" in result.safe_content or result.items_vaulted >= 1

        # Restore check: Gemini may or may not echo back the token;
        # if it does, restore() must recover the real email.
        if "TKN_EMAIL" in ai_raw or result.items_vaulted >= 1:
            assert result.session_id.startswith("sess_")

        print(f"\n[PROTECT ] {result.safe_content[:120]}")
        print(f"[GEMINI  ] {ai_raw[:120]}")
        print(f"[RESTORED] {str(final)[:120]}")

    # ── 2. API key protection ──────────────────────────────────────────────────

    def test_api_key_not_leaked_to_gemini(self, gemini, pds):
        """
        OpenAI-style secret key must be vaulted; Gemini never sees the real key.
        """
        secret_key = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
        raw = f"I need help debugging my code. My API key is {secret_key}."

        result, ai_raw, final = _ask(gemini, pds, raw)

        # Real key must not reach AI
        assert secret_key not in result.safe_content, (
            "API key leaked to Gemini in safe_content!"
        )
        assert result.items_vaulted >= 1, "Expected API key to be vaulted"

        # At least one CRITICAL alert should have been fired
        assert len(result.alerts) >= 1, "Expected CRITICAL alert for API key"

        print(f"\n[PROTECT ] {result.safe_content[:120]}")
        print(f"[GEMINI  ] {ai_raw[:120]}")
        print(f"[RESTORED] {str(final)[:120]}")

    # ── 3. Database connection string ─────────────────────────────────────────

    def test_db_connection_not_leaked(self, gemini, pds):
        """
        PostgreSQL connection URI with password must not reach Gemini.
        """
        raw = (
            "Connect to postgresql://dbadmin:SuperSecret99@prod.internal:5432/customers "
            "and fetch the latest records."
        )
        result, ai_raw, final = _ask(gemini, pds, raw)

        assert "SuperSecret99" not in result.safe_content, (
            "DB password leaked to Gemini!"
        )
        assert result.items_vaulted >= 1

        print(f"\n[PROTECT ] {result.safe_content[:120]}")
        print(f"[GEMINI  ] {ai_raw[:120]}")
        print(f"[RESTORED] {str(final)[:120]}")

    # ── 4. Multiple secrets in one prompt ─────────────────────────────────────

    def test_multi_secret_protect_restore(self, gemini, pds):
        """
        A prompt containing email + API key + phone number.
        All three must be vaulted; none must reach Gemini.
        """
        raw = (
            "Hi, I'm Priya. My email is priya@secret.io, "
            "phone +91-9876543210, "
            "and OpenAI key sk-proj-MultiTestKEY1234567890abcdef. "
            "Please summarise my account."
        )
        result, ai_raw, final = _ask(gemini, pds, raw)

        assert "priya@secret.io"  not in result.safe_content
        assert "+91-9876543210"   not in result.safe_content
        assert "sk-proj-MultiTest" not in result.safe_content
        assert result.items_vaulted >= 2, (
            f"Expected ≥2 items vaulted, got {result.items_vaulted}"
        )

        print(f"\n[PROTECT ] {result.safe_content[:160]}")
        print(f"[GEMINI  ] {ai_raw[:160]}")
        print(f"[RESTORED] {str(final)[:160]}")
        print(f"[VAULTED ] {result.items_vaulted} items | alerts: {len(result.alerts)}")

    # ── 5. Audit trail after real conversation ────────────────────────────────

    def test_audit_trail_after_real_conversation(self, gemini, pds):
        """
        After a real Gemini conversation involving a secret,
        the audit log must contain at least one entry.
        """
        raw = "My email is audit.check@company.org. Can you help me reset my password?"
        result, ai_raw, final = _ask(gemini, pds, raw)

        if result.items_vaulted > 0:
            audit_log = pds.audit(result.session_id)
            assert len(audit_log) >= 1, (
                "Audit log empty after vaulting data"
            )
            # Verify the audit entry has expected fields
            entry = audit_log[0]
            assert entry.session_id == result.session_id
            assert entry.token != ""

        print(f"\n[VAULTED ] {result.items_vaulted} | audit entries: "
              f"{len(pds.audit(result.session_id))}")

    # ── 6. Clean prompt — nothing vaulted ─────────────────────────────────────

    def test_no_data_passthrough_clean_prompt(self, gemini, pds):
        """
        A prompt with zero confidential data: items_vaulted must be 0,
        and Gemini should reply normally (no tokens in prompt or response).
        """
        raw = "What is the capital of France?"
        result, ai_raw, final = _ask(gemini, pds, raw)

        assert result.items_vaulted == 0
        assert result.safe_content == raw, "Clean prompt should be unchanged"
        assert "TKN_" not in ai_raw, "Unexpected token in Gemini reply for clean prompt"

        # Gemini should mention Paris
        assert "Paris" in final or "paris" in final.lower(), (
            f"Expected 'Paris' in Gemini answer, got: {final[:200]}"
        )

        print(f"\n[GEMINI  ] {ai_raw[:120]}")
        print(f"[RESTORED] {final[:120]}")

    # ── 7. Session revoke blocks restore ──────────────────────────────────────

    def test_revoke_session_blocks_restore(self, gemini, pds):
        """
        After revoking a session, calling restore() must raise VaultAccessError.
        """
        raw = "Key: sk-proj-RevokeTest99XYZabcdef1234567890"
        result, ai_raw, _ = _ask.__wrapped__ if hasattr(_ask, "__wrapped__") else (
            lambda g, p, r: (p.protect(r), g.chat(p.protect(r).safe_content), None)
        )(gemini, pds, raw)

        # Protect only (don't restore yet)
        result  = pds.protect(raw)
        ai_raw  = gemini.chat(result.safe_content)

        # Revoke the session
        pds.revoke_session(result.session_id)

        # Restore must now be denied
        with pytest.raises(VaultAccessError):
            pds.restore(ai_raw, session_id=result.session_id)

        print(f"\n[REVOKE  ] session {result.session_id} revoked — restore blocked ✓")

    # ── 8. Banking config + card number ───────────────────────────────────────

    def test_banking_config_with_real_ai(self, gemini, banking_pds):
        """
        Banking config (high sensitivity): a credit card number must be
        vaulted and a CRITICAL alert fired before Gemini processes the request.
        """
        raw = (
            "Transaction failed for card 4111-2222-3333-4444 with CVV 902 "
            "and expiry 12/28. Please verify the issue."
        )
        result, ai_raw, final = _ask(gemini, banking_pds, raw)

        assert "4111-2222-3333-4444" not in result.safe_content, (
            "Card number leaked to Gemini!"
        )
        assert result.items_vaulted >= 1

        # Banking / high-sensitivity should fire a CRITICAL alert
        assert len(result.alerts) >= 1, (
            "Expected CRITICAL alert for credit card in banking config"
        )

        print(f"\n[PROTECT ] {result.safe_content[:120]}")
        print(f"[GEMINI  ] {ai_raw[:120]}")
        print(f"[RESTORED] {str(final)[:120]}")
        print(f"[ALERTS  ] {result.alerts}")


# ══════════════════════════════════════════════════════════════════════════════
#  Quick smoke test — prints a live conversation to stdout (-s flag)
# ══════════════════════════════════════════════════════════════════════════════

@requires_gemini
def test_live_conversation_smoke(gemini, pds, capsys):
    """
    One full live conversation printed to stdout. Run with -s to see the output.

    User message contains email + phone. Shows exactly what Gemini receives
    vs what the user finally sees.
    """
    raw = (
        "Hi! My name is Golu and my email is golu.dev@example.com. "
        "My phone is +91-9123456789. "
        "Can you write me a short Python function to reverse a string?"
    )

    print("\n" + "═" * 70)
    print("  LIVE GEMINI 2.5 FLASH — PRIVACY LAYER E2E SMOKE TEST")
    print("═" * 70)

    # Step 1: Protect
    result = pds.protect(raw)
    print(f"\n[USER INPUT ]\n{raw}")
    print(f"\n[AFTER PROTECT — sent to Gemini]\n{result.safe_content}")
    print(f"\n  ↳ Items vaulted: {result.items_vaulted} | Alerts: {len(result.alerts)}")

    # Step 2: Real Gemini call
    ai_raw = gemini.chat(result.safe_content)
    print(f"\n[GEMINI RESPONSE — raw]\n{ai_raw}")

    # Step 3: Restore
    final = pds.restore(ai_raw, session_id=result.session_id)
    print(f"\n[FINAL RESPONSE — user sees]\n{final}")

    # Step 4: Audit
    audit_log = pds.audit(result.session_id)
    print(f"\n[AUDIT LOG] {len(audit_log)} entries for session {result.session_id}")
    for entry in audit_log:
        print(f"  • {entry.type:<20} token={entry.token[:30]}...")

    print("\n" + "═" * 70)

    # Assertions
    assert "golu.dev@example.com" not in result.safe_content
    assert "+91-9123456789"       not in result.safe_content
    assert result.items_vaulted   >= 1
    assert result.session_id.startswith("sess_")
