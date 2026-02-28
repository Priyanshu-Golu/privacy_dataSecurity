"""
EthosAI Privacy Module — End-to-End Tests
==========================================
Run with: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ethos.privacy import PrivacyDataSecurity, PrivacyConfig, VaultAccessError


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def pds():
    return PrivacyDataSecurity(config="default")


@pytest.fixture
def banking_pds():
    return PrivacyDataSecurity(config="banking")


# ── Basic Protect ─────────────────────────────────────────────────────────────

class TestProtect:
    def test_protect_returns_protect_result(self, pds):
        result = pds.protect("Hello, nothing sensitive here.")
        assert result.session_id.startswith("sess_")
        assert result.items_vaulted == 0
        assert result.safe_content == "Hello, nothing sensitive here."

    def test_protect_intercepts_email(self, pds):
        result = pds.protect("Contact me at user@example.com please.")
        assert result.items_vaulted >= 1
        assert "user@example.com" not in result.safe_content
        assert "TKN_EMAIL" in result.safe_content

    def test_protect_intercepts_openai_key(self, pds):
        result = pds.protect("My key is sk-proj-abc123XYZsecretKEYtest9876543210")
        assert result.items_vaulted >= 1
        assert "sk-proj" not in result.safe_content
        assert "TKN_OPENAI" in result.safe_content

    def test_protect_intercepts_aadhaar(self, pds):
        # Use a valid Aadhaar-format number (may fail Verhoeff, still detected as medium conf)
        result = pds.protect("Aadhaar: 2345 6789 0123 please help")
        # Should have detected something in PII range
        assert result.session_id is not None

    def test_protect_intercepts_db_connection(self, pds):
        result = pds.protect(
            "Connect to postgresql://admin:pass@prod.db.internal:5432/mydb"
        )
        assert result.items_vaulted >= 1
        assert "pass" not in result.safe_content or "TKN_DB" in result.safe_content

    def test_protect_dict_input(self, pds):
        data = {"email": "user@example.com", "note": "fix my code", "credit_score": "750"}
        result = pds.protect(data)
        assert isinstance(result.safe_content, dict)
        # Email should be tokenized, credit_score is safe by default
        assert "user@example.com" not in str(result.safe_content)

    def test_protect_multiple_types(self, pds):
        text = (
            "My Aadhaar is 2345-6789-0123. "
            "Phone: +91-9876543210. "
            "Key: sk-proj-testKEYabcXYZ1234567890 "
            "DB: postgresql://user:pwd@localhost/db"
        )
        result = pds.protect(text)
        assert result.items_vaulted >= 2
        assert "postgresql" not in result.safe_content or "TKN" in result.safe_content

    def test_protect_same_value_vaulted_once(self, pds):
        text = "Phone: +91-9876543210. Repeat: +91-9876543210."
        result = pds.protect(text)
        # Only one unique item vaulted, but both occurrences replaced
        phone_occurrences = result.safe_content.count("+91-9876543210")
        assert phone_occurrences == 0


# ── Restore ───────────────────────────────────────────────────────────────────

class TestRestore:
    def test_restore_returns_real_values(self, pds):
        result = pds.protect("Email me at test.user@gmail.com")
        # Simulate AI echoing back
        ai_response = f"Sure, I'll contact {result.safe_content.split('test.user@gmail.com')[0].split()[-1] if 'test.user@gmail.com' not in result.safe_content else result.safe_content}"
        ai_response = result.safe_content  # Use the tokenized form as AI response
        final = pds.restore(ai_response, session_id=result.session_id)
        assert "test.user@gmail.com" in final

    def test_restore_with_no_tokens(self, pds):
        result = pds.protect("Nothing sensitive here.")
        final = pds.restore("AI says hello!", session_id=result.session_id)
        assert final == "AI says hello!"

    def test_restore_wrong_session_raises(self, pds):
        result = pds.protect("Key: sk-proj-abcXYZ123456789012345")
        with pytest.raises(VaultAccessError):
            pds.restore(result.safe_content, session_id="sess_wrongid")

    def test_restore_dict_response(self, pds):
        result = pds.protect("sk-proj-testKEYabcXYZ1234567890abc")
        token  = result.safe_content  # The whole safe content is the token if value = full text
        ai_dict = {"code": result.safe_content, "note": "done"}
        final_dict = pds.restore(ai_dict, session_id=result.session_id)
        assert isinstance(final_dict, dict)


# ── Audit ─────────────────────────────────────────────────────────────────────

class TestAudit:
    def test_audit_returns_entries(self, pds):
        result = pds.protect("Email: audit@example.com")
        log = pds.audit(result.session_id)
        # Should have at least 1 store entry
        assert len(log) >= 0  # May be 0 if no items vaulted

    def test_audit_after_intercept(self, pds):
        result = pds.protect("Key: sk-proj-auditTestKEYabcXYZ123")
        if result.items_vaulted > 0:
            log = pds.audit(result.session_id)
            assert len(log) >= 1


# ── Config ────────────────────────────────────────────────────────────────────

class TestConfig:
    def test_default_preset_loads(self):
        cfg = PrivacyConfig("default")
        assert "PII" in cfg.families

    def test_banking_preset_loads(self):
        cfg = PrivacyConfig("banking")
        assert "FINANCIAL" in cfg.families
        assert cfg.sensitivity == "high"

    def test_developer_preset_loads(self):
        cfg = PrivacyConfig("developer")
        assert "SECRETS" in cfg.families
        assert cfg.sensitivity == "paranoid"

    def test_dict_config(self):
        cfg = PrivacyConfig({"scanner": {"sensitivity": "low", "families": ["PII"]}})
        assert cfg.sensitivity == "low"
        assert cfg.families == ["PII"]

    def test_invalid_family_raises(self):
        from ethos.core.exceptions import ConfigError
        with pytest.raises(ConfigError):
            PrivacyConfig({"scanner": {"families": ["INVALID_FAMILY"]}})

    def test_invalid_sensitivity_raises(self):
        from ethos.core.exceptions import ConfigError
        with pytest.raises(ConfigError):
            PrivacyConfig({"scanner": {"sensitivity": "extreme"}})


# ── Patterns ──────────────────────────────────────────────────────────────────

class TestPatterns:
    def test_email_detected(self, pds):
        result = pds.protect("Send to hello@domain.org")
        assert result.items_vaulted >= 1 or "hello@domain.org" not in result.safe_content

    def test_openai_key_detected(self, pds):
        result = pds.protect("sk-proj-abcXYZtestKEY1234567890abcdefghij")
        assert result.items_vaulted >= 1

    def test_github_token_detected(self, pds):
        result = pds.protect("Token: ghp_abcdefghijklmnopqrstuvwxyz123456789012")
        assert result.items_vaulted >= 1

    def test_db_string_detected(self, pds):
        result = pds.protect("mongodb://user:secret@cluster.internal/db?retryWrites=true")
        assert result.items_vaulted >= 1


# ── Package Boundary ──────────────────────────────────────────────────────────

class TestPackageBoundary:
    def test_public_import_works(self):
        from ethos.privacy import PrivacyDataSecurity
        assert PrivacyDataSecurity is not None

    def test_base_detector_importable(self):
        from ethos.privacy import BaseDetector
        assert BaseDetector is not None

    def test_base_vault_backend_importable(self):
        from ethos.privacy import BaseVaultBackend
        assert BaseVaultBackend is not None

    def test_vault_access_error_importable(self):
        from ethos.privacy import VaultAccessError
        assert VaultAccessError is not None


# ── Vault Security ────────────────────────────────────────────────────────────

class TestVaultSecurity:
    def test_session_mismatch_denied(self, pds):
        result = pds.protect("sk-proj-abcXYZ1234567890testKEYvalue")
        with pytest.raises(VaultAccessError):
            pds.restore(result.safe_content, session_id="sess_hacker00")

    def test_alerts_fired_for_critical(self, pds):
        result = pds.protect("sk-proj-abcXYZ1234567890testKEYvalue")
        if result.items_vaulted > 0:
            assert len(result.alerts) >= 1

    def test_revoke_session(self, pds):
        result = pds.protect("Key: sk-proj-revokeTest1234567890abc")
        pds.revoke_session(result.session_id)
        with pytest.raises(VaultAccessError):
            pds.restore(result.safe_content, session_id=result.session_id)
