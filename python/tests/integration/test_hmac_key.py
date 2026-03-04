"""
Tests: HMAC key management (Gap #10).
Validates fail-secure behavior and env var loading.
"""

import os
import pytest
import importlib


class TestHmacKeyLoading:

    def test_env_key_used(self, monkeypatch):
        """BTV_HMAC_KEY env var should be used when set."""
        monkeypatch.setenv("BTV_HMAC_KEY", "my-secret-key-123")
        monkeypatch.delenv("BTV_ENV", raising=False)

        from buildtovalue.api.app import _load_hmac_key
        key = _load_hmac_key()
        assert key == b"my-secret-key-123"

    def test_dev_fallback(self, monkeypatch):
        """Without env var in dev, should use fallback with warning."""
        monkeypatch.delenv("BTV_HMAC_KEY", raising=False)
        monkeypatch.setenv("BTV_ENV", "development")

        from buildtovalue.api.app import _load_hmac_key
        key = _load_hmac_key()
        assert key == b"btv-dev-key-NOT-FOR-PRODUCTION!!"

    def test_production_fails_without_key(self, monkeypatch):
        """Production without BTV_HMAC_KEY must fail-secure."""
        monkeypatch.delenv("BTV_HMAC_KEY", raising=False)
        monkeypatch.setenv("BTV_ENV", "production")

        from buildtovalue.api.app import _load_hmac_key
        with pytest.raises(RuntimeError, match="BTV_HMAC_KEY must be set"):
            _load_hmac_key()

    def test_key_not_empty(self, monkeypatch):
        """Empty string should use fallback."""
        monkeypatch.setenv("BTV_HMAC_KEY", "")
        monkeypatch.setenv("BTV_ENV", "development")

        from buildtovalue.api.app import _load_hmac_key
        key = _load_hmac_key()
        # Empty string is falsy → falls through to dev fallback
        assert key == b"btv-dev-key-NOT-FOR-PRODUCTION!!"


class TestSignatureWithEnvKey:

    def test_verdict_signed_with_env_key(self, monkeypatch):
        """Verdicts should use the env-loaded key."""
        monkeypatch.setenv("BTV_HMAC_KEY", "test-key-for-signing-padded!!")

        from buildtovalue.api.app import sign_verdict, _load_hmac_key
        import buildtovalue.api.app as app_module

        # Reload the key
        app_module.HMAC_KEY = _load_hmac_key()

        sig = sign_verdict("verd_test", "BLOCK", 0.8)
        assert sig != ""
        assert len(sig) == 64  # HMAC-SHA256 hex digest