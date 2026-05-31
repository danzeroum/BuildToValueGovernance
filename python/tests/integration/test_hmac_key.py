"""
Tests: HMAC key management (Gap #10) — fail-secure behavior + env loading.

#198: rewired from the removed `app.py._load_hmac_key` (deleted in the ADR-0093
slimming) to the current key API in `buildtovalue.security.keys`:
``init_hmac_key()`` resolves env → fail-closed rules into a process singleton;
``get_hmac_key()`` returns it. ``_zeroize_for_tests()`` clears the holder so each
case re-reads a fresh env (init also pops BTV_HMAC_KEY from os.environ).
"""

import pytest

from buildtovalue.security.keys import (
    init_hmac_key,
    get_hmac_key,
    _DEV_FALLBACK,
    _zeroize_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_key_holder():
    """Each test starts and ends with a clean key holder."""
    _zeroize_for_tests()
    yield
    _zeroize_for_tests()


class TestHmacKeyLoading:

    def test_env_key_used(self, monkeypatch):
        """BTV_HMAC_KEY env var should be used when set."""
        monkeypatch.setenv("BTV_HMAC_KEY", "my-secret-key-123")
        monkeypatch.delenv("BTV_ENV", raising=False)

        init_hmac_key()
        assert get_hmac_key() == b"my-secret-key-123"

    def test_dev_fallback(self, monkeypatch):
        """Without env var in dev, should use fallback with warning."""
        monkeypatch.delenv("BTV_HMAC_KEY", raising=False)
        monkeypatch.setenv("BTV_ENV", "development")

        init_hmac_key()
        assert get_hmac_key() == _DEV_FALLBACK

    def test_production_fails_without_key(self, monkeypatch):
        """Production without BTV_HMAC_KEY must fail-secure."""
        monkeypatch.delenv("BTV_HMAC_KEY", raising=False)
        monkeypatch.setenv("BTV_ENV", "production")

        with pytest.raises(RuntimeError, match="BTV_HMAC_KEY must be set"):
            init_hmac_key()

    def test_key_not_empty(self, monkeypatch):
        """Empty string is falsy → falls through to dev fallback."""
        monkeypatch.setenv("BTV_HMAC_KEY", "")
        monkeypatch.setenv("BTV_ENV", "development")

        init_hmac_key()
        assert get_hmac_key() == _DEV_FALLBACK


class TestSignatureWithEnvKey:

    def test_verdict_signed_with_env_key(self, monkeypatch):
        """Verdicts should be signed with the env-loaded key."""
        monkeypatch.setenv("BTV_HMAC_KEY", "test-key-for-signing-padded!!")
        monkeypatch.delenv("BTV_ENV", raising=False)

        init_hmac_key()

        from buildtovalue.api.app import sign_verdict
        sig = sign_verdict("verd_test", "BLOCK", 0.8)
        assert sig != ""
        assert len(sig) == 64  # HMAC-SHA256 hex digest
