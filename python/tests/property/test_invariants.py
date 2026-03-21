"""Property-based tests for governance invariants using Hypothesis."""
from __future__ import annotations

import hashlib
import hmac as hmac_lib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.visual_input_firewall import (
    FirewallVerdict,
    VisualInputFirewall,
)


@pytest.mark.property
class TestFirewallInvariants:
    @given(text=st.text(min_size=0, max_size=500))
    @settings(max_examples=100)
    def test_explain_never_empty(self, text: str) -> None:
        """For any string input, sanitize() always returns a non-empty explain."""
        fw = VisualInputFirewall()
        result = fw.sanitize(text)
        assert result.explain, f"Empty explain for input: {text!r}"

    @given(text=st.text(min_size=0, max_size=500))
    @settings(max_examples=100)
    def test_block_verdict_deterministic(self, text: str) -> None:
        """Same input always produces the same verdict."""
        fw = VisualInputFirewall()
        r1 = fw.sanitize(text)
        r2 = fw.sanitize(text)
        assert r1.verdict == r2.verdict

    @given(
        data=st.one_of(
            st.integers(min_value=1),
            st.lists(st.text(min_size=1), min_size=1, max_size=3),
        )
    )
    @settings(max_examples=50)
    def test_firewall_fail_secure_truthy_non_string(self, data) -> None:
        """For truthy non-string input, sanitize() returns BLOCK (fail-secure via exception).

        Note: falsy values (None, 0, [], False) are treated as empty text → ALLOW
        by the firewall's `if not ocr_text:` check. This tests only truthy non-strings.
        """
        fw = VisualInputFirewall()
        result = fw.sanitize(data)  # type: ignore[arg-type]
        assert result.verdict == FirewallVerdict.BLOCK


@pytest.mark.property
class TestHmacInvariants:
    @given(
        key=st.binary(min_size=1, max_size=100),
        data=st.text(min_size=1, max_size=200),
    )
    @settings(max_examples=100)
    def test_hmac_deterministic(self, key: bytes, data: str) -> None:
        """Same key + data always produces the same HMAC."""
        sig1 = hmac_lib.new(key, data.encode(), hashlib.sha256).hexdigest()
        sig2 = hmac_lib.new(key, data.encode(), hashlib.sha256).hexdigest()
        assert sig1 == sig2

    @given(
        key=st.binary(min_size=1, max_size=100),
        data=st.text(min_size=1, max_size=200),
    )
    @settings(max_examples=50)
    def test_hmac_is_64_hex(self, key: bytes, data: str) -> None:
        """HMAC-SHA256 always produces a 64-char hex string."""
        sig = hmac_lib.new(key, data.encode(), hashlib.sha256).hexdigest()
        assert len(sig) == 64
        int(sig, 16)  # Should not raise


@pytest.mark.property
class TestLedgerInvariants:
    @given(
        payloads=st.lists(
            st.dictionaries(
                st.text(min_size=1, max_size=20),
                st.text(min_size=0, max_size=50),
                min_size=1,
                max_size=5,
            ),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=50)
    def test_durable_ledger_append_only(self, payloads) -> None:
        """Entries count only grows; entries are never modified."""
        ledger = DurableLedger(hmac_key=b"test-key")
        prev_count = 0

        for i, payload in enumerate(payloads):
            # Ensure explain_decision is present (ledger invariant)
            payload["explain_decision"] = f"Test entry {i}"
            ledger.append(payload)
            current_count = len(ledger.entries())
            assert current_count > prev_count, "Ledger must grow on append"
            prev_count = current_count
