"""
test_model_integrity_contestability.py — ADR-051 Fase 3
"""
import pytest

from buildtovalue.governance.model_integrity_contestability import (
    ModelIntegrityContestabilityFlow,
    ManifestAppealResult,
    MANIFEST_GROUND,
    _blake3_hex,
    _sign_manifest,
    _explain,
)
from buildtovalue.governance.contestability_loop import AppealStatus

VALID_MANIFEST = b'{"model":"phi-3-mini","tensors_sha256":"abc123"}'
SIGNING_KEY    = b"\x42" * 32
MODEL_ID       = "phi-3-mini-v1"
LONG_REASON    = "Updated weights after legitimate fine-tuning session on 2026-03-09"


def _flow(tmp_path):
    return ModelIntegrityContestabilityFlow(
        db_path=str(tmp_path / "appeals.db")
    )


def _submit(flow):
    return flow.submit_manifest_appeal(
        model_id=MODEL_ID,
        violation_type="HashMismatch",
        alternative_manifest_bytes=VALID_MANIFEST,
        operator_signing_key=SIGNING_KEY,
        reason=LONG_REASON,
    )


# ─── Funções puras ───────────────────────────────────────────────────────────────────────────────

class TestPureFunctions:
    def test_blake3_hex_length(self):
        h = _blake3_hex(b"test manifest")
        assert len(h) == 64  # 32 bytes * 2 hex chars

    def test_blake3_hex_deterministic(self):
        assert _blake3_hex(b"same") == _blake3_hex(b"same")

    def test_blake3_hex_different_inputs(self):
        assert _blake3_hex(b"abc") != _blake3_hex(b"xyz")

    def test_sign_manifest_deterministic(self):
        s1 = _sign_manifest(b"manifest", SIGNING_KEY)
        s2 = _sign_manifest(b"manifest", SIGNING_KEY)
        assert s1 == s2

    def test_sign_manifest_different_keys(self):
        s1 = _sign_manifest(b"manifest", b"\x42" * 32)
        s2 = _sign_manifest(b"manifest", b"\x43" * 32)
        assert s1 != s2

    def test_explain_accept_contains_hash(self):
        txt = _explain(MODEL_ID, "APL-1", True, "a" * 64, "looks good")
        assert "ACCEPTED" in txt
        assert "BLAKE3" in txt
        assert "ADR-042" in txt

    def test_explain_reject_contains_block(self):
        txt = _explain(MODEL_ID, "APL-1", False, None, "not valid")
        assert "REJECTED" in txt
        assert "BLOCK" in txt

    def test_explain_always_non_contestable(self):
        txt = _explain(MODEL_ID, "APL-1", False, None, "reason")
        assert "non-contestable" in txt


# ─── Submit ────────────────────────────────────────────────────────────────────────────────────
class TestSubmitManifestAppeal:
    def test_creates_pending_appeal(self, tmp_path):
        appeal = _submit(_flow(tmp_path))
        assert appeal.status == AppealStatus.PENDING

    def test_has_manifest_ground(self, tmp_path):
        appeal = _submit(_flow(tmp_path))
        assert MANIFEST_GROUND in appeal.grounds

    def test_has_evidence_hash(self, tmp_path):
        appeal = _submit(_flow(tmp_path))
        assert appeal.evidence_hash is not None
        assert len(appeal.evidence_hash) == 64

    def test_sla_is_24h(self, tmp_path):
        appeal = _submit(_flow(tmp_path))
        assert appeal.sla_deadline == appeal.timestamp + (24 * 3600)

    def test_empty_manifest_raises(self, tmp_path):
        with pytest.raises(ValueError, match="vazio"):
            _flow(tmp_path).submit_manifest_appeal(
                model_id=MODEL_ID,
                violation_type="HashMismatch",
                alternative_manifest_bytes=b"",
                operator_signing_key=SIGNING_KEY,
                reason=LONG_REASON,
            )

    def test_short_reason_raises(self, tmp_path):
        with pytest.raises(ValueError):
            _flow(tmp_path).submit_manifest_appeal(
                model_id=MODEL_ID,
                violation_type="HashMismatch",
                alternative_manifest_bytes=VALID_MANIFEST,
                operator_signing_key=SIGNING_KEY,
                reason="too short",
            )


# ─── Resolve ──────────────────────────────────────────────────────────────────────────────────
class TestResolveManifestAppeal:
    def _setup(self, tmp_path):
        flow   = _flow(tmp_path)
        appeal = _submit(flow)
        return flow, appeal

    def test_accept_returns_new_hash(self, tmp_path):
        flow, appeal = self._setup(tmp_path)
        result = flow.resolve_manifest_appeal(
            appeal_id=appeal.appeal_id,
            model_id=MODEL_ID,
            accepted=True,
            reviewer_notes="Legitimate fine-tuning verified by security team.",
            new_manifest_bytes=VALID_MANIFEST,
        )
        assert result.accepted is True
        assert result.new_expected_hash is not None
        assert len(result.new_expected_hash) == 64

    def test_reject_returns_no_hash(self, tmp_path):
        flow, appeal = self._setup(tmp_path)
        result = flow.resolve_manifest_appeal(
            appeal_id=appeal.appeal_id,
            model_id=MODEL_ID,
            accepted=False,
            reviewer_notes="No evidence of legitimate modification found.",
        )
        assert result.accepted is False
        assert result.new_expected_hash is None

    def test_explanation_always_present(self, tmp_path):
        flow, appeal = self._setup(tmp_path)
        result = flow.resolve_manifest_appeal(
            appeal_id=appeal.appeal_id,
            model_id=MODEL_ID,
            accepted=False,
            reviewer_notes="Rejected: no legitimate justification provided.",
        )
        assert result.explanation
        assert MODEL_ID in result.explanation
        assert "BLOCK" in result.explanation

    def test_accept_without_bytes_raises(self, tmp_path):
        flow, appeal = self._setup(tmp_path)
        with pytest.raises(ValueError, match="new_manifest_bytes"):
            flow.resolve_manifest_appeal(
                appeal_id=appeal.appeal_id,
                model_id=MODEL_ID,
                accepted=True,
                reviewer_notes="Accepted without providing bytes.",
                new_manifest_bytes=None,
            )

    def test_resolution_is_not_contestable(self, tmp_path):
        flow, appeal = self._setup(tmp_path)
        result = flow.resolve_manifest_appeal(
            appeal_id=appeal.appeal_id,
            model_id=MODEL_ID,
            accepted=False,
            reviewer_notes="Final decision after full review.",
        )
        assert result.contestable is False

    def test_pending_list_filtered_by_ground(self, tmp_path):
        flow   = _flow(tmp_path)
        _submit(flow)
        pending = flow.get_pending_manifest_appeals()
        assert len(pending) == 1
        assert MANIFEST_GROUND in pending[0].grounds

    def test_accept_hash_matches_manifest(self, tmp_path):
        """new_expected_hash deve ser o hash do new_manifest_bytes fornecido."""
        flow, appeal = self._setup(tmp_path)
        new_manifest = b'{"model":"phi-3-mini","tensors_sha256":"updated_xyz"}'
        result = flow.resolve_manifest_appeal(
            appeal_id=appeal.appeal_id,
            model_id=MODEL_ID,
            accepted=True,
            reviewer_notes="Accepted after code review and lineage verification.",
            new_manifest_bytes=new_manifest,
        )
        expected_hash = _blake3_hex(new_manifest)
        assert result.new_expected_hash == expected_hash
