"""Tests for ContentProvenanceVerifier — Cenários 16, 21, 8."""
from __future__ import annotations

import pytest

from buildtovalue.governance.content_provenance import (
    ContentClassification,
    ContentMetadata,
    ContentProvenanceVerifier,
    ProvenanceAction,
    ProvenanceReport,
)
from buildtovalue.governance.durable_ledger import DurableLedger


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key-content-provenance")


@pytest.fixture
def verifier(ledger: DurableLedger) -> ContentProvenanceVerifier:
    return ContentProvenanceVerifier(ledger=ledger)


def _make_metadata(
    content: bytes = b"conteudo de teste",
    classification: ContentClassification = ContentClassification.INTERNAL,
    c2pa_manifest: bytes | None = None,
    exif_data: dict | None = None,
    source_uri: str | None = None,
) -> ContentMetadata:
    return ContentMetadata(
        content_bytes=content,
        classification=classification,
        c2pa_manifest=c2pa_manifest,
        exif_data=exif_data,
        source_uri=source_uri,
    )


# ── TestC2PAAbsent — SIM-1: C2PA ausente → EDUCATE (nunca BLOCK) ──────────────

class TestC2PAAbsent:
    def test_no_c2pa_returns_educate(self, verifier: ContentProvenanceVerifier) -> None:
        """Conteúdo sem C2PA → EDUCATE, não BLOCK (crate instável)."""
        metadata = _make_metadata(c2pa_manifest=None)
        report = verifier.verify(metadata)
        assert report.action == ProvenanceAction.EDUCATE
        assert not report.blocked

    def test_no_c2pa_public_returns_educate(self, verifier: ContentProvenanceVerifier) -> None:
        metadata = _make_metadata(
            classification=ContentClassification.PUBLIC,
            c2pa_manifest=None,
        )
        report = verifier.verify(metadata)
        assert report.action == ProvenanceAction.EDUCATE

    def test_no_c2pa_confidential_returns_educate_if_exif_ok(
        self, verifier: ContentProvenanceVerifier
    ) -> None:
        """CONFIDENTIAL sem C2PA mas EXIF ok → EDUCATE (C2PA ausente, não modificação)."""
        metadata = _make_metadata(
            classification=ContentClassification.CONFIDENTIAL,
            c2pa_manifest=None,
            exif_data=None,  # sem EXIF
        )
        report = verifier.verify(metadata)
        assert report.action == ProvenanceAction.EDUCATE
        assert not report.blocked


# ── TestC2PAValid — SIM-2: C2PA válida → ALLOW ────────────────────────────────

class TestC2PAValid:
    def test_valid_c2pa_returns_allow(self, verifier: ContentProvenanceVerifier) -> None:
        """C2PA presente e válida (stub) → ALLOW."""
        metadata = _make_metadata(c2pa_manifest=b"c2pa manifest valido")
        report = verifier.verify(metadata)
        assert report.action == ProvenanceAction.ALLOW
        assert not report.blocked

    def test_c2pa_field_true_on_valid(self, verifier: ContentProvenanceVerifier) -> None:
        metadata = _make_metadata(c2pa_manifest=b"c2pa signed")
        report = verifier.verify(metadata)
        assert report.c2pa_present is True
        assert report.c2pa_valid is True


# ── TestEXIFModification — SIM-3: EXIF modificado em CONFIDENTIAL → BLOCK ─────

class TestEXIFModification:
    def test_modified_exif_confidential_blocks(self, verifier: ContentProvenanceVerifier) -> None:
        """EXIF com data original != data modificada em CONFIDENTIAL → BLOCK."""
        metadata = _make_metadata(
            classification=ContentClassification.CONFIDENTIAL,
            exif_data={
                "Software": "Adobe Photoshop",
                "DateTimeOriginal": "2026:01:01 10:00:00",
                "DateTime":         "2026:01:02 15:30:00",  # data diferente → suspeito
            },
        )
        report = verifier.verify(metadata)
        assert report.action == ProvenanceAction.BLOCK
        assert report.blocked is True
        assert not report.exif_consistent

    def test_modified_exif_restricted_blocks(self, verifier: ContentProvenanceVerifier) -> None:
        metadata = _make_metadata(
            classification=ContentClassification.RESTRICTED,
            exif_data={
                "Software": "GIMP",
                "DateTimeOriginal": "2026:01:01 10:00:00",
                "DateTime":         "2026:03:15 08:00:00",
            },
        )
        report = verifier.verify(metadata)
        assert report.action == ProvenanceAction.BLOCK

    def test_modified_exif_public_educates(self, verifier: ContentProvenanceVerifier) -> None:
        """EXIF modificado em conteúdo PUBLIC → EDUCATE (não BLOCK)."""
        metadata = _make_metadata(
            classification=ContentClassification.PUBLIC,
            exif_data={
                "Software": "Adobe Photoshop",
                "DateTimeOriginal": "2026:01:01 10:00:00",
                "DateTime":         "2026:02:01 12:00:00",
            },
        )
        report = verifier.verify(metadata)
        # PUBLIC: EXIF modificado → EDUCATE, não BLOCK
        assert report.action in (ProvenanceAction.EDUCATE, ProvenanceAction.ALLOW)

    def test_consistent_exif_no_block(self, verifier: ContentProvenanceVerifier) -> None:
        """EXIF sem sinais de modificação → consistent=True."""
        metadata = _make_metadata(
            exif_data={
                "DateTimeOriginal": "2026:01:01 10:00:00",
                "DateTime":         "2026:01:01 10:00:00",  # mesma data → consistente
            },
        )
        report = verifier.verify(metadata)
        assert report.exif_consistent is True


# ── TestCustodyChain — SIM-4: Hash gravado no DurableLedger ───────────────────

class TestCustodyChain:
    def test_hash_recorded_in_ledger(
        self, ledger: DurableLedger, verifier: ContentProvenanceVerifier
    ) -> None:
        """Hash BLAKE2b do conteúdo deve ser gravado no DurableLedger sempre."""
        content = b"conteudo para hash"
        metadata = _make_metadata(content=content)
        report = verifier.verify(metadata)

        entries = ledger.entries()
        custody_entries = [
            e for e in entries
            if e.payload.get("type") == "content_provenance_check"
            and e.payload.get("content_hash") == report.content_hash
        ]
        assert len(custody_entries) == 1

    def test_hash_is_blake2b_deterministic(self, verifier: ContentProvenanceVerifier) -> None:
        """Mesmo conteúdo → mesmo hash BLAKE2b."""
        content = b"conteudo fixo"
        meta1 = _make_metadata(content=content)
        meta2 = _make_metadata(content=content)
        report1 = verifier.verify(meta1)
        report2 = verifier.verify(meta2)
        assert report1.content_hash == report2.content_hash

    def test_ledger_integrity_after_checks(
        self, ledger: DurableLedger, verifier: ContentProvenanceVerifier
    ) -> None:
        """DurableLedger mantém integridade após múltiplas verificações."""
        for i in range(5):
            verifier.verify(_make_metadata(content=f"conteudo {i}".encode()))
        verification = ledger.verify()
        assert verification.valid is True

    def test_custody_entry_contains_classification(
        self, ledger: DurableLedger, verifier: ContentProvenanceVerifier
    ) -> None:
        metadata = _make_metadata(
            classification=ContentClassification.CONFIDENTIAL,
            source_uri="https://example.com/doc.pdf",
        )
        report = verifier.verify(metadata)
        entries = ledger.entries()
        custody = next(
            (e for e in entries
             if e.payload.get("content_hash") == report.content_hash), None
        )
        assert custody is not None
        assert custody.payload["classification"] == "CONFIDENTIAL"


# ── TestFailSecure — SIM-5: Fail-secure ───────────────────────────────────────

class TestFailSecure:
    def test_explain_always_present(self, verifier: ContentProvenanceVerifier) -> None:
        report = verifier.verify(_make_metadata())
        assert report.explain_decision
        assert len(report.explain_decision) > 10

    def test_signature_always_present(self, verifier: ContentProvenanceVerifier) -> None:
        report = verifier.verify(_make_metadata())
        assert report.signature
        assert len(report.signature) == 64

    def test_result_is_frozen(self, verifier: ContentProvenanceVerifier) -> None:
        report = verifier.verify(_make_metadata())
        with pytest.raises((AttributeError, TypeError)):
            report.action = ProvenanceAction.BLOCK  # type: ignore[misc]

    def test_decided_at_iso_is_utc(self, verifier: ContentProvenanceVerifier) -> None:
        report = verifier.verify(_make_metadata())
        assert "Z" in report.decided_at_iso or "+00:00" in report.decided_at_iso
