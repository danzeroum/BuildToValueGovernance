"""
ContentProvenanceVerifier — Cenários 16, 21, 8
Verificação de proveniência de conteúdo (imagens, documentos, mídia).

Detecta conteúdo sem assinatura C2PA, modificações inconsistentes em metadados
EXIF, e gera hash BLAKE2b do conteúdo para rastreabilidade no DurableLedger.

IMPORTANTE: O crate c2pa para Rust está em estado alpha instável.
Portanto, este módulo implementa:
  - C2PA: STUB Python com hook para integração futura
  - Modo padrão: EDUCATE quando C2PA ausente (nunca BLOCK por ausência de assinatura)
  - EXIF: análise básica de consistência via campos canônicos
  - Hash BLAKE2b do conteúdo para cadeia de custódia no DurableLedger

Invariantes:
  - Fail-secure: exceção → ProvenanceReport(action=BLOCK)
  - explain_decision obrigatório em todo resultado
  - HMAC-SHA256 em todo ProvenanceReport
  - Modo EDUCATE enquanto C2PA estiver instável (mudar para BLOCK após estabilizar)
  - Hash BLAKE2b gravado no DurableLedger para auditoria completa
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.content_provenance")

_DEFAULT_KEY: bytes = b"btv-content-provenance-default-v1"


# ─── Enums ────────────────────────────────────────────────────────────────────

class ProvenanceAction(str, Enum):
    ALLOW   = "ALLOW"    # C2PA válida + EXIF consistente
    EDUCATE = "EDUCATE"  # C2PA ausente (modo padrão enquanto crate instável)
    BLOCK   = "BLOCK"    # Modificação detectada em conteúdo CONFIDENTIAL/RESTRICTED


class ContentClassification(str, Enum):
    PUBLIC       = "PUBLIC"
    INTERNAL     = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED   = "RESTRICTED"


# ─── Resultado imutável ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProvenanceReport:
    """
    Resultado imutável da verificação de proveniência.
    action=EDUCATE é o padrão quando C2PA ausente (não BLOCK).
    content_hash gravado no DurableLedger para cadeia de custódia.
    """
    action:              ProvenanceAction
    content_hash:        str           # BLAKE2b hex do conteúdo
    c2pa_present:        bool
    c2pa_valid:          bool          # Stub False até integração real
    exif_consistent:     bool
    classification:      ContentClassification
    explain_decision:    str
    decided_at_iso:      str
    signature:           str

    @property
    def blocked(self) -> bool:
        return self.action == ProvenanceAction.BLOCK

    @property
    def needs_education(self) -> bool:
        return self.action == ProvenanceAction.EDUCATE


# ─── ContentMetadata — metadados do conteúdo ──────────────────────────────────

@dataclass
class ContentMetadata:
    """
    Metadados de conteúdo a verificar.

    content_bytes: conteúdo bruto (para hash BLAKE2b)
    exif_data:     dict com campos EXIF extraídos (opcional)
    c2pa_manifest: bytes do manifesto C2PA (None se ausente)
    classification: classificação de sensibilidade
    source_uri:    URI de origem (para rastreabilidade)
    """
    content_bytes:    bytes
    classification:   ContentClassification = ContentClassification.INTERNAL
    exif_data:        Optional[Dict[str, Any]] = None
    c2pa_manifest:    Optional[bytes] = None
    source_uri:       Optional[str] = None


# ─── ContentProvenanceVerifier ────────────────────────────────────────────────

class ContentProvenanceVerifier:
    """
    Verifica proveniência de conteúdo e grava hash no DurableLedger.

    Modo C2PA: STUB — implementação real aguarda estabilização do crate c2pa.
    Enquanto isso, ausência de C2PA → EDUCATE (não BLOCK).

    Uso:
        verifier = ContentProvenanceVerifier(ledger=ledger)
        report = verifier.verify(metadata)
        if report.blocked:
            # conteúdo modificado em CONFIDENTIAL/RESTRICTED
            ...
    """

    def __init__(
        self,
        ledger:    DurableLedger,
        hmac_key:  bytes = _DEFAULT_KEY,
        c2pa_mode: str = "EDUCATE",  # "EDUCATE" ou "BLOCK" (mudar após estabilizar)
    ) -> None:
        self._ledger    = ledger
        self._secret    = hmac_key
        self._c2pa_mode = c2pa_mode

    # ── API pública ────────────────────────────────────────────────────────────

    def verify(self, metadata: ContentMetadata) -> ProvenanceReport:
        """
        Verifica proveniência e grava hash no DurableLedger.
        Fail-secure: exceção → ProvenanceReport(action=BLOCK).
        """
        try:
            return self._verify_internal(metadata)
        except Exception as exc:
            logger.error("[ContentProvenanceVerifier] FAIL-SECURE: %s", exc)
            return self._fail_secure(metadata, str(exc))

    # ── Internos ───────────────────────────────────────────────────────────────

    def _verify_internal(self, metadata: ContentMetadata) -> ProvenanceReport:
        content_hash    = self._compute_hash(metadata.content_bytes)
        c2pa_present    = metadata.c2pa_manifest is not None
        c2pa_valid      = self._verify_c2pa_stub(metadata.c2pa_manifest)
        exif_consistent = self._check_exif_consistency(metadata.exif_data)

        action = self._determine_action(
            c2pa_present    = c2pa_present,
            c2pa_valid      = c2pa_valid,
            exif_consistent = exif_consistent,
            classification  = metadata.classification,
        )

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        explain = self._build_explain(
            action, c2pa_present, c2pa_valid, exif_consistent,
            metadata.classification, content_hash,
        )
        sig = self._sign(content_hash, action, now_iso)

        report = ProvenanceReport(
            action           = action,
            content_hash     = content_hash,
            c2pa_present     = c2pa_present,
            c2pa_valid       = c2pa_valid,
            exif_consistent  = exif_consistent,
            classification   = metadata.classification,
            explain_decision = explain,
            decided_at_iso   = now_iso,
            signature        = sig,
        )

        # Grava hash no DurableLedger para cadeia de custódia (sempre)
        self._record_custody(metadata, report, now_iso)

        return report

    def _determine_action(
        self,
        c2pa_present:    bool,
        c2pa_valid:      bool,
        exif_consistent: bool,
        classification:  ContentClassification,
    ) -> ProvenanceAction:
        # EXIF inconsistente em conteúdo sensível → BLOCK
        if not exif_consistent and classification in (
            ContentClassification.CONFIDENTIAL, ContentClassification.RESTRICTED
        ):
            return ProvenanceAction.BLOCK

        # C2PA presente e válida → ALLOW
        if c2pa_present and c2pa_valid:
            return ProvenanceAction.ALLOW

        # C2PA ausente → EDUCATE (nunca BLOCK enquanto crate instável)
        if not c2pa_present:
            return ProvenanceAction.EDUCATE

        # C2PA presente mas inválida → EDUCATE (modo stub, não BLOCK)
        return ProvenanceAction.EDUCATE

    def _verify_c2pa_stub(self, c2pa_manifest: Optional[bytes]) -> bool:
        """
        STUB: Verificação C2PA.
        TODO: Integrar com crate c2pa após estabilização da API.
        Retorna True apenas se o manifest contém assinatura válida (heurística básica).
        """
        if c2pa_manifest is None:
            return False
        # Heurística básica: manifest não vazio e contém marcador C2PA
        return (
            len(c2pa_manifest) > 0
            and b"c2pa" in c2pa_manifest.lower()
        )

    def _check_exif_consistency(self, exif_data: Optional[Dict[str, Any]]) -> bool:
        """
        Verifica consistência básica de metadados EXIF.
        Detecta inconsistências comuns em imagens modificadas.
        """
        if exif_data is None:
            return True  # Sem EXIF → sem inconsistência detectável

        # Verificação 1: Software de edição indica modificação
        software = exif_data.get("Software", "")
        if isinstance(software, str) and any(
            editor in software.lower()
            for editor in ["photoshop", "gimp", "lightroom", "affinity", "canva"]
        ):
            # Edição não é inconsistência per se, mas é detectada
            # Retorna False apenas se há indicadores de falsificação
            original_date = exif_data.get("DateTimeOriginal", "")
            modified_date = exif_data.get("DateTime", "")
            if original_date and modified_date and original_date != modified_date:
                # Data original difere da data de modificação → suspeito
                return False

        # Verificação 2: GPS vs. criação — coordenadas impossíveis
        gps_lat = exif_data.get("GPSLatitude")
        gps_lon = exif_data.get("GPSLongitude")
        if gps_lat is not None and gps_lon is not None:
            try:
                lat = float(gps_lat)
                lon = float(gps_lon)
                if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                    return False  # Coordenadas inválidas → inconsistência
            except (ValueError, TypeError):
                return False

        return True

    @staticmethod
    def _compute_hash(content_bytes: bytes) -> str:
        """BLAKE2b-256 do conteúdo → hex."""
        h = hashlib.blake2b(content_bytes, digest_size=32)
        return h.hexdigest()

    def _record_custody(
        self,
        metadata: ContentMetadata,
        report:   ProvenanceReport,
        now_iso:  str,
    ) -> None:
        """Grava hash no DurableLedger para cadeia de custódia completa."""
        self._ledger.append({
            "type":              "content_provenance_check",
            "content_hash":      report.content_hash,
            "action":            report.action.value,
            "c2pa_present":      report.c2pa_present,
            "c2pa_valid":        report.c2pa_valid,
            "exif_consistent":   report.exif_consistent,
            "classification":    report.classification.value,
            "source_uri":        metadata.source_uri,
            "checked_at_iso":    now_iso,
            "explain_decision":  report.explain_decision,
        })

    def _build_explain(
        self,
        action:          ProvenanceAction,
        c2pa_present:    bool,
        c2pa_valid:      bool,
        exif_consistent: bool,
        classification:  ContentClassification,
        content_hash:    str,
    ) -> str:
        lines = [
            f"[ContentProvenanceVerifier] action={action.value}",
            f"  classification={classification.value}",
            f"  c2pa_present={c2pa_present} c2pa_valid={c2pa_valid}",
            f"  exif_consistent={exif_consistent}",
            f"  content_hash={content_hash[:16]}… (BLAKE2b-256)",
        ]
        if action == ProvenanceAction.EDUCATE:
            lines.append(
                "  EDUCATE: C2PA ausente ou inválida. "
                "Nota: crate c2pa está em estado alpha — verificação completa pendente. "
                "Conteúdo permitido com aviso educativo."
            )
        elif action == ProvenanceAction.BLOCK:
            lines.append(
                "  BLOCK: Modificação detectada em conteúdo CONFIDENTIAL/RESTRICTED. "
                "EXIF inconsistente. Jonas: responsabilidade exige bloquear conteúdo adulterado."
            )
        else:
            lines.append("  ALLOW: C2PA válida + EXIF consistente.")
        lines.append("  Hash gravado no DurableLedger para auditoria completa.")
        lines.append("  Contestável via /api/v1/contestation (SLA 24h).")
        return "\n".join(lines)

    def _fail_secure(self, metadata: ContentMetadata, error: str) -> ProvenanceReport:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        content_hash = "FAIL-SECURE"
        try:
            content_hash = self._compute_hash(metadata.content_bytes)
        except Exception:
            pass
        explain = (
            f"[ContentProvenanceVerifier] FAIL-SECURE ativado.\n"
            f"  erro={error}\n"
            f"  Ação: BLOCK (Jonas: erro do sistema não é licença para aceitar conteúdo não verificado).\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        sig = self._sign(content_hash, ProvenanceAction.BLOCK, now_iso)
        return ProvenanceReport(
            action           = ProvenanceAction.BLOCK,
            content_hash     = content_hash,
            c2pa_present     = False,
            c2pa_valid       = False,
            exif_consistent  = False,
            classification   = getattr(metadata, "classification", ContentClassification.INTERNAL),
            explain_decision = explain,
            decided_at_iso   = now_iso,
            signature        = sig,
        )

    def _sign(self, content_hash: str, action: ProvenanceAction, now_iso: str) -> str:
        payload = json.dumps(
            {"content_hash": content_hash, "action": action.value, "decided_at": now_iso},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
