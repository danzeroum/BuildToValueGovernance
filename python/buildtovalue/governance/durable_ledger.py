"""
DurableLedger v1.1.0 — Immutable Audit Ledger
Algorithmic Republic — Auditivo Branch (ADR-0051)

Invariantes:
  - Append-only: sem deleção, sem mutação de entradas existentes
  - Chain hash: H(n) = BLAKE2b(H(n-1) || json_sorted(payload_n))
  - HMAC-SHA256: autenticidade de cada entrada (Jonas: responsabilidade)
  - explain_decision obrigatório em toda entrada (Levinas: transparência)
  - Genesis: H(0) = BLAKE2b(BTV-LEDGER-GENESIS-v1.0)
  - Thread-safe: threading.Lock em append() e verify()

Changelog v1.1.0 (Sprint 2, Gap 8):
  - _verify_locked() agora verifica entry.prev_hash contra prev_hash_bytes
    antes de qualquer outra checagem. Adulteração do campo prev_hash era
    silenciosa em v1.0.0.

NOTE: BLAKE2b (stdlib) é usado como substituto de BLAKE3 até integração
com o kernel Rust (ADR-0051 §4). Migração sem mudança de API.
"""

import hashlib
import hmac as hmac_mod
import json
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ─── Constantes imutáveis ──────────────────────────────────────────────────────────────────

GENESIS_SEED: bytes = b"BTV-LEDGER-GENESIS-v1.0"
BLAKE2B_DIGEST_SIZE: int = 32  # 256 bits


# ─── Funções de hash puro ───────────────────────────────────────────────────────────────

def _genesis_hash() -> bytes:
    """Hash determinístico do bloco genesis."""
    return hashlib.blake2b(GENESIS_SEED, digest_size=BLAKE2B_DIGEST_SIZE).digest()


def _chain_hash(prev_hash: bytes, payload_bytes: bytes) -> bytes:
    """BLAKE2b(prev_hash || payload_bytes) — integridade da cadeia."""
    h = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
    h.update(prev_hash)
    h.update(payload_bytes)
    return h.digest()


# ─── Dataclasses ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LedgerEntry:
    """
    Entrada imutável no ledger.

    Frozen: qualquer tentativa de mutação levanta AttributeError.
    explain_decision no payload garante rastreabilidade (Levinas).
    """
    sequence:        int              # monotônico a partir de 1
    entry_hash:      str              # hex BLAKE2b(prev_hash || payload)
    prev_hash:       str              # hex do hash anterior (ou genesis)
    payload:         Dict[str, Any]   # deve conter 'explain_decision'
    hmac_sha256:     str              # HMAC-SHA256(sequence || entry_hash || iso)
    recorded_at_iso: str              # UTC ISO 8601 com sufixo Z


@dataclass
class LedgerVerification:
    """
    Resultado de verificação de integridade do ledger.

    valid=False implica adulteração ou corrupção a partir de
    first_invalid_sequence.
    """
    valid:                   bool
    entries_checked:         int
    first_invalid_sequence:  Optional[int] = None
    reason:                  Optional[str] = None


# ─── DurableLedger ───────────────────────────────────────────────────────────────────

class DurableLedger:
    """
    Ledger imutável para auditoria de decisões éticas (ADR-0051).

    Uso:
        ledger = DurableLedger(hmac_key=key)
        entry  = ledger.append({
            "decision_id": "DEC-abc",
            "explain_decision": unified_decision.to_audit_dict(),
        })
        result = ledger.verify()
    """

    def __init__(self, hmac_key: bytes) -> None:
        self._hmac_key:        bytes              = hmac_key
        self._entries:         List[LedgerEntry]  = []
        self._lock:            threading.Lock     = threading.Lock()
        self._prev_hash_bytes: bytes              = _genesis_hash()

    # ── API pública ─────────────────────────────────────────────────────────────────

    def append(self, payload: Dict[str, Any]) -> LedgerEntry:
        """
        Appende entrada ao ledger de forma thread-safe.

        Args:
            payload: deve conter chave 'explain_decision' (Levinas).

        Returns:
            LedgerEntry frozen com hash e HMAC calculados.

        Raises:
            ValueError: se 'explain_decision' ausente no payload.
        """
        if "explain_decision" not in payload:
            raise ValueError(
                "explain_decision obrigatório em toda entrada do ledger (Levinas/ADR-0051)"
            )
        with self._lock:
            return self._append_locked(payload)

    def verify(self) -> LedgerVerification:
        """
        Verifica integridade de toda a cadeia (prev_hash + chain hash + HMAC).

        Thread-safe. Complexidade O(n).
        """
        with self._lock:
            return self._verify_locked()

    def entries(self) -> Tuple[LedgerEntry, ...]:
        """Snapshot imutável (tuple) das entradas registradas."""
        with self._lock:
            return tuple(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # ── Internos ────────────────────────────────────────────────────────────────────

    def _append_locked(self, payload: Dict[str, Any]) -> LedgerEntry:
        sequence         = len(self._entries) + 1
        now_iso          = datetime.utcnow().isoformat() + "Z"
        payload_bytes    = json.dumps(payload, sort_keys=True, default=str).encode()
        entry_hash_bytes = _chain_hash(self._prev_hash_bytes, payload_bytes)
        entry_hash_hex   = entry_hash_bytes.hex()
        prev_hash_hex    = self._prev_hash_bytes.hex()
        hmac_sig         = self._sign(sequence, entry_hash_bytes, now_iso)

        entry = LedgerEntry(
            sequence        = sequence,
            entry_hash      = entry_hash_hex,
            prev_hash       = prev_hash_hex,
            payload         = payload,
            hmac_sha256     = hmac_sig,
            recorded_at_iso = now_iso,
        )
        self._entries.append(entry)
        self._prev_hash_bytes = entry_hash_bytes
        return entry

    def _verify_locked(self) -> LedgerVerification:
        prev_hash_bytes = _genesis_hash()
        for entry in self._entries:
            # Gap 8 (v1.1.0): verificar prev_hash antes de qualquer outra checagem.
            # Em v1.0.0 este campo era gravado mas nunca validado —
            # adulteração passava silenciosamente.
            if entry.prev_hash != prev_hash_bytes.hex():
                return LedgerVerification(
                    valid                  = False,
                    entries_checked        = entry.sequence - 1,
                    first_invalid_sequence = entry.sequence,
                    reason                 = (
                        f"prev_hash adulterado na entrada {entry.sequence}: "
                        f"esperado={prev_hash_bytes.hex()[:16]}… "
                        f"encontrado={entry.prev_hash[:16]}…"
                    ),
                )

            payload_bytes = json.dumps(
                entry.payload, sort_keys=True, default=str
            ).encode()
            expected_hash = _chain_hash(prev_hash_bytes, payload_bytes)

            if expected_hash.hex() != entry.entry_hash:
                return LedgerVerification(
                    valid                  = False,
                    entries_checked        = entry.sequence - 1,
                    first_invalid_sequence = entry.sequence,
                    reason                 = f"chain hash inválido na entrada {entry.sequence}",
                )

            expected_hmac = self._sign(entry.sequence, expected_hash, entry.recorded_at_iso)
            if not hmac_mod.compare_digest(expected_hmac, entry.hmac_sha256):
                return LedgerVerification(
                    valid                  = False,
                    entries_checked        = entry.sequence - 1,
                    first_invalid_sequence = entry.sequence,
                    reason                 = f"HMAC inválido na entrada {entry.sequence}",
                )

            prev_hash_bytes = expected_hash

        return LedgerVerification(
            valid           = True,
            entries_checked = len(self._entries),
        )

    def _sign(self, sequence: int, entry_hash: bytes, now_iso: str) -> str:
        """HMAC-SHA256(sequence_bytes || entry_hash || iso_bytes)."""
        mac = hmac_mod.new(self._hmac_key, digestmod=hashlib.sha256)
        mac.update(sequence.to_bytes(8, "big"))
        mac.update(entry_hash)
        mac.update(now_iso.encode())
        return mac.hexdigest()
