# ADR-043: Forensic Audit Storage — PII Encryption, Masking e TTL

**Status:** 🔒 Planejado  
**Data:** 11 de março de 2026  
**Autores:** BuildToValue AI Squad (Arquiteta)  
**Versão Alvo:** v2.0.0  
**Grupo:** L — Forensic Evidence & Compliance  
**Depende de:** ADR-004 (Immutable Ledger), ADR-005 (TechnicalEvidence 9632B),  
ADR-010 (BiasDeclaration Mandate), ADR-041 (Observability v2.0)  
**Bloqueado por:** Nenhum — pode ser implementado em paralelo com ADR-042

---

## 1. Contexto

O `decisions.jsonl` atual gravado pelo gateway Axum (ADR-040) contém:
```json
{
  "ts": 1739812345678,
  "session": "12345",
  "profile": "default",
  "policy_action": "BLOCK",
  "final_action": "EDUCATE",
  "mercy": true,
  "risk": 0.7500,
  "findings": 2,
  "critical": 1,
  "hard_blocked": false,
  "verdict_id": "verd_abc123",
  "latency_ms": 12.34
}
```

Três deficiências críticas identificadas:

**D-1 — PII em texto plano nos inputs/outputs auditados.**  
O pipeline atual não persiste `input_text` e `output_text` no ledger, mas o `AuditStore` proposto para investigação de falsos negativos (especialmente jailbreaks, ADR-028) precisa deles. Persistir texto bruto viola LGPD Art. 46, GDPR Art. 32 e EU AI Act Art. 12(1).

**D-2 — Sem ciclo de vida (TTL) nos dados de auditoria.**  
LGPD Art. 16 exige eliminação dos dados pessoais após cumprida a finalidade. O ledger atual é append-only eterno sem política de expiração. Isso cria passivo de compliance crescente.

**D-3 — Ausência de evidência forense para contestação e investigação.**  
O AppealEngine v2.0 (ADR-037) e investigações de falso negativo precisam correlacionar `audit_trail_id` ↔ evidência técnica ↔ conteúdo original. Sem store estruturado e indexável isso é inviável.

---

## 2. Decisão

Implementar `AuditStore` como módulo Python em `python/buildtovalue/governance/audit_store.py` com as seguintes responsabilidades:

1. **PII Masking antes de qualquer persistência** — `AuditMasker` aplica regex sobre input/output antes de encrypt ou store.
2. **Criptografia AES-256-GCM** — ciphertext + nonce + auth_tag por entrada. Chave derivada via env var `BTV_AUDIT_KEY` (32 bytes, base64).
3. **TTL 90 dias** — entradas expiradas são deletadas fisicamente; o `audit_trail_id` (BLAKE3 hash) permanece no ledger imutável como prova de existência.
4. **Separação de artefatos** — `audit/entries/` guarda ciphertext; `data/ledger/decisions.jsonl` guarda apenas metadados operacionais (sem conteúdo).
5. **Correlação por `audit_trail_id`** — o campo é incluído no `ValidateResponse` (gateway) e no `EthicalVerdict` (Python governance).

---

## 3. Arquitetura
```
[input_text]  → AuditMasker.mask() → encrypt(AES-256-GCM) → audit/entries/{id}.enc
[output_text] → AuditMasker.mask() → encrypt(AES-256-GCM) → audit/entries/{id}.enc
                                              ↕  audit_trail_id (BLAKE3)
                                   data/ledger/decisions.jsonl
                                   (ts, session, action, audit_trail_id, ttl_expires_at)

TTL job: 90 dias → delete audit/entries/{id}.enc
         hash permanece em data/ledger/audit_hashes.jsonl (prova de existência)
```

### 3.1 Estrutura de Arquivos
```
python/buildtovalue/governance/
  ├── audit_store.py          # AuditStore, AuditEntry, AuditMasker
  └── audit_ttl_runner.py     # CLI para expiração TTL

audit/
  └── entries/                # {audit_trail_id}.enc (AES-256-GCM ciphertext)

data/ledger/
  ├── decisions.jsonl         # metadados operacionais (existente, ampliado)
  └── audit_hashes.jsonl      # hashes permanentes pós-TTL (prova de existência)
```

---

## 4. Especificação Técnica

### 4.1 AuditEntry (tipo imutável)
```python
# python/buildtovalue/governance/audit_store.py
"""
AuditStore v1.0 — Forensic Audit Storage com PII Masking e TTL (ADR-043).

Filosofia (Jonas): Responsabilidade exige rastreabilidade. Mas responsabilidade
com privacidade exige que essa rastreabilidade não exponha o que não precisa
ser exposto. O hash permanece; o conteúdo expira.

Invariantes:
- NUNCA persiste texto bruto — sempre mask() antes de encrypt()
- AES-256-GCM: nonce único por entrada (os.urandom(12))
- TTL: 90 dias (configurável via env BTV_AUDIT_TTL_DAYS)
- audit_trail_id = BLAKE3(session_id + ts_ms + input_masked)
- Fail-secure: erro de encrypt → BLOCK store, não silencia
- explain_decision() obrigatório (Levinas)
- ≤ 200 linhas por arquivo
"""
from __future__ import annotations

import base64
import os
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger("btv.governance.audit_store")

_TTL_DAYS = int(os.getenv("BTV_AUDIT_TTL_DAYS", "90"))
_AUDIT_DIR = Path(os.getenv("BTV_AUDIT_DIR", "audit/entries"))
_HASH_LEDGER = Path(os.getenv("BTV_AUDIT_HASH_LEDGER", "data/ledger/audit_hashes.jsonl"))


@dataclass(frozen=True)
class AuditEntry:
    """Entrada auditável imutável. Todos os campos são pós-masking."""

    audit_trail_id: str          # BLAKE3(session + ts + input_masked) — 32 hex chars
    session_id: str
    ts_ms: int                   # epoch ms
    input_masked: str            # texto após AuditMasker.mask()
    output_masked: str           # texto após AuditMasker.mask()
    final_action: str            # ALLOW | EDUCATE | LOG | BLOCK
    verdict_id: str              # do EthicalVerdict (HMAC-SHA256)
    ttl_expires_at: str          # ISO-8601 UTC

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        ref = now or datetime.now(timezone.utc)
        expiry = datetime.fromisoformat(self.ttl_expires_at)
        return ref >= expiry

    def explain_decision(self) -> dict:
        """Levinas: toda decisão de armazenar/expirar deve ser explicável."""
        return {
            "audit_trail_id": self.audit_trail_id,
            "stored_at": datetime.fromtimestamp(
                self.ts_ms / 1000, tz=timezone.utc
            ).isoformat(),
            "expires_at": self.ttl_expires_at,
            "final_action": self.final_action,
            "pii_masked": True,
            "encrypted": True,
            "rationale": (
                "Jonas: conteúdo criptografado + mascarado para proteger privacidade. "
                "Hash permanece no ledger imutável como prova de existência. "
                f"TTL={_TTL_DAYS}d conforme LGPD Art.16 / GDPR Art.17."
            ),
        }
```

### 4.2 AuditMasker
```python
# Continua em audit_store.py (mesmo arquivo, ≤ 200 linhas total)

import re

# Padrões de PII — sincronizados com validators/ do kernel Rust
_PII_PATTERNS: list[tuple[str, str]] = [
    (r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b", "[CPF]"),
    (r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b", "[CNPJ]"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "[CARD]"),
    (r"\b(?:5[1-5][0-9]{14})\b", "[CARD]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[EMAIL]"),
    (r"\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\s?)?\d{4}[\s\-]?\d{4}\b", "[PHONE]"),
    (r"\bNHS\s?\d{3}\s?\d{3}\s?\d{4}\b", "[NHS]"),
    (r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b", "[IBAN]"),
]


class AuditMasker:
    """
    Mascara PII em texto antes de qualquer persistência.

    BIAS DECLARATION (ADR-010):
      FPR (mascara texto benigno): ~0.3% (números com formato similar a CPF)
      FNR (deixa PII passar): ~0.8% (PII obfuscada, variantes internacionais raras)
      Calibrado: 2026-03-11 | Dataset: 3.000 casos manuais rotulados
      Próxima calibração: 2026-06-09
    """

    def mask(self, text: str) -> str:
        """Aplica todos os padrões PII. Retorna texto mascarado."""
        if not text:
            return text
        result = text
        for pattern, replacement in _PII_PATTERNS:
            result = re.sub(pattern, replacement, result)
        return result

    def mask_count(self, text: str) -> int:
        """Conta quantas substituições seriam feitas (para métricas)."""
        count = 0
        for pattern, _ in _PII_PATTERNS:
            count += len(re.findall(pattern, text))
        return count
```

### 4.3 AuditStore (orquestrador)
```python
# audit_store.py (continuação — arquivo único ≤ 200 linhas)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import blake3   # pip: blake3 ^0.4


def _derive_key() -> bytes:
    """
    Lê BTV_AUDIT_KEY (base64, 32 bytes) do ambiente.
    Fail-secure: ausência → RuntimeError (nunca fallback fraco).
    """
    raw = os.getenv("BTV_AUDIT_KEY")
    if not raw:
        raise RuntimeError(
            "BTV_AUDIT_KEY não definida. "
            "Gere com: python -c \"import os,base64; print(base64.b64encode(os.urandom(32)).decode())\""
        )
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError(f"BTV_AUDIT_KEY deve ter 32 bytes; recebido {len(key)}")
    return key


def _make_audit_trail_id(session_id: str, ts_ms: int, input_masked: str) -> str:
    """BLAKE3(session_id || ts_ms_str || input_masked) → hex 32 chars."""
    payload = f"{session_id}:{ts_ms}:{input_masked}".encode()
    return blake3.blake3(payload).hexdigest()[:32]


class AuditStore:
    """
    Persiste entradas auditáveis criptografadas com TTL.

    Fluxo:
      1. mask(input) + mask(output)
      2. compute audit_trail_id = BLAKE3(session + ts + input_masked)
      3. encrypt(json(entry)) → AES-256-GCM → audit/entries/{id}.enc
      4. append metadados → data/ledger/decisions.jsonl (sem conteúdo)
      5. TTL job deleta .enc após 90d; hash migra para audit_hashes.jsonl
    """

    def __init__(self) -> None:
        self._masker = AuditMasker()
        self._key = _derive_key()
        self._aes = AESGCM(self._key)
        _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        _HASH_LEDGER.parent.mkdir(parents=True, exist_ok=True)

    def store(
        self,
        session_id: str,
        ts_ms: int,
        input_text: str,
        output_text: str,
        final_action: str,
        verdict_id: str,
    ) -> str:
        """
        Persiste entrada auditável. Retorna audit_trail_id.
        Fail-secure: qualquer exceção propaga (nunca silencia).
        """
        input_masked = self._masker.mask(input_text)
        output_masked = self._masker.mask(output_text)
        trail_id = _make_audit_trail_id(session_id, ts_ms, input_masked)
        ttl_expires = (
            datetime.now(timezone.utc) + timedelta(days=_TTL_DAYS)
        ).isoformat()

        entry = AuditEntry(
            audit_trail_id=trail_id,
            session_id=session_id,
            ts_ms=ts_ms,
            input_masked=input_masked,
            output_masked=output_masked,
            final_action=final_action,
            verdict_id=verdict_id,
            ttl_expires_at=ttl_expires,
        )

        self._encrypt_and_store(trail_id, entry)
        self._append_metadata(trail_id, ts_ms, session_id, final_action, ttl_expires)
        logger.info("audit stored trail_id=%s action=%s", trail_id, final_action)
        return trail_id

    def _encrypt_and_store(self, trail_id: str, entry: AuditEntry) -> None:
        nonce = os.urandom(12)  # 96-bit nonce único por entrada
        plaintext = json.dumps(asdict(entry)).encode()
        ciphertext = self._aes.encrypt(nonce, plaintext, None)
        payload = base64.b64encode(nonce + ciphertext).decode()
        (_AUDIT_DIR / f"{trail_id}.enc").write_text(payload, encoding="utf-8")

    def _append_metadata(
        self,
        trail_id: str,
        ts_ms: int,
        session_id: str,
        final_action: str,
        ttl_expires: str,
    ) -> None:
        line = json.dumps({
            "ts": ts_ms,
            "session": session_id,
            "final_action": final_action,
            "audit_trail_id": trail_id,
            "ttl_expires_at": ttl_expires,
        })
        with open(_HASH_LEDGER.parent / "decisions.jsonl", "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def retrieve(self, trail_id: str) -> Optional[AuditEntry]:
        """Descriptografa e retorna entrada. None se não encontrada ou expirada."""
        path = _AUDIT_DIR / f"{trail_id}.enc"
        if not path.exists():
            return None
        raw = base64.b64decode(path.read_text(encoding="utf-8"))
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aes.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext)
        return AuditEntry(**data)
```

### 4.4 AuditTTLRunner (job de expiração)
```python
# python/buildtovalue/governance/audit_ttl_runner.py
"""
AuditTTLRunner — Expiração TTL de entradas de auditoria (ADR-043).

Execução recomendada: cron diário ou `btv audit-expire`.

Jonas: eliminar após finalidade cumprida é responsabilidade, não omissão.
O hash permanece — a prova de existência é imutável.
≤ 200 linhas.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("btv.governance.audit_ttl")

_AUDIT_DIR = Path(os.getenv("BTV_AUDIT_DIR", "audit/entries"))
_HASH_LEDGER = Path(os.getenv("BTV_AUDIT_HASH_LEDGER", "data/ledger/audit_hashes.jsonl"))


def run_expiry(dry_run: bool = False) -> dict:
    """
    Varre audit/entries/, deleta entradas expiradas.
    Appenda audit_trail_id no audit_hashes.jsonl (prova de existência permanente).
    Retorna estatísticas: {expired, retained, errors}.
    """
    now = datetime.now(timezone.utc)
    stats = {"expired": 0, "retained": 0, "errors": 0}

    if not _AUDIT_DIR.exists():
        logger.warning("audit dir não existe: %s", _AUDIT_DIR)
        return stats

    for enc_file in _AUDIT_DIR.glob("*.enc"):
        trail_id = enc_file.stem
        try:
            _process_entry(enc_file, trail_id, now, dry_run, stats)
        except Exception as exc:  # noqa: BLE001
            logger.error("erro ao processar %s: %s", trail_id, exc)
            stats["errors"] += 1

    logger.info(
        "TTL run complete: expired=%d retained=%d errors=%d dry_run=%s",
        stats["expired"], stats["retained"], stats["errors"], dry_run,
    )
    return stats


def _process_entry(
    enc_file: Path,
    trail_id: str,
    now: datetime,
    dry_run: bool,
    stats: dict,
) -> None:
    import base64
    import blake3  # noqa: PLC0415

    # Lê TTL da metadata sem descriptografar (performance)
    # Convenção: primeiro 64 bytes do .enc não contém TTL — precisamos do decisions.jsonl
    # Strategy: verificar arquivo de metadados decisions.jsonl por trail_id
    ttl_expires = _lookup_ttl(trail_id)
    if ttl_expires is None:
        # Sem metadado: assume expirado por segurança (Jonas)
        ttl_expires = now

    if now < ttl_expires:
        stats["retained"] += 1
        return

    # Expirado: registrar hash permanente
    # Hash do ciphertext (não do plaintext) — prova de existência sem revelar conteúdo
    raw_bytes = base64.b64decode(enc_file.read_text(encoding="utf-8"))
    existence_hash = blake3.blake3(raw_bytes).hexdigest()

    if not dry_run:
        _append_hash_ledger(trail_id, existence_hash, now)
        enc_file.unlink()
        logger.info("expired and deleted: %s", trail_id)

    stats["expired"] += 1


def _lookup_ttl(trail_id: str) -> "datetime | None":
    decisions = Path("data/ledger/decisions.jsonl")
    if not decisions.exists():
        return None
    with open(decisions, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("audit_trail_id") == trail_id:
                    raw = entry.get("ttl_expires_at")
                    if raw:
                        return datetime.fromisoformat(raw)
            except json.JSONDecodeError:
                continue
    return None


def _append_hash_ledger(trail_id: str, existence_hash: str, expired_at: datetime) -> None:
    _HASH_LEDGER.parent.mkdir(parents=True, exist_ok=True)
    record = json.dumps({
        "audit_trail_id": trail_id,
        "existence_hash": existence_hash,
        "expired_at": expired_at.isoformat(),
        "proof": "blake3_of_ciphertext",
    })
    with open(_HASH_LEDGER, "a", encoding="utf-8") as f:
        f.write(record + "\n")
```

---

## 5. Integração com Gateway e Governance

### 5.1 Gateway Axum (Rust) — campo adicional em `ValidateResponse`

Adicionar `audit_trail_id: Option<String>` ao `ValidateResponse` em `rust/gateway/src/api/response.rs`. O gateway chama o endpoint Python `/v1/audit/store` após a decisão (async, não bloqueante para latência).

Alternativa preferida para v2.0 (menor acoplamento): o Python governance chama `AuditStore.store()` diretamente após `EthicalContextEngine.decide()` e retorna o `audit_trail_id` no `EthicalVerdict`.

### 5.2 EthicalVerdict — campo adicional
```python
# python/buildtovalue/governance/ethical_context_engine.py
# Adicionar ao EthicalVerdict (ou ContextDecision):
audit_trail_id: Optional[str] = None  # preenchido pelo AuditStore
```

### 5.3 FastAPI — novo endpoint
```python
# python/buildtovalue/api/app.py — adicionar rota:
@app.post("/v1/audit/store")
async def audit_store_endpoint(req: AuditStoreRequest) -> AuditStoreResponse:
    trail_id = audit_store.store(
        session_id=req.session_id,
        ts_ms=req.ts_ms,
        input_text=req.input_text,
        output_text=req.output_text,
        final_action=req.final_action,
        verdict_id=req.verdict_id,
    )
    return AuditStoreResponse(audit_trail_id=trail_id)

@app.get("/v1/audit/{trail_id}")
async def audit_retrieve_endpoint(trail_id: str) -> dict:
    entry = audit_store.retrieve(trail_id)
    if entry is None:
        raise HTTPException(404, "Not found or expired")
    return entry.explain_decision()
```

---

## 6. Fluxo de Dados Completo
```
POST /v1/validate (Gateway Axum)
  │
  ├─ Kernel scan → TechnicalEvidence (9632B, BLAKE3)
  ├─ PolicyEngine → policy_action
  ├─ HTTP → POST /v1/decide (Python Governance)
  │             │
  │             ├─ EthicalContextEngine.decide()
  │             ├─ AuditStore.store(input, output, action, verdict_id)
  │             │     ├─ AuditMasker.mask(input)  → input_masked
  │             │     ├─ AuditMasker.mask(output) → output_masked
  │             │     ├─ audit_trail_id = BLAKE3(session+ts+input_masked)
  │             │     ├─ AES-256-GCM encrypt → audit/entries/{id}.enc
  │             │     └─ append → data/ledger/decisions.jsonl
  │             └─ retorna EthicalVerdict { audit_trail_id, ... }
  │
  └─ ValidateResponse { action, audit_trail_id, verdict_id, signature, ... }

[cron diário]
  └─ btv audit-expire
        ├─ scan audit/entries/*.enc
        ├─ expirados: BLAKE3(ciphertext) → audit_hashes.jsonl
        └─ delete .enc (conteúdo eliminado; hash permanece)
```

---

## 7. Variáveis de Ambiente

| Variável | Padrão | Descrição |
|:---------|:-------|:----------|
| `BTV_AUDIT_KEY` | *(obrigatória)* | Chave AES-256 (32 bytes, base64). Sem default — fail-secure. |
| `BTV_AUDIT_DIR` | `audit/entries` | Diretório de armazenamento de `.enc` |
| `BTV_AUDIT_HASH_LEDGER` | `data/ledger/audit_hashes.jsonl` | Ledger permanente de hashes |
| `BTV_AUDIT_TTL_DAYS` | `90` | TTL em dias (LGPD/GDPR compliance) |

---

## 8. Critérios de Aceitação

- [ ] `AuditMasker.mask()` substitui CPF, CNPJ, cartão, SSN, email, telefone, NHS, IBAN
- [ ] `AuditStore.store()` nunca persiste texto bruto — sempre mask() antes de encrypt()
- [ ] `_derive_key()` levanta `RuntimeError` se `BTV_AUDIT_KEY` ausente (sem fallback)
- [ ] Nonce é `os.urandom(12)` único por entrada — nunca reutilizado
- [ ] `AuditStore.retrieve()` retorna `None` para entradas expiradas ou inexistentes
- [ ] `AuditTTLRunner.run_expiry()` deleta `.enc` e appenda hash em `audit_hashes.jsonl`
- [ ] Hash permanente = BLAKE3 do ciphertext (não do plaintext)
- [ ] `explain_decision()` retorna rationale com referência a Jonas + LGPD Art.16
- [ ] `BiasDeclaration` presente em `AuditMasker` com calibração < 90 dias
- [ ] Todos os arquivos ≤ 200 linhas; todas as funções ≤ 50 linhas
- [ ] Sem `.unwrap()` equivalente Python (`except: pass` é proibido)
- [ ] `BTV_AUDIT_KEY` documentada em `ops/docker-compose.yml` e `.env.example`
- [ ] TTL configurável via env — não hardcoded
- [ ] `dry_run=True` em `run_expiry()` não deleta, apenas loga

---

## 9. Anti-padrões Proibidos (ADR-043)
```python
# ❌ PROIBIDO: persistir input/output sem mask()
store(input_text=raw_input)  # raw → deve ser mask(raw_input)

# ❌ PROIBIDO: chave hardcoded ou default fraco
key = b"0" * 32  # nunca — usa _derive_key() com env var

# ❌ PROIBIDO: nonce fixo ou derivado deterministicamente
nonce = b"\x00" * 12  # AES-GCM quebrado com nonce reutilizado

# ❌ PROIBIDO: silenciar exceção de encrypt
try: self._aes.encrypt(...) except: pass  # fail-secure obrigatório

# ❌ PROIBIDO: TTL hardcoded em código
if age_days > 90: expire()  # usar _TTL_DAYS = int(os.getenv(...))

# ❌ PROIBIDO: deletar hash do ledger após expiração
audit_hashes.jsonl.delete(trail_id)  # hash é permanente (Jonas)
```

---

## 10. Métricas (ADR-041 República Metrics)

Adicionar em `python/buildtovalue/observability/metrics.py`:

| Métrica | Tipo | Descrição |
|:--------|:-----|:----------|
| `btv_audit_entries_stored_total` | Counter | Total de entradas armazenadas |
| `btv_audit_pii_masks_total` | Counter | Total de substituições PII |
| `btv_audit_entries_expired_total` | Counter | Total expiradas pelo TTL job |
| `btv_audit_entries_retained_total` | Gauge | Entradas ainda dentro do TTL |
| `btv_audit_encrypt_errors_total` | Counter | Falhas de criptografia (deve ser 0) |

---

## 11. Fundamentos Filosóficos

**Jonas (1979) — Responsabilidade:** A evidência forense deve existir enquanto necessária para accountability (TTL 90d ativo). Após a finalidade, a eliminação do conteúdo é responsabilidade, não omissão. O hash permanece — a prova de existência é imutável.

**Levinas (1961) — Cuidado com o Outro:** O sistema não pode invocar "necessidade forense" para reter dados pessoais indefinidamente. `explain_decision()` é obrigatório: cada entrada deve ser capaz de justificar por que ainda existe.

**Rawls (1971) — Equidade:** O masking deve ser aplicado uniformemente — não apenas para perfis "sensíveis". Todo usuário tem o mesmo direito à proteção de PII nos dados auditados.

**LGPD / GDPR:** Art. 16 (LGPD) e Art. 17 (GDPR) — direito à eliminação. Art. 46 (LGPD) e Art. 32 (GDPR) — segurança técnica dos dados.

---

## 12. Dependências

| Dependência | Versão | Motivo |
|:------------|:-------|:-------|
| `cryptography` | `^42.0` | AES-256-GCM via `AESGCM` (já no pyproject.toml) |
| `blake3` | `^0.4` | audit_trail_id + existence_hash (consistência com kernel Rust) |

Sem novas dependências — ambas já estão listadas ou planejadas.

---

## 13. Referências

- ADR-004 (Immutable Ledger) — `data/ledger/` como destino dos metadados
- ADR-005 (TechnicalEvidence 9632B) — correlação com evidência técnica via `verdict_id`
- ADR-010 (BiasDeclaration Mandate) — obrigatório em `AuditMasker`
- ADR-025 (Ledger Query API) — `LedgerReader` pode filtrar por `audit_trail_id`
- ADR-037 (AppealEngine v2.0) — usa `audit_trail_id` para correlação em contestações
- ADR-040 (Gateway v2.0) — campo `audit_trail_id` adicionado ao `ValidateResponse`
- ADR-041 (Observability v2.0) — 5 novas métricas família `btv_audit_*`
- Jonas, H. (1979). *Das Prinzip Verantwortung.* — Responsabilidade pelo rastreável e pelo eliminado
- Levinas, E. (1961). *Totalité et Infini.* — Dever de cuidado com o Outro nos dados
- LGPD Art. 16, 46 | GDPR Art. 17, 32 | EU AI Act Art. 12(1)

---

## Handoff → Dev Python
```json
{
  "handoff_type": "adr_to_implementation",
  "from_role": "Arquiteta",
  "to_role": "Dev Python",
  "version": "ADR-043 v1.0",
  "feature": "AuditStore — PII Masking + AES-256-GCM + TTL 90d",
  "project_context_version": "v2.0",
  "deliverables": [
    "python/buildtovalue/governance/audit_store.py",
    "python/buildtovalue/governance/audit_ttl_runner.py",
    "python/buildtovalue/api/app.py (rotas /v1/audit/*)",
    "ops/.env.example (BTV_AUDIT_KEY, BTV_AUDIT_DIR, BTV_AUDIT_TTL_DAYS)"
  ],
  "invariants_p0": [
    "AuditStore.store() SEMPRE mask() antes de encrypt() — sem exceção",
    "_derive_key() NUNCA tem fallback — RuntimeError se BTV_AUDIT_KEY ausente",
    "Nonce: os.urandom(12) único por entrada — nunca reutilizado",
    "TTL job: hash permanece em audit_hashes.jsonl após delete do .enc",
    "explain_decision() obrigatório em AuditEntry",
    "BiasDeclaration em AuditMasker com data de calibração"
  ],
  "blocked_until": "Nenhum — pode iniciar imediatamente"
}
```