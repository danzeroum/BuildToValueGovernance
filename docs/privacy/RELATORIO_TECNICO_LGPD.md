# Relatório Técnico — Revisão LGPD & Privacy by Design

**Sistema:** BuildToValue (BTV) — Governança de Agentes de IA
**Commit auditado:** `ac6ac79`
**Data:** 2026-07-29
**Escopo:** backend (Rust + Python), frontend, infraestrutura, banco de dados, ML/LLM, integrações, documentação
**Norma de referência:** Lei 13.709/2018 (LGPD) + 7 Princípios de Privacy by Design (Cavoukian)

---

> ## ⚠️ Aviso de divulgação
>
> Este documento contém **descrições de vulnerabilidades não corrigidas** na data de emissão,
> incluindo cadeias de exploração completas com localização exata no código. Ele foi commitado
> com detalhe integral por decisão explícita do responsável pelo repositório.
>
> **Se você encontrou este documento e identificou uma instância do BTV exposta publicamente,
> não abra issue pública.** Reporte pelo canal do [`SECURITY.md`](../../SECURITY.md).
>
> Os riscos classificados como **P0** abaixo devem ser tratados antes de qualquer deploy que
> processe dados pessoais reais. Nenhum deles foi corrigido nesta entrega — esta é uma auditoria,
> não uma remediação.

---

## 1. Metodologia e escopo

### 1.1 O que foi revisado

| Superfície | Artefatos |
|---|---|
| Gateway Rust (Axum) | `rust/gateway/src/**` — 18 rotas, 6 middlewares, ledger JSONL |
| Kernel Rust | `rust/kernel/src/**` — validadores, evidência, ledger binário, WAL, FFI, chaves |
| Crates auxiliares | `btv-core`, `btv-sigma`, `btv-redaction`, `btv-judicial`, `btv-governance`, `btv-types` |
| API Python (FastAPI) | `python/buildtovalue/api/**` — 53 rotas, DTOs, auth, webhooks |
| Governança Python | `python/buildtovalue/governance/**` — ~70 módulos (política, contestabilidade, ledger, budget) |
| Inteligência / ML | `python/buildtovalue/intelligence/**` — NER, SLM, LLM clients, pipeline de treino |
| Compliance | `python/buildtovalue/compliance/**` — ROPA, FRIA, Art. 20, plugins |
| Frontend | `demo/**` (19 HTML + JS), `python/buildtovalue/dashboard/app.py`, `docs/ui-reference/**` |
| Infraestrutura | `ops/k8s/**`, `ops/nginx/**`, `ops/docker-compose*.yml`, Dockerfiles, `fly.toml` |
| CI/CD | `.github/workflows/**` (11 workflows), `.pre-commit-config.yaml`, `scripts/ci/lint_guards.sh` |
| Dados | 4 SQLite versionados, `data/policies/**`, `data/ner/**`, datasets de treino |
| Documentação | 98 ADRs, `docs/mapa-de-dados/**`, `docs/runbooks/**`, `docs/compliance.md`, `SECURITY.md` |

### 1.2 Método

Leitura estática do código-fonte com verificação direta de cada afirmação. Cada achado tem
âncora `arquivo:linha` e trecho literal do código. Nenhuma afirmação foi incluída sem que o
trecho correspondente fosse lido no commit auditado.

Onde o levantamento inicial divergiu da evidência primária, a **evidência primária prevaleceu**.
Três correções desse tipo estão documentadas na §5 — importam porque descrever um risco pior do
que ele é destrói a credibilidade dos outros 45.

### 1.3 Limites declarados

| Limite | Consequência |
|---|---|
| Clone raso (`.git/shallow`, 50 commits) | Não foi possível verificar o histórico completo do repositório. **R-048** depende de reexecução em clone integral. |
| Análise estática apenas | Nenhum ambiente foi executado. Achados de runtime (ex.: comportamento real sob `BTV_ENV=production`) são inferidos do código, não observados. |
| Sem acesso a ambientes reais | Não foi possível confirmar se as instâncias `demo.buildtovalue.cloud` / `docs.buildtovalue.io` estão no ar com a configuração do repositório. |

### 1.4 Papéis LGPD do BTV

O BTV ocupa **dois papéis simultâneos**, e a maior parte da documentação existente só reconhece o primeiro:

1. **Operador** (Art. 5º, VII) dos dados dos clientes — todo prompt interceptado por
   `/v1/proxy`, `/v1/decide` e `/v1/validate` é tratado por conta do controlador-cliente.
2. **Controlador** (Art. 5º, VI) do próprio site público — IP e User-Agent de visitantes
   (Google Fonts, Google Analytics), `localStorage`, `session_id`, histórico de vereditos.

Um achado no papel de operador se propaga para **todos** os controladores que adotam o BTV.

---

## 2. Sumário executivo

### 2.1 Contagem

| Severidade | Qtd. | Critério |
|---|---|---|
| **P0 — Crítico** | 10 | Viola artigo da LGPD de forma direta e explorável, ou torna inexistente um direito do titular |
| **P1 — Alto** | 17 | Ausência de controle exigido, ou controle presente mas contornável |
| **P2 — Médio** | 21 | Defeito de defesa em profundidade, inconsistência documental ou dívida de governança |
| **Total** | **48** | |

### 2.2 A observação estrutural

O achado mais importante desta auditoria não é nenhum risco isolado. É este:

> **O BTV aplica a terceiros regras que não aplica a si mesmo.**

O arquivo `data/policies/frameworks/lgpd_base.yaml:199` define, como violação a ser detectada
nos sistemas dos clientes:

```yaml
      (data.at_rest == true and storage.encrypted == false)
```

E as bases SQLite do próprio BTV — incluindo `explanations.full_data` (que grava `ip_address`)
e `appeal_records.explanation_text` — estão em texto claro no disco. Não há uma única chamada de
cifragem em todo o repositório (§R-002).

O mesmo padrão se repete em quatro eixos:

| O BTV exige do cliente | O BTV faz |
|---|---|
| Criptografia em repouso (`lgpd_base.yaml:199`) | Zero criptografia em repouso (**R-002**) |
| Base legal válida para dado sensível (`lgpd_base.yaml`, Art. 11) | Declara legítimo interesse para dado sensível no próprio ROPA (**R-010**) |
| Detecção e mascaramento de PII antes de processar (`docs/compliance.md:27`) | Grava input bruto de dado sensível no ledger imutável (**R-001**) |
| Governança sobre chamadas a LLM | Chama Anthropic/OpenAI/DeepSeek sem auditoria, sem detecção de PII, sem gate de DPA (**R-038**) |

### 2.3 Os cinco achados que mais importam

1. **R-001** — O validador do Art. 11 grava o **input bruto** no ledger *append-only*. O componente
   que existe para proteger dado sensível é o que o persiste em claro, para sempre, sem
   possibilidade de exclusão.
2. **R-003 + R-004** — Não existe expurgo e não existe nenhum endpoint de direito do titular.
   Pela regra do próprio escopo desta revisão: *o direito que não tem endpoint com prazo,
   autenticação e log não existe no sistema*. Nove dos nove incisos do Art. 18 estão ausentes.
3. **R-006 + R-007 + R-016** — Cadeia completa: qualquer origem obtém um JWT de `admin` via
   `POST /demo-login` sob CORS `*`; nenhuma rota verifica `role`; e qualquer path terminado em
   `.json` pula o `ApiKeyLayer` do gateway. Autenticação existe, autorização não.
4. **R-009 + R-010 + R-044** — Transferência internacional real (OpenAI/EUA, DeepSeek/China,
   `us-east-1`) enquanto a documentação afirma "100% on-premises, nenhum dado enviado para
   servidores externos" e o gerador de ROPA emite `cross_border_transfer=False` **hardcoded**.
5. **R-040** — O próprio relatório de red-team versionado no repositório mede **32,5% de detecção**
   de PII (42,5% de bypass) contra um FNR declarado de 18%. O Art. 46 exige medidas *aptas*; a
   aptidão está medida e documentada como insuficiente pelo próprio fornecedor.

### 2.4 O que está bem-feito

Registrado por honestidade auditorial e porque define a linha de base a preservar:

- `python/buildtovalue/security/keys.py` — fail-closed em produção, zeroização real via
  `ctypes.memset` sobre `bytearray` (com justificativa correta contra `lru_cache`/`bytes`
  internados), remoção de `BTV_HMAC_KEY` do `environ` após leitura.
- `rust/gateway/src/middleware/internal_auth.rs:69-82` — comparação em tempo constante com
  `subtle::ConstantTimeEq` + `Zeroizing`, mínimo de 32 bytes, fail-secure. É o melhor controle
  do repositório.
- `python/buildtovalue/api/response_sanitizer.py:74-92` — CSP estrito, HSTS, `frame-ancestors 'none'`,
  `Permissions-Policy`, aplicados globalmente nas respostas da API.
- `rust/kernel/src/output_guard/sanitizer.rs:68-79` — `OutputSanitizer` com todos os detectores
  **ligados por default** (CPF, CNPJ, e-mail, telefone, cartão, SSN) e *rescan* de verificação.
- `rust/gateway/src/routes/validate.rs:314-330` — o ledger JSONL grava o **hash** do input, não o texto.
- `python/buildtovalue/api/webhook_dispatcher.py:49` — o payload de webhook por design não inclui o input original.
- Fail-secure consistente: governança indisponível → `BLOCK` (`proxy.rs:206-208`).
- `docs/mapa-de-dados/` — catálogo de dados a nível de campo. É o melhor artefato de conformidade
  do repositório e a base natural para o catálogo formal recomendado em R-022.
- CI com `bandit`, `cargo audit` e TruffleHog bloqueante.
- `fly.toml:13` — `primary_region = "gru"`, única declaração explícita de residência de dados.

---

## 3. Fichas de risco

Legenda dos princípios PbD: **(1)** Proativo e Preventivo · **(2)** Privacy by Default ·
**(3)** Privacidade no Design · **(4)** Soma Positiva · **(5)** Transparência ·
**(6)** Segurança Ponta-a-Ponta · **(7)** Centrado no Usuário.

---

### P0 — Crítico

---

#### R-001 — Dado sensível do Art. 11 gravado em claro no ledger imutável

| Campo | |
|---|---|
| **Localização** | `rust/kernel/src/validators/sensitive/lgpd.rs:84-90` → `rust/kernel/src/evidence/finding.rs:36-39` → `rust/kernel/src/ledger/wal.rs:32-45` |
| **Categoria** | Minimização · Criptografia · Retenção |
| **Base legal violada** | **Art. 11** (tratamento de dado pessoal sensível) · **Art. 46** (medidas de segurança) · **Art. 16** (eliminação após término do tratamento) |
| **Princípio PbD** | (2) Privacy by Default · (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Alto** |

**Problema.** O `SensitiveDataValidator` — o componente cuja única função é detectar dados do
Art. 11 (saúde, biometria, origem racial, religião, opinião política, orientação sexual) — passa
`input`, o texto de entrada **inteiro e sem máscara**, como `matched_text` do `Finding`.

Esse `matched_text` é um `[u8; 64]` embutido na `TechnicalEvidence`, que por sua vez é serializada
no `WalEntry.evidence_snapshot` e persistida no WAL *append-only*. O `BTV-RUN-008.md:26` proíbe
explicitamente `DELETE` sobre o ledger, sob pena de quebrar a cadeia BLAKE3 — ou seja, **o dado
sensível entra e não sai**.

Todos os demais validadores mascaram antes de gravar. Este, o mais crítico, não:

| Validador | Argumento passado | Mascarado? |
|---|---|---|
| `brazilian/cpf.rs:89` (ramo válido) | `&Self::mask_cpf(candidate)` | ✅ |
| `financial/credit_card.rs:77` | `&Self::mask_cc(candidate)` | ✅ |
| `us/ssn.rs:96` | `&Self::mask_ssn(area, group, serial)` | ✅ |
| `uk/nhs.rs:53` | `&format!("NHS:{}...", &m.as_str()[..3])` | ✅ |
| **`sensitive/lgpd.rs:89`** | **`input`** | ❌ |
| `brazilian/cpf.rs:78` (ramo inválido) | `candidate` | ❌ |
| `brazilian/cnpj.rs:80` (ramo inválido) | `candidate` | ❌ |
| `network/ip.rs:84` | `.with_matched_text(ip)` | ❌ |

**Agravante — os padrões de disparo são triviais.** Não é preciso um prontuário médico para
acionar o gatilho. `lgpd.rs:12-35` casa com palavras comuns do português:

```rust
    static ref HEALTH_PATTERN_2: Regex =
        Regex::new(r"(?i)\b(doença|diagnóstico|tratamento|cirurgia|medicamento)\b")
    static ref RACIAL_PATTERN: Regex =
        Regex::new(r"(?i)\b(raça|cor|etnia|pardo|negro|branco|indígena)\b")
    static ref POLITICAL_PATTERN: Regex =
        Regex::new(r"(?i)\b(partido político|filiação partidária|ideologia)\b")
```

A palavra `cor` sozinha aciona `RACIAL_PATTERN`. A própria declaração de viés do módulo admite
(`lgpd.rs:99-101`): *"Keyword-based detection (no semantics); Brazilian Portuguese only;
**high FPR for medical terms**"*.

**Cenário de dano.** Um titular escreve num chatbot governado pelo BTV: *"preciso remarcar meu
tratamento de diabetes, o médico pediu novo medicamento"*. O validador dispara, e os primeiros
64 bytes dessa frase — informação de saúde, Art. 11 — são gravados em claro no WAL do ledger,
sem cifra, sem prazo de retenção, sem mecanismo de exclusão e, se o sync remoto estiver
habilitado, replicados para `us-east-1` (R-009). Um vazamento do volume `ledger_data` expõe
diretamente dados de saúde de todos os titulares que já passaram pelo sistema.

**Evidência.**

```rust
// rust/kernel/src/validators/sensitive/lgpd.rs:78-95
impl Validator for SensitiveDataValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let detections = self.detect_sensitive_type(input);
        for (data_type, conf) in detections {
            findings.push(
                Finding::new(
                    ValidatorModule::SensitiveData,
                    TechnicalSeverity::Critical(255),
                    "LGPD_ART11_DADOS_SENSIVEIS",
                    &format!("SENSITIVE_DATA_{}", data_type.to_uppercase()),
                    input,          // ← input bruto, sem máscara
                )
```

```rust
// rust/kernel/src/evidence/finding.rs:36-39
    /// Snippet do texto que causou o match.
    pub matched_text: [u8; 64],
```

```rust
// rust/kernel/src/ledger/wal.rs:32-45
pub struct WalEntry {
    pub seq: u64,
    pub timestamp: u128,
    pub evidence_snapshot: Vec<u8>,   // evidence.to_bytes() — 9632 B
}
```

**Recomendação.**
1. Substituir `input` por um resumo não reversível: `&format!("SENSITIVE_{}_len{}", data_type, input.len())`,
   ou o hash BLAKE3 truncado do trecho casado. O `Finding` precisa provar *que* houve match, não *qual* texto.
2. Aplicar a mesma correção aos três ramos sem máscara (`cpf.rs:78`, `cnpj.rs:80`, `ip.rs:84`).
3. Adicionar um teste de invariante que falhe se qualquer `Finding::new` receber um argumento
   que não passou por uma função `mask_*` — é uma regra estrutural, não uma revisão de PR.
4. Adicionar guard no `scripts/ci/lint_guards.sh` que rejeite `Finding::new(` com argumento
   `input` ou `candidate` cru.

---

#### R-002 — Ausência total de criptografia em repouso; não há envelope encryption

| Campo | |
|---|---|
| **Localização** | Todo o repositório. Contraste: `rust/kernel/src/security/tenant_key.rs` vs `rust/gateway/src/routes/decide.rs:1116` |
| **Categoria** | Criptografia e chaves |
| **Base legal violada** | **Art. 46** (medidas técnicas aptas a proteger os dados) · **Art. 6º, VII** (segurança) |
| **Princípio PbD** | (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Alto** |

**Problema.** Uma varredura por `encrypt`, `decrypt`, `AES`, `GCM`, `ChaCha20`, `Fernet`,
`SQLCipher` e `KMS` sobre todos os `.py` e `.rs` do repositório retorna **zero implementações**.
Todos os resultados são (a) YAML de política que avalia *terceiros*, (b) comentários do tipo
"em produção usar HSM ou KMS", ou (c) o `envelope` de resposta HTTP, homônimo sem relação.

Existe derivação de chave por tenant, e o nome sugere cifragem — mas ela não cifra nada:

```rust
// rust/kernel/src/security/tenant_key.rs:1-3
//! Derivação de Tenant Encryption Key (TEK) via HKDF-SHA256 (ADR-0083).
//! TEK = HKDF-SHA256(ikm=MKK, salt=[], info="btv-tek-v1:{tenant_id}", len=32)
```

Os únicos consumidores da TEK a usam como chave de **MAC**, não de cifra:
- `rust/gateway/src/routes/decide.rs:1116` — `<Hmac<Sha256>>::new_from_slice(tek.as_ref())` para o header `X-BTV-Verdict-Signature`
- `rust/gateway/src/routes/decide.rs:1096,1210` — `.append_with_key(entry, evidence, tek)`

Em `rust/kernel/src/ledger/durable_ledger.rs:160-166`, `append_internal` chama
`entry.finalize_with_key(key)` e em seguida `self.wal.append(evidence)` / `write_to_disk(entry)`
— **sem nenhum passo de cifragem entre a assinatura e a escrita em disco**.

Consequência: não há DEK por registro, não há KEK em KMS, não há chave por campo, não há
auditoria de acesso a chave (CloudTrail ou equivalente). Todos os itens do bloco 7 do checklist
de escopo estão ausentes.

O que fica em claro no disco: `explanations.full_data` (JSON com `ip_address` e `findings_detail`),
`appeal_records.explanation_text`, `appeals.reason`/`evidence`/`reviewer_notes`, `users.password_hash`
(mitigado por bcrypt), e o `WalEntry.evidence_snapshot` com o `matched_text` de R-001.

**Cenário de dano.** Acesso ao volume `ledger_data` / PVC `buildtovalue-explanations-pvc` (100 Gi,
`ops/k8s/30-pvc.yaml`, sem anotação de criptografia) — por backup mal descartado, snapshot de
volume, ou comprometimento de um nó — expõe integralmente o conteúdo tratado, sem que nenhuma
chave precise ser quebrada.

**Recomendação.**
1. Envelope encryption real: DEK por registro (AES-256-GCM), KEK em KMS externo (AWS KMS,
   GCP KMS, Azure Key Vault ou HSM). A TEK já derivada por HKDF é o ponto de partida natural
   para a KEK por tenant — falta o passo de cifragem.
2. Chave própria para os campos de maior sensibilidade (`matched_text`, `explanation_text`,
   `appeals.reason`), de modo que o comprometimento de uma chave não exponha todas as tabelas.
3. Cifra em repouso das bases SQLite (SQLCipher) ou migração para um backend com TDE.
4. Habilitar criptografia no `StorageClass` dos PVCs e declarar isso no manifesto.
5. Auditoria de acesso ao KMS (quem, quando, de qual IP), com retenção de 5 anos.

---

#### R-003 — Nenhum job de expurgo em execução; retenção declarada não é enforçada

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/governance/explanation_store.py:269-285` (função órfã); `docs/runbooks/BTV-RUN-008.md:26` |
| **Categoria** | Retenção e ciclo de vida |
| **Base legal violada** | **Art. 15** (término do tratamento) · **Art. 16** (eliminação) · **Art. 18, VI** (eliminação a pedido) |
| **Princípio PbD** | (1) Proativo e Preventivo · (2) Privacy by Default |
| **Impacto** | **Alto** |

**Problema.** Existe exatamente **uma** função de expurgo em todo o repositório, e ela nunca é
chamada:

```python
# python/buildtovalue/governance/explanation_store.py:269-272
    def cleanup_old_entries(self, retention_days: int = 90):
        """Remove explicações antigas (compliance com retenção)."""
        cutoff_timestamp = int(time.time()) - (retention_days * 86400)
        ...
        cursor.execute("DELETE FROM explanations WHERE timestamp < ?", (cutoff_timestamp,))
```

`grep -rn "cleanup_old_entries"` retorna apenas a definição (`:269`) e a mensagem de log (`:284`).
Zero call-sites, zero testes, zero agendamento. Não há cron, `CronJob` do k8s, APScheduler,
`@repeat_every` nem systemd timer de retenção em lugar nenhum.

`expire_overdue()` (`governance/contestability/_loop.py:241-243`) apenas **conta** appeals com SLA
vencido — não deleta nada. É chamada em `api/routes/appeals.py:80,128` só para atualizar métrica.

Não existe evidência de exclusão (hash de *tombstone*). As variáveis
`BTV_AUDIT_TTL_DAYS` / `BTV_AUDIT_HASH_LEDGER` / `BTV_AUDIT_KEY` aparecem no catálogo do
`docs/mapa-de-dados/README.md:103` **com defaults**, como se estivessem implementadas — mas têm
zero ocorrências em código (ver R-034).

E o ledger é, por design, inexpurgável: `docs/runbooks/BTV-RUN-008.md:26` proíbe `DELETE` para
não quebrar a cadeia BLAKE3.

**Cenário de dano.** Um titular exerce o direito do Art. 18, VI. Não há endpoint (R-004); e mesmo
que houvesse, não há mecanismo capaz de eliminar o dado: o WAL é append-only, o `explanations`
não é expurgado, e o runbook oficial de cripto-shredding é inexecutável (R-035). A resposta
honesta ao titular hoje seria "não conseguimos eliminar" — o que, sob Art. 16, é a admissão da
violação.

**Recomendação.**
1. Implementar o job de expurgo diário em batch, com registro de evidência de exclusão
   (hash + contagem + timestamp) num livro de ocorrências append-only separado.
2. Chamar `cleanup_old_entries()` a partir desse job — a função já existe e está correta.
3. Para o ledger append-only, adotar **cripto-shredding**: cada registro cifrado com uma DEK
   por titular (depende de R-002); a eliminação passa a ser a destruição da DEK, o que preserva
   a cadeia de hashes e satisfaz o Art. 16. Esta é a arquitetura que o `BTV-RUN-008` já
   descreve — falta implementá-la.
4. Retenção diferenciada: logs operacionais 30 dias; log de auditoria 5 anos **sem PII**.

---

#### R-004 — Nenhum endpoint de direitos do titular (Art. 18, incisos I a IX)

| Campo | |
|---|---|
| **Localização** | Ausência em `python/buildtovalue/api/routes/**` e `rust/gateway/src/routes/**` |
| **Categoria** | Direitos do titular |
| **Base legal violada** | **Art. 18, I a IX** · **Art. 19** (prazos de resposta) |
| **Princípio PbD** | (7) Centrado no Usuário · (5) Transparência |
| **Impacto** | **Alto** |

**Problema.** Varredura por `art_?18`, `data_subject`, `portability`, `portabilidade`, `erasure`,
`eliminação`, `anonimiz`, `right_to`, `delete_user` em toda a superfície HTTP: **zero resultados
relevantes**.

| Direito (Art. 18) | Endpoint | Status |
|---|---|---|
| I — confirmação da existência de tratamento | — | ❌ ausente |
| II — acesso aos dados | — | ❌ ausente |
| III — correção de dados | — | ❌ ausente |
| IV — anonimização, bloqueio ou eliminação de dado desnecessário | — | ❌ ausente |
| V — portabilidade | — | ❌ ausente |
| VI — eliminação de dado tratado com consentimento | — | ❌ ausente |
| VII — informação sobre compartilhamento | — | ❌ ausente |
| VIII — informação sobre a possibilidade de não consentir | — | ❌ ausente |
| IX — revogação do consentimento | — | ❌ ausente |
| **Art. 20** — revisão de decisão automatizada | `/v1/appeals` | ⚠️ existe, mas quebrado (R-039) e sem controle de posse (R-008, R-016) |

`GET /v1/auth/me` **não** é o direito de acesso — retorna apenas `username` e `role` de uma conta
de **operador do dashboard** (tabela `users`), não do titular cujos dados foram tratados:

```python
# python/buildtovalue/api/routes/auth.py:223-225
@router.get("/me", response_model=UserInfo)
def get_me(user: dict = Depends(require_jwt)):
    return UserInfo(username=user["username"], role=user["role"])
```

Os únicos `DELETE` existentes são operacionais, não de titular:
- `DELETE /v1/agents/{agent_id}/revoke` (`agents.py:141`) faz `UPDATE ... SET revoked_at` —
  **não apaga** `public_key_hex` nem `registration_proof`.
- `DELETE /internal/v1/tenants/{tenant_id}` (`internal.rs:80`) é eviction de cache em memória.

**Cenário de dano.** A ANPD instaura procedimento a partir de uma reclamação de titular. O
controlador-cliente é questionado sobre como atende o Art. 18 e responde que usa o BTV. Não há
endpoint, não há prazo, não há log de atendimento. O controlador é sancionado (Art. 52) e o BTV,
como operador, responde solidariamente (Art. 42).

**Recomendação.** Implementar a superfície mínima, cada endpoint com prazo, autenticação e log
de evidência:

| Direito | Endpoint | Auth | Resposta |
|---|---|---|---|
| Art. 18, I | `GET /v1/me/tratamento` | JWT válido | `200 OK` — apenas confirma |
| Art. 18, II | `GET /v1/me/dados` | JWT + MFA | JSON compacto, imediato |
| Art. 18, II (declaração completa) | `POST /v1/me/declaracao` | JWT + MFA | `202 Accepted`, geração assíncrona, prazo de 15 dias (Art. 19, §3) |
| Art. 18, V | `GET /v1/me/portabilidade` | JWT + MFA | formato interoperável |
| Art. 18, III | `PATCH /v1/me/dados` | JWT + MFA | log de correção |
| Art. 18, VI | `DELETE /v1/me/dados` | JWT + MFA | efeito cascata; dado de verificação descartado após uso |
| Art. 18, VII | `GET /v1/me/compartilhamentos` | JWT | lista de subprocessadores efetivamente acionados |

Cada um deve gravar no log de auditoria: ator, recurso, propósito, base legal, campos acessados
e timestamp.

---

#### R-005 — Ausência total de controle de finalidade (purpose limitation)

| Campo | |
|---|---|
| **Localização** | Toda a superfície HTTP. `python/buildtovalue/api/routes/auth.py:155-162` (claims do JWT); `rust/gateway/src/middleware/tenant_extractor.rs:33-47` |
| **Categoria** | Limitação de finalidade |
| **Base legal violada** | **Art. 6º, I** (finalidade) · **Art. 6º, II** (adequação) · **Art. 6º, III** (necessidade) |
| **Princípio PbD** | (3) Privacidade no Design · (5) Transparência |
| **Impacto** | **Alto** |

**Problema.** Varredura por `x-purpose`, `purpose`, `finalidade`, `legal_basis`, `base_legal` em
`python/buildtovalue/api/` e `rust/gateway/src/` retorna **uma única linha**, e é falso positivo:

```
rust/gateway/src/middleware/tenant_extractor.rs:238:
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
```

Nenhum endpoint declara a finalidade que atende. Os claims do JWT são `sub`, `role`, `iat`, `exp`
(`routes/auth.py:156-161`) e `tenant_id`, `exp`, `sub` (`tenant_extractor.rs:33-47`) — nenhum de
propósito. Os headers aceitos no CORS são `Authorization, Content-Type, X-BTV-Session,
X-BTV-Jurisdiction` (`app.py:150`) — `X-BTV-Jurisdiction` é territorial, não finalístico.

Existe geração de artefato de ROPA (`compliance.py:187`) e de relatório do Art. 20
(`compliance.py:202`), mas ali a finalidade é um campo de documento produzido *a posteriori* —
não um controle de runtime que restrinja o que cada ator pode acessar.

Não há middleware de admin separado com propósito explícito. Não há claim de propósito revogável
quando um atendente muda de função.

**Cenário de dano.** Um atendente com API key válida consulta `GET /v1/appeals?user_id=...` de um
titular com quem não tem relação de atendimento (R-008). Não existe registro do porquê. Numa
auditoria da ANPD, não é possível distinguir acesso legítimo de curiosidade ou de exfiltração —
o que torna o log de auditoria inútil como prova de conformidade.

**Recomendação.**
1. Header `X-Purpose` obrigatório (ou claim `purpose` no JWT) em todo endpoint que acesse dado
   pessoal; requisição sem propósito → `400`.
2. Enum fechado de finalidades declaradas, validado contra o catálogo de dados: cada finalidade
   mapeia para o conjunto de campos que autoriza.
3. O propósito entra no log de auditoria de cada acesso (ver R-020).
4. Middleware de admin separado, com propósito explícito (ex.: `?purpose=auditoria_interna`).
5. Propósito revogável: a claim expira e é reemitida quando o papel do ator muda.

---

#### R-006 — Bypass de autenticação por sufixo de arquivo no gateway

| Campo | |
|---|---|
| **Localização** | `rust/gateway/src/middleware/auth.rs:11,14,112-124` |
| **Categoria** | Segurança de endpoints |
| **Base legal violada** | **Art. 46** (medidas de segurança) · **Art. 6º, VII** |
| **Princípio PbD** | (1) Proativo e Preventivo · (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Alto** |

**Problema.** O `ApiKeyLayer` — aplicado globalmente a todas as rotas do gateway
(`routes/mod.rs:113`) — decide o bypass a partir do **sufixo textual do path**, antes de qualquer
verificação:

```rust
// rust/gateway/src/middleware/auth.rs:11,14
const PUBLIC_PATHS: &[&str] = &["/health", "/metrics", "/v1/auth"];
const STATIC_EXTENSIONS: &[&str] = &[".js", ".css", ".svg", ".png", ".ico", ".html", ".json", ".woff", ".woff2", ".map"];
```

```rust
// rust/gateway/src/middleware/auth.rs:112-124
            // Public paths bypass auth
            if PUBLIC_PATHS.iter().any(|p| path.starts_with(p)) {
                return inner.call(req).await;
            }

            // Static assets (React dashboard) bypass auth
            if path == "/"
                || STATIC_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
                || path.starts_with("/assets/")
            {
                return inner.call(req).await;   // ← bypass total de auth
            }
```

Dois defeitos independentes:

1. **`ends_with` sobre extensões.** As rotas de path param aceitam qualquer string, então
   `GET /v1/trust/<id>.json` e `GET /v1/appeals/<id>.json` casam com `.json` e pulam o
   `ApiKeyLayer` inteiro. O handler recebe o ID com o sufixo anexado — o que limita a
   exploração direta a IDs que tolerem o sufixo —, mas a camada de autenticação foi
   estruturalmente derrotada, e qualquer rota futura que normalize o path passa a ser
   plenamente acessível sem credencial.
2. **`starts_with` sobre `PUBLIC_PATHS`.** `/healthXYZ` e `/metricsXYZ` também são tratados como
   públicos. Hoje sem rota correspondente; amanhã, com uma rota `/metrics-detail`, seria acesso
   anônimo a dados agregados.

**Cenário de dano.** Defesa em profundidade anulada. Numa configuração em que o gateway está
publicado (o `ops/docker-compose.yml:17-31` publica `8080:8080` **sem definir `BTV_API_KEYS`**),
a combinação com R-015 e R-007 dá acesso não autenticado a superfície que deveria exigir chave.

**Recomendação.**
1. Trocar a heurística de sufixo por um **roteamento explícito**: montar os estáticos num
   `Router` próprio (`.nest_service("/assets", ServeDir::new(...))`) e aplicar o `ApiKeyLayer`
   apenas ao router de API — a decisão passa a ser estrutural, não textual.
2. Trocar `starts_with` por igualdade exata na lista de paths públicos.
3. Adicionar teste de regressão que faça `GET /v1/trust/x.json` sem `X-API-Key` e exija `401`.

---

#### R-007 — `/demo-login` emite JWT de `admin` para qualquer origem, sob CORS `*`

| Campo | |
|---|---|
| **Localização** | `demo/proxy.py:24-25,172-200,229-232` |
| **Categoria** | Autenticação e sessão |
| **Base legal violada** | **Art. 46** · **Art. 6º, VII** |
| **Princípio PbD** | (2) Privacy by Default · (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Alto** |

**Problema.** O proxy do demo expõe `POST /demo-login`, **sem autenticação alguma**, que troca
credenciais de ambiente por um JWT emitido pelo backend real:

```python
# demo/proxy.py:24-25
DEMO_USER       = os.environ.get("BTV_DEMO_USER", "admin")
DEMO_PASSWORD   = os.environ.get("BTV_DEMO_PASSWORD", "")  # fail-secure: vazio = somente-leitura
```

```python
# demo/proxy.py:190-199
        url = f"{API_BASE}/v1/auth/login"
        body = json.dumps({"username": DEMO_USER, "password": DEMO_PASSWORD}).encode()
        ...
                print(f"[DEMO-AUTH] Decision: ALLOW. User: {DEMO_USER}")
                self._write_json(resp.status, data)
```

E toda resposta sai com CORS irrestrito:

```python
# demo/proxy.py:229-232
    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
```

Além disso, o proxy injeta a API key real do lado servidor em toda requisição encaminhada
(`demo/proxy.py:210-213`), configurando um *confused deputy*: o cliente não precisa da chave,
o proxy a anexa por ele.

**Cadeia de exploração completa.** Combinando com R-016 (nenhuma rota verifica `role`):

1. Um site qualquer faz `fetch('https://demo.buildtovalue.cloud/demo-login', {method:'POST'})`.
   CORS `*` permite ler a resposta.
2. A resposta contém um JWT válido com `role: "admin"` (usuário `admin`, `routes/auth.py:120`).
3. Com esse JWT, `POST /v1/appeals/{id}/resolve` — que exige apenas `Depends(require_jwt)` e não
   verifica `role` — **resolve o recurso de qualquer titular**, com `reviewer_id` informado
   livremente no corpo (R-016).

O único freio é o fail-secure de `BTV_DEMO_PASSWORD` vazia (`proxy.py:180-188`) — ou seja, a
segurança do fluxo depende de o operador **não** provisionar a senha, que é exatamente o que a
documentação do demo instrui a fazer para habilitar as personas de escrita.

**Cenário de dano.** Um titular tem sua contestação do Art. 20 rejeitada por um terceiro anônimo,
com `reviewer_id` forjado. O registro de revisão humana — que é a prova exigida pelo Art. 20, §1 —
passa a ser falso, e o log não permite distinguir.

**Recomendação.**
1. Remover `/demo-login` ou exigir interação humana explícita (não auto-login no `init()` do frontend).
2. Restringir `Access-Control-Allow-Origin` à origem do próprio demo; nunca `*` em endpoint que emite credencial.
3. Criar um usuário `demo` com `role: "viewer"` — o demo nunca deve autenticar como `admin`.
4. Corrigir R-016 (verificação de `role`), que é o que transforma este achado em escalada de privilégio.

---

#### R-008 — Nenhuma checagem de posse de recurso; enumeração de titulares por API key

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/api/routes/appeals.py:95-107,114-158`; `python/buildtovalue/api/_models.py:121-135` |
| **Categoria** | Segurança de endpoints · Minimização |
| **Base legal violada** | **Art. 6º, VII** (segurança) · **Art. 6º, III** (necessidade) · **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default · (3) Privacidade no Design |
| **Impacto** | **Alto** |

**Problema.** **Nenhum handler da aplicação compara o sujeito autenticado com o dono do recurso.**
Não existe uma única linha `if appeal.user_id != current_user` em todo o repositório.

`GET /v1/appeals` aceita `user_id` como filtro **opcional controlado pelo chamador**, protegido
apenas por uma API key compartilhada:

```python
# python/buildtovalue/api/routes/appeals.py:114-127
@router.get(
    "/v1/appeals",
    response_model=AppealPageResponse,
    dependencies=[Depends(require_api_key)],  # CRITICO-03: read requires API key
)
def list_appeals(
    status: Optional[str] = None,
    user_id: Optional[str] = None,          # ← PII em query string
```

```python
# python/buildtovalue/api/routes/appeals.py:142-143
    if user_id:
        appeals = [a for a in appeals if a.user_id == user_id]
```

O DTO retornado devolve o conteúdo integral da contestação (`_models.py:121-135`): `user_id`,
`reason` (texto livre do titular, `min_length=20` — por design é uma narrativa pessoal),
`evidence_provided` e `reviewer_notes`.

Três defeitos compostos:
1. **Sem posse**: qualquer portador de API key lê o recurso de qualquer titular.
2. **PII em query string**: `user_id` viaja na URL, portanto entra em logs de acesso do nginx,
   `Referer` e histórico de proxy — o oposto do exigido pelo bloco 3 do checklist.
3. **DTO de escopo único**: existe allowlist explícita (`_decide_helpers.py:60-77`, o que é
   correto), mas **um só** DTO serve tanto a `GET /{id}` quanto à listagem. Não há projeção por
   finalidade — quem lista recebe tanto quanto quem consulta um caso específico.

Além disso, `POST /v1/appeals` aceita `user_id` do corpo sem vinculá-lo ao `sub` do JWT
(`appeals.py:47-60`) — permite abrir contestação em nome de outra pessoa.

Os `404` retornados (`appeals.py:106`) são de inexistência, não de não-autorização; combinados
com a ausência de posse, produzem um oráculo de existência de `appeal_id` / `session_id` / `agent_id`.

**Cenário de dano.** Uma única API key vazada (e o `python/.env.example:3` distribui
`btv_dev_key_001,btv_dev_key_002` como exemplo funcional) permite iterar `user_id` e extrair a
narrativa completa de todas as contestações — que são, por natureza, relatos pessoais sobre
decisões automatizadas que afetaram o titular.

**Recomendação.**
1. Derivar o escopo do **token**, não do parâmetro: o filtro por `user_id` só é aceito de um ator
   com propósito declarado (R-005) e papel autorizado; para o titular, o escopo é sempre o `sub` do JWT.
2. Retornar `404`, nunca `403`, para recurso de outro titular — e implementar de fato a checagem
   que hoje não existe.
3. Mover a busca por identificador natural para `POST` com hash, nunca query string.
4. DTOs por escopo: `AppealSummary` (listagem: id, status, timestamp, `is_overdue`) vs
   `AppealDetail` (caso específico, com `reason`), servidos conforme a finalidade declarada.
5. Vincular `POST /v1/appeals` ao `sub` do JWT; ignorar `user_id` do corpo.

---

#### R-009 — Transferência internacional sem mecanismo do Art. 33

| Campo | |
|---|---|
| **Localização** | `rust/gateway/src/routes/proxy.rs:74-77,215-226`; `demo/proxy.py:28`; `python/buildtovalue/intelligence/llm_async_client.py:354`; `rust/kernel/src/ledger/remote/config.rs:17-26`; `ops/k8s/security/pod-security-policy.yaml:110-119` |
| **Categoria** | Transferência internacional |
| **Base legal violada** | **Art. 33** (hipóteses de transferência internacional) · **Art. 34** (adequação) · **Art. 35** (cláusulas-padrão) |
| **Princípio PbD** | (2) Privacy by Default · (5) Transparência |
| **Impacto** | **Alto** |

**Problema.** O sistema envia dados pessoais para fora do Brasil por **quatro caminhos**, nenhum
com decisão de adequação da ANPD, cláusulas-padrão contratuais ou registro documental.

| Destino | Evidência | País |
|---|---|---|
| OpenAI (default do proxy) | `rust/gateway/src/routes/proxy.rs:74-77` | EUA |
| OpenAI (cliente Python) | `intelligence/llm_async_client.py:354` — `base_url = "https://api.openai.com/v1"` | EUA |
| **DeepSeek** | `demo/proxy.py:28` — `DEEPSEEK_BASE = ... "https://api.deepseek.com"`; acionado pelo frontend em `demo/js/deepseek.js:27` | **China** |
| Anthropic | `agentic/policy_elicitor.py:109-125` (ver R-038) | EUA |
| AWS S3 — sync do WAL | `rust/kernel/src/ledger/remote/config.rs:22` — `region: "us-east-1"` | EUA |
| Google Fonts / Analytics | R-024 — IP + User-Agent de todo visitante | EUA |

```rust
// rust/gateway/src/routes/proxy.rs:74-77
fn upstream_url() -> String {
    std::env::var("BTV_PROXY_UPSTREAM_URL")
        .unwrap_or_else(|_| "https://api.openai.com".to_string())
}
```

**O corpo é encaminhado sem redação.** O `proxy_forward` repassa o `body` original, byte a byte:

```rust
// rust/gateway/src/routes/proxy.rs:215-226
    let forward_url = format!("{}/{}", upstream_url().trim_end_matches('/'), path);
    let upstream = state.http_client
        .request(..., &forward_url)
        .headers(filter_forward_headers(&headers))
        .body(body.to_vec())      // ← corpo original, sem máscara
        .send()
        .await;
```

O kernel escaneia e pode bloquear, mas quando o veredito é `ALLOW` o prompt segue **íntegro** —
inclusive o prompt que contém CPF ou dado de saúde que o próprio kernel detectou mas classificou
abaixo do limiar de bloqueio.

**Sem gate por jurisdição.** Não há verificação de região no caminho de rede. Existem políticas
declarativas sobre geografia (`data/policies/agents/pa_privacy_geo.yaml`, header
`X-BTV-Jurisdiction`) e o proxy até carrega o campo — mas **hardcoded**:

```rust
// rust/gateway/src/routes/proxy.rs:188-190
        ip_risk: "Low".to_string(),
        ip_jurisdiction: "XX".to_string(),
        drift_level: "None".to_string(),
```

A NetworkPolicy do k8s **não** implementa gate de saída por região, e a regra que se propõe a
liberar HTTPS externo não faz o que o comentário diz:

```yaml
# ops/k8s/security/pod-security-policy.yaml:110-119
    # Allow HTTPS external (remote sync, APIs, etc)
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 443
```

`namespaceSelector: {}` seleciona pods de **qualquer namespace do cluster** — não endereços
externos. Para permitir saída à internet seria preciso `ipBlock`. Ou seja: a regra nem faz o gate
de jurisdição, nem cumpre a intenção declarada no comentário.

**Contradição com a própria residência declarada.** `fly.toml:13` diz
`primary_region = "gru"  # São Paulo — residência de dados LGPD`, enquanto `fly.toml:6` instrui a
apontar o upstream para `api.openai.com`. A residência do *compute* é BR; a do *conteúdo tratado*
e a do *ledger* são US.

**Nuance sobre o sync remoto.** O sync do WAL vem **desabilitado por default**
(`rust/kernel/src/ledger/remote/sync.rs:41` — `enabled: false`). O achado, portanto, não é
"replicação automática para os EUA", e sim: *quando o operador habilita a replicação do ledger
forense, o default de região é `us-east-1`*. É falha de Privacy by Default, não de exfiltração
automática.

**Cenário de dano.** Um hospital adota o BTV para governar seu chatbot. Prompts com dados de saúde
(Art. 11) são encaminhados a `api.openai.com` por default, sem SCC, sem adequação, sem registro,
e sem que o ROPA gerado pelo próprio BTV mencione a transferência (R-010). Sanção do Art. 52 recai
sobre o hospital como controlador, e solidariamente sobre o BTV como operador (Art. 42).

**Recomendação.**
1. Gate de jurisdição no gateway: allowlist de FQDN/região no `upstream_url()`, com bloqueio
   fail-secure para destino não registrado.
2. Registro versionado de subprocessadores com país, mecanismo do Art. 33 aplicável, hash do
   SCC e data de validade — validado programaticamente antes de liberar a integração (bloco 11
   do checklist).
3. Redação obrigatória antes do encaminhamento: aplicar o `OutputSanitizer`, que já existe, ao
   corpo de saída do proxy — não apenas à mensagem de resposta.
4. Preencher `ip_jurisdiction` de verdade (o campo já existe no contrato) e usá-lo como gate.
5. Trocar o default de `remote/config.rs:22` para uma região brasileira, ou torná-lo obrigatório
   sem default.
6. Corrigir a regra de egress do NetworkPolicy para `ipBlock` com CIDR explícito das
   integrações aprovadas.

---

#### R-010 — ROPA gerado é factualmente falso e usa base legal inválida para dado sensível

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/compliance/ropa_generator.py:138-190` |
| **Categoria** | ROPA e catálogo · Base legal |
| **Base legal violada** | **Art. 37** (registro das operações de tratamento) · **Art. 11** (base legal de dado sensível) · **Art. 33** (transferência não declarada) · **Art. 16** (retenção indefinida) |
| **Princípio PbD** | (5) Transparência · (1) Proativo e Preventivo |
| **Impacto** | **Alto** |

**Problema.** O `ROPAGenerator` produz o documento do Art. 37 a partir de **strings literais
hardcoded**, não de metadado real do sistema. Quatro campos estão factualmente errados:

```python
# python/buildtovalue/compliance/ropa_generator.py:144-163 (atividade 1)
            purpose="Validacao de seguranca, deteccao de PII, e prevencao de injecao de prompt ...",
            legal_basis="Art. 7, IX — Interesse legitimo do controlador para protecao de seguranca",
            ...
            recipients="Nenhum — processamento local, dados nao sao compartilhados (Jonas: soberania de dados)",
            retention_period="Conforme politica de retencao do ledger (padrao: 90 dias para dados ativos, arquivo imutavel indefinido)",
            ...
            cross_border_transfer=False,
```

```python
# python/buildtovalue/compliance/ropa_generator.py:169-180 (atividade 2)
            legal_basis="Art. 7, IX — Interesse legitimo; Art. 20 — Direito a revisao de decisoes automatizadas",
            recipients="Nenhum — decisoes armazenadas localmente no ledger imutavel",
            retention_period="Indefinido (ledger imutavel para auditoria e contestacao)",
            cross_border_transfer=False,
```

| Declaração | Realidade | Artigo |
|---|---|---|
| `cross_border_transfer=False` | OpenAI/EUA por default, DeepSeek/China no demo, `us-east-1` no sync (R-009) | Art. 33 |
| `recipients="Nenhum"` | OpenAI, Anthropic, DeepSeek, AWS, Google (Fonts/Analytics), destinos de webhook | Art. 37 |
| `legal_basis="Art. 7º, IX"` para todo o tratamento | O sistema classifica e trata dado de saúde, biometria, origem racial e orientação sexual (`governance/privacy_budget.py:52-56`; `validators/sensitive/lgpd.rs`). **O Art. 11 não admite legítimo interesse** — dado sensível exige consentimento específico ou uma das hipóteses do Art. 11, II | Art. 11 |
| `retention_period="Indefinido"` / "90 dias" | Nenhuma das duas é enforçada; não há job de expurgo (R-003) | Art. 15, 16 |

O erro do `legal_basis` é o mais grave em termos jurídicos. O legítimo interesse (Art. 7º, IX)
é uma base legal do **Art. 7º**, que trata de dado pessoal comum. O **Art. 11** enumera
exaustivamente as hipóteses para dado sensível, e legítimo interesse não está entre elas. Um
sistema que declara legítimo interesse para tratar dado de saúde declara, no próprio documento
de conformidade, uma base legal que a lei não oferece.

**Cenário de dano.** A ANPD requisita o ROPA (Art. 37). O documento entregue afirma que não há
transferência internacional e que não há destinatários. A verificação técnica mostra o contrário.
O que era uma falha de configuração vira **declaração inexata a autoridade**, agravante na
dosimetria do Art. 52, §1º.

**Recomendação.**
1. Derivar o ROPA do **catálogo de dados** (R-022), não de literais. O `docs/mapa-de-dados/` já é
   90% do inventário necessário — falta a coluna de classificação e a regeneração automática.
2. `cross_border_transfer` deve ser computado do registro de subprocessadores efetivamente
   configurados (`BTV_PROXY_UPSTREAM_URL`, config do sync remoto), não fixado.
3. `legal_basis` por **finalidade e por categoria de dado**, com ramo separado para Art. 11.
   Se o pipeline detecta dado sensível, a base legal do Art. 7º deixa de ser válida e o ROPA
   deve refletir isso — ou o tratamento deve parar.
4. `retention_period` deve ler o `retencao_ate` real do catálogo. Enquanto R-003 não for
   corrigido, o campo honesto é "não enforçada".
5. Teste que falhe se o ROPA gerado declarar `cross_border_transfer=False` enquanto
   `BTV_PROXY_UPSTREAM_URL` apontar para fora do Brasil.

---

### P1 — Alto

---

#### R-011 — `verdict_id` assinado com chave zero no caminho legado/FFI

| Campo | |
|---|---|
| **Localização** | `rust/kernel/src/ledger/entry.rs:120-128,141-151`; `rust/kernel/src/ledger/durable_ledger.rs:155-163` |
| **Categoria** | Criptografia · Auditoria |
| **Base legal violada** | **Art. 37** (registro fidedigno) · **Art. 46** |
| **Princípio PbD** | (6) Segurança Ponta-a-Ponta · (5) Transparência |
| **Impacto** | **Alto** |

**Problema.** Existem dois caminhos de finalização de entrada no ledger. O caminho legado assina
o `verdict_id` com uma chave literalmente zerada:

```rust
// rust/kernel/src/ledger/entry.rs:120-139
    pub fn finalize(&mut self) {
        self.entry_hash = self.calculate_hash();
        self.verdict_id = Self::compute_verdict_id(
            &self.entry_hash,
            self.ethical_verdict,
            self.entry_id,
            &[0u8; 32],            // ← chave zero
        );
    }

    /// Finaliza com chave de assinatura do operador (produção).
    pub fn finalize_with_key(&mut self, signing_key: &[u8]) { ... }
```

E a verificação usa a mesma chave zero (`entry.rs:141-151`), de modo que a entrada "valida"
normalmente. O seletor entre os dois caminhos:

```rust
// rust/kernel/src/ledger/durable_ledger.rs:155-163
        // INVARIANTE: `signing_key = None` preserva o comportamento legado
        // de `append()` byte-a-byte — `entry.finalize()` usa zero-key por
        // spec ... Caller pré-ADR-0083 (ex: ffi/bridge/mod.rs) continua
        // produzindo verdict_id verificável com a mesma chave-zero
        match signing_key {
            Some(key) => entry.finalize_with_key(key),
            None => entry.finalize(),
        }
```

Como a chave é pública (é `[0u8; 32]`, está no código-fonte), qualquer pessoa pode computar um
`verdict_id` válido para um `entry_hash` arbitrário. O `entry_hash` em si é BLAKE3 **sem chave**.
Resultado: no caminho FFI/legado, o veredito **não tem propriedade de não repúdio** — que é
exatamente a garantia que o produto vende.

O caminho do gateway (`decide.rs:1096,1210`, via `append_with_key` com a TEK) está correto.

**Cenário de dano.** Numa disputa sobre uma decisão automatizada, o titular contesta e o
controlador apresenta o `verdict_id` como prova de que a decisão foi tomada de determinada forma.
A defesa demonstra que o identificador é forjável por qualquer um com acesso ao código aberto do
BTV. A evidência criptográfica perde valor probatório — e junto com ela, todo o argumento de
conformidade com o Art. 37.

**Recomendação.**
1. Tornar `signing_key` obrigatório: remover `finalize()` e o ramo `None`, migrando os callers
   pré-ADR-0083 (`ffi/bridge/mod.rs`) para `finalize_with_key`.
2. Enquanto a migração não conclui, marcar `finalize()` como `#[deprecated]` e emitir `log::error!`
   a cada uso, para que o caminho inseguro seja visível em produção.
3. Verificação (`validate()`) deve exigir a chave real; entradas assinadas com chave zero devem
   ser reportadas como **não verificadas**, não como válidas.

---

#### R-012 — Chaves HMAC default hardcoded em ~11 módulos

| Campo | |
|---|---|
| **Localização** | `governance/commit_reveal.py:40`, `memory_consistency.py:37`, `liveness_monitor.py:38`, `privacy_budget.py:41`, `multi_party_kill_switch.py:36`, `content_provenance.py:37`, `approval_workflow.py:62`, `capability_enforcer.py:32`, `output_leakage_detector.py:76`, `conversation_threat_graph.py:68`; `sdk/mcp-server/btv_mcp/server.py:474` |
| **Categoria** | Criptografia e chaves |
| **Base legal violada** | **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default · (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Médio-Alto** |

**Problema.** Há uma resolução central e correta de chave HMAC (`security/keys.py`, com
fail-closed em produção). Mas onze módulos de governança a contornam, aceitando a chave como
parâmetro com **default literal**:

```python
# python/buildtovalue/governance/privacy_budget.py:41,142
_DEFAULT_KEY = b"btv-privacy-budget-default-key-v1"
        hmac_key:  bytes = _DEFAULT_KEY,
```

```python
# python/buildtovalue/governance/approval_workflow.py:62
        hmac_key: bytes = b"btv-approval-default-key",
```

Qualquer instanciação que omita `hmac_key` — o caso comum — produz selos assinados com uma chave
que está no código-fonte público. O selo então prova apenas que o dado passou pelo BTV, não que
não foi adulterado. Vale para o `PrivacyBudgetTracker` (que rastreia consumo de dados sensíveis),
para o `MultiPartyKillSwitch` e para o `ApprovalWorkflow`.

O guard G2 do CI (`scripts/ci/lint_guards.sh:76`) já detecta sentinelas HMAC, mas o padrão
`btv-*-default-key` não está na lista de proibições.

**Recomendação.**
1. Remover o default: `hmac_key: bytes` sem valor, resolvido por `get_hmac_key()` no call-site,
   ou injetado pelo lifespan.
2. Estender o guard G2 para rejeitar o regex `hmac_key.*=\s*b"btv-` fora de `security/keys.py`.
3. Substituir a chave literal do MCP (`server.py:474`, `hmac_key=b"btv-mcp-elicitor-v1"`) pela
   resolução central.

---

#### R-013 — Fallback de chave e de JWT ativo em qualquer ambiente que não seja `production`

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/security/keys.py:106-132`; `python/buildtovalue/api/routes/auth.py:27-47`; `rust/kernel/src/keys.rs:88`; `rust/gateway/src/middleware/tenant_extractor.rs:231-246` |
| **Categoria** | Criptografia e chaves · Autenticação |
| **Base legal violada** | **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default |
| **Impacto** | **Médio-Alto** |

**Problema.** O gate de fail-closed compara com a string exata `"production"`:

```python
# python/buildtovalue/security/keys.py:106-132
def _resolve_key_as_bytearray() -> bytearray:
    env = os.environ.get("BTV_ENV", "development").lower()
    raw = os.environ.get("BTV_HMAC_KEY")
    if env == "production":
        if not raw:
            raise HmacKeyUnsetError(...)
    ...
    logger.warning("BTV_HMAC_KEY not set; using insecure dev fallback. ...")
    return bytearray(_DEV_FALLBACK)
```

Qualquer outro valor — `staging`, `homolog`, `prod`, `Production ` com espaço, ou a variável não
definida — cai no fallback `b"btv-dev-key-NOT-FOR-PRODUCTION!!"`. O mesmo vale para o JWT
(`auth.py:47` → `"dev-jwt-fallback-do-not-deploy"`) e para o kernel (`keys.rs:88`).

Pior no gateway: sem `BTV_JWT_SECRET`, o `tenant_extractor` **decodifica o JWT sem verificar a
assinatura** (`tenant_extractor.rs:231-246`) — qualquer token forjado é aceito.

Ambientes de homologação costumam receber cópias ou amostras de dados reais. É exatamente ali que
o fallback está ativo.

**Recomendação.**
1. Inverter a lógica: fail-closed é o default; apenas `BTV_ENV=development` explícito libera o fallback.
2. Normalizar e validar `BTV_ENV` contra um enum fechado; valor desconhecido → recusa de boot.
3. Remover o caminho de decode-sem-verificação do `tenant_extractor` — usar um segredo de teste
   real em dev, não a ausência de verificação.

---

#### R-014 — CORS wildcard no gateway Rust e no proxy do demo

| Campo | |
|---|---|
| **Localização** | `rust/gateway/src/routes/mod.rs:49-52,116`; `demo/proxy.py:229-231`; guard incompleto em `scripts/ci/lint_guards.sh` |
| **Categoria** | Frontend e CORS |
| **Base legal violada** | **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default |
| **Impacto** | **Médio-Alto** |

**Problema.** O gateway aplica CORS irrestrito a **todas** as rotas, incluindo `/v1/proxy/*` e
`/v1/decide`, sem gate de ambiente:

```rust
// rust/gateway/src/routes/mod.rs:49-52
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
```

A API Python faz o certo (`app.py:54-68`: lista explícita e `RuntimeError` se `BTV_CORS_ORIGINS`
não estiver definida em produção), o que torna a inconsistência mais visível: dois serviços da
mesma aplicação com posturas opostas.

O guard G3 do CI só reconhece a sintaxe Python `allow_origins=["*"]` — não cobre `allow_origin(Any)`
do `tower-http` nem o `send_header("Access-Control-Allow-Origin", "*")` do demo. Ou seja, o
controle automatizado existe e passa, enquanto duas das três superfícies estão abertas.

**Recomendação.**
1. `CorsLayer` com `AllowOrigin::list(...)` a partir de `BTV_CORS_ORIGINS`, com `panic!` no boot
   se `BTV_ENV=production` e a variável estiver vazia — espelhando o comportamento do Python.
2. Estender o guard G3 para `allow_origin(Any)` e `Access-Control-Allow-Origin", "*"`.

---

#### R-015 — Rotas sem nenhuma dependência de autenticação, incluindo uma de escrita

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/api/routes/metrics.py:132`; `fleet.py:120`; `intelligence.py:32,91,110` |
| **Categoria** | Segurança de endpoints |
| **Base legal violada** | **Art. 46** · **Art. 6º, VII** |
| **Princípio PbD** | (2) Privacy by Default |
| **Impacto** | **Médio-Alto** |

**Problema.** Contagem de `require_api_key`/`require_jwt` por arquivo de rota: `metrics.py` = 0,
`fleet.py` = 0. O router de inteligência é declarado sem `dependencies`, ao contrário de
`ledger.py:22` e `webhooks.py:27`:

```python
# python/buildtovalue/api/routes/intelligence.py:32
router = APIRouter(prefix="/v1/intelligence/bridge", tags=["intelligence"])
```

| Rota | Arquivo:linha | Exposição |
|---|---|---|
| `GET /v1/metrics` | `metrics.py:132` | agregação do ledger: `block_rate`, `trust_avg`, heatmap 7×24, `top_vectors`, feed de atividade |
| `GET /v1/fleet` | `fleet.py:120` | registry de agentes: `owner`, `model`, `jurisdictions`, `capabilities` |
| **`POST /v1/intelligence/bridge/sync`** | `intelligence.py:91` | **escrita** — dispara geração de políticas em disco |
| `GET /v1/intelligence/bridge/status` | `intelligence.py:110` | estado do bridge |

`POST .../sync` é o mais grave: é uma operação de escrita, anônima, que ainda devolve `str(exc)`
no erro (`intelligence.py:107`), vazando caminhos de filesystem para um chamador não autenticado.

**Recomendação.** Aplicar `dependencies=[Depends(require_api_key)]` no `APIRouter` de
`intelligence`, `metrics` e `fleet`; para `bridge/sync`, exigir JWT com papel administrativo
(depende de R-016). Adicionar teste que enumere as rotas do app e falhe se alguma que toque dado
pessoal não tiver dependência de auth.

---

#### R-016 — Nenhuma verificação de papel (RBAC); `reviewer_id` auto-declarado

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/api/routes/auth.py:176-183`; `routes/appeals.py:161-190`; `_models.py:159-163` |
| **Categoria** | Autorização · Governança de decisão automatizada |
| **Base legal violada** | **Art. 20, §1º** (revisão por pessoa natural, com informação sobre os critérios) · **Art. 46** |
| **Princípio PbD** | (3) Privacidade no Design · (5) Transparência |
| **Impacto** | **Alto** |

**Problema.** O `require_jwt` devolve o papel, e **nenhuma rota o utiliza**:

```python
# python/buildtovalue/api/routes/auth.py:176-183
async def require_jwt(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """FastAPI dependency — validates JWT Bearer token, returns user info."""
    if creds is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    payload = _decode_token(creds.credentials)
    return {"username": payload["sub"], "role": payload["role"]}
```

O papel default de um usuário é `viewer` (`auth.py:115`). E a rota que resolve uma contestação
do Art. 20 exige apenas *um* JWT — qualquer JWT:

```python
# python/buildtovalue/api/routes/appeals.py:161-166
@router.post(
    "/v1/appeals/{appeal_id}/resolve",
    response_model=AppealResponse,
    dependencies=[Depends(require_jwt)],  # CRITICO-03: write requires JWT
)
```

Pior: o identificador do revisor humano vem **do corpo da requisição** (`AppealResolveRequest`,
`_models.py:159-163`), não do token. O sistema registra como revisor quem o requisitante
declarar ser.

Isso ataca diretamente a garantia do Art. 20, §1º: a revisão precisa ser feita por pessoa natural
identificável, e o registro dessa revisão é a prova. Um `reviewer_id` auto-declarado não prova nada.

Existe `_resolve_role` (`_decide_helpers.py:93-123`), mas ele alimenta a pipeline de decisão
ética — não é um gate de autorização.

**Recomendação.**
1. Dependência `require_role("reviewer")` / `require_role("admin")` nas rotas de escrita.
2. Derivar `reviewer_id` do `sub` do JWT; **remover** o campo do corpo da requisição.
3. Tornar o log da revisão imutável, com decisão original, decisão revisada e justificativa —
   como exige o bloco 10 do checklist de escopo.

---

#### R-017 — Access token e refresh token indistinguíveis; sem revogação

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/api/routes/auth.py:155-162,207-220` |
| **Categoria** | Autenticação e sessão |
| **Base legal violada** | **Art. 46** |
| **Princípio PbD** | (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Médio** |

**Problema.** Ambos os tokens são produzidos pela mesma função, com o mesmo payload; a única
diferença é o `exp`:

```python
# python/buildtovalue/api/routes/auth.py:155-162
def _create_token(username: str, role: str, expiry: int) -> str:
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + expiry,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
```

Consequências: um access token de 8h funciona como refresh token; um refresh token de 7 dias
funciona como access token em todas as rotas `require_jwt`; e `/refresh` (`auth.py:207`) não tem
rate limit — só `/login` tem (`auth.py:189`). Não há claim `typ`, não há `jti`, não há denylist,
não há revogação. Um token vazado é válido até expirar, sem recurso.

Também não há **MFA** em nenhum ponto do sistema (varredura por `mfa|2fa|totp|webauthn` retorna
apenas um rótulo de canal em `channel_authority.rs:66`) — exigência do bloco 4 do checklist para
acesso a dados pessoais.

**Recomendação.**
1. Claim `typ: "access" | "refresh"`, validada em cada uso; `/refresh` aceita apenas `typ=refresh`.
2. `jti` + denylist (Redis com TTL = `exp`) para revogação efetiva.
3. Rate limit em `/refresh`.
4. MFA obrigatório para os endpoints de acesso a dados pessoais (a criar em R-004).

---

#### R-018 — Erro 422 ecoa o payload do titular; `str(e)` em 6 rotas; sem `errorId`

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/api/app.py:238-273`; `routes/intelligence.py:107`; `appeals.py:68,191`; `agents.py:341,373`; `compliance.py:231` |
| **Categoria** | Logging e tratamento de erro |
| **Base legal violada** | **Art. 46** · **Art. 6º, VI** (transparência sem exposição indevida) |
| **Princípio PbD** | (2) Privacy by Default |
| **Impacto** | **Médio-Alto** |

**Problema.** O handler global de erro de validação devolve `exc.errors()` no corpo da resposta:

```python
# python/buildtovalue/api/app.py:259-266
async def _validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=_problem_body(422, f"Validation error: {exc.errors()}"),
```

No Pydantic v2, cada item de `errors()` contém a chave `input` — **o valor rejeitado**. Em
`/v1/decide` e `/v1/scan/semantic`, esse valor é justamente o texto do titular, que pode conter
CPF ou dado de saúde. O payload volta ao cliente e vai para os logs de acesso junto com o `detail`.

Seis rotas devolvem `str(e)` da exceção interna. A mais grave é `intelligence.py:107`, porque
aquela rota **não tem autenticação** (R-015) e a exceção vem de uma operação de escrita em
filesystem — caminhos internos vazam para um chamador anônimo.

Além disso, o problem body RFC 7807 **não tem `errorId`**:

```python
# python/buildtovalue/api/app.py:238-248
def _problem_body(status: int, detail: object) -> dict[str, object]:
    ...
    return {
        "type": f"{_PROBLEM_BASE}/{status}",
        "title": _STATUS_TITLES.get(status, "Error"),
        "status": status,
        "detail": msg,
    }
```

Existe um `X-BTV-Request-ID` gerado em `app.py:90-95` e devolvido em header, mas ele não entra no
corpo — o titular não tem como referenciar um erro específico ao acionar o controlador.

**Recomendação.**
1. Substituir `exc.errors()` por uma projeção que preserve apenas `loc` e `type`, descartando `input` e `msg`.
2. Substituir `str(e)` por mensagem genérica; registrar o detalhe internamente correlacionado ao `errorId`.
3. Incluir o `X-BTV-Request-ID` no problem body como `instance` ou `errorId`.
4. Guard de CI que rejeite `detail=str(` em `routes/`.

---

#### R-019 — Stack trace em log de produção; mensagem logada sem redação

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/observability/logging.py:42-63` |
| **Categoria** | Logging e observabilidade |
| **Base legal violada** | **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default · (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Médio** |

**Problema.** O `JSONFormatter` — usado por todo o serviço Python — anexa o traceback completo e
a mensagem verbatim, sem filtro:

```python
# python/buildtovalue/observability/logging.py:43-63
        log_data = {
            ...
            "message": record.getMessage(),      # ← sem redação
            ...
        }
        ...
        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)   # ← stack trace
```

Um `logger.error("falha ao processar %s", payload)` grava o payload; uma exceção levantada durante
o processamento grava o traceback, que frequentemente inclui variáveis locais no texto da mensagem.
Não há allowlist de campos nem passagem pelo `OutputSanitizer`, que já existe no lado Rust.

No gateway há um caso análogo com `session_id` em nível `info`
(`rust/gateway/src/routes/guard.rs:66-71`), contrastando com a invariante declarada em
`rate_limit.rs:13` (*"X-BTV-Tenant-Key nunca aparece em logs"*).

**Recomendação.**
1. Aplicar o sanitizador de PII ao campo `message` antes de serializar.
2. Não incluir `exception` em produção: enviar para um sistema de observabilidade separado
   (Sentry/DataDog) com PII mascarada e acesso restrito.
3. Retenção diferenciada: 30 dias para logs operacionais, 5 anos para auditoria sem PII.

---

#### R-020 — Log de auditoria sem ator, propósito, base legal ou campos acessados; falha silenciosa

| Campo | |
|---|---|
| **Localização** | `rust/gateway/src/routes/validate.rs:304-340`; `rust/gateway/src/routes/decide.rs:1073-1081` |
| **Categoria** | Auditoria |
| **Base legal violada** | **Art. 37** (registro das operações) · **Art. 46** |
| **Princípio PbD** | (5) Transparência · (1) Proativo e Preventivo |
| **Impacto** | **Médio-Alto** |

**Problema.** A linha gravada no `decisions.jsonl` contém metadados de decisão, mas **nenhum** dos
campos que tornam uma trilha auditável sob o Art. 37:

```rust
// rust/gateway/src/routes/validate.rs:315
            "{{\"ts\":{},\"session\":\"{}\",\"profile\":\"{}\",\"policy_action\":\"{}\",\"final_action\":\"{}\",\"mercy\":{},\"risk\":{:.4},\"findings\":{},\"critical\":{},\"hard_blocked\":{},\"verdict_id\":\"{}\",\"latency_ms\":{:.2}}}\n",
```

Faltam: **ator** (quem fez a requisição — só há `session`, que é pseudônimo), **propósito**
(R-005), **base legal**, e **campos acessados**. Sem propósito registrado, a auditoria não
comprova conformidade — apenas registra que algo aconteceu.

E a escrita é *best-effort* silenciosa:

```rust
// rust/gateway/src/routes/validate.rs:332-339
        let _ = std::fs::create_dir_all("data/ledger");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("data/ledger/decisions.jsonl")
        {
            let _ = f.write_all(log_line.as_bytes());
        }
```

Disco cheio, permissão negada ou I/O com erro → a decisão prossegue e **nenhum registro é feito,
sem nenhum sinal**. É precisamente a classe de falha que o README do projeto usa para justificar
sua própria existência: *"Logs de runtime podem ser descartados sob carga, sobrescritos ou
omitidos silenciosamente"*.

O arquivo também não tem cadeia de hash — qualquer linha é editável sem detecção (o ledger binário
encadeado é um sink separado).

**Recomendação.**
1. Acrescentar `actor`, `purpose`, `legal_basis` e `fields_accessed` à linha de auditoria.
2. Tratar falha de escrita do log de auditoria como erro: incrementar métrica, emitir alerta e —
   para operações sobre dado pessoal — considerar fail-secure (recusar a operação que não pode
   ser auditada).
3. Encadear o JSONL por hash, ou remover a duplicidade e usar apenas o ledger binário como fonte
   de verdade.

---

#### R-021 — `/v1/scan/semantic` devolve o texto bruto da PII detectada

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/intelligence/ner_entities.py:60-78`; `python/buildtovalue/api/routes/slm_ner.py:85-103` |
| **Categoria** | Minimização · PII em resposta |
| **Base legal violada** | **Art. 6º, III** (necessidade) · **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default |
| **Impacto** | **Médio-Alto** |

**Problema.** O detector NER devolve o valor da entidade detectada em claro, tanto no dicionário
de finding quanto no `to_dict()`:

```python
# python/buildtovalue/intelligence/ner_entities.py:60-78
            "module": "NER_DETECTOR",
            "rule_id": f"NER_SEMANTIC_{self.entity_type.value}",
            "severity": self.severity,
            "confidence": self.confidence,
            "matched_text": self.text,      # ← valor de PII em claro
            ...
    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type.value,
            "text": self.text,              # ← idem
```

Encadeado em `ner_detector.py:58-60` e retornado sem projeção em `slm_ner.py:103`
(`return result.to_dict()`). O endpoint ainda aceita `Dict[str, object]` cru
(`slm_ner.py:90`), sem cap de tamanho — o único `max_length=50000` do sistema está em
`_models.py:18` e não cobre esta rota.

Um endpoint cuja finalidade é *detectar* PII responde devolvendo a PII, o que a copia para os logs
de acesso do cliente e para qualquer cache intermediário.

**Recomendação.**
1. Devolver `entity_type`, `start`, `end`, `confidence` e um valor mascarado — nunca `text`.
   O chamador já tem o texto original; não precisa recebê-lo de volta.
2. Tipar o corpo da requisição com modelo Pydantic e `max_length`.

---

#### R-022 — Nenhum schema tem atributos de ciclo de vida

| Campo | |
|---|---|
| **Localização** | `api/_db.py:20-46`; `routes/auth.py:112-118`; `governance/contestability/_loop.py:60`; `explanation_store.py:75-112`; `privacy_budget.py:423-431`; `trust_score.py:266-274`; `intelligence/threat_feed.py:24`; `rust/btv-core/src/appeal_writer.rs:74-84` |
| **Categoria** | Catálogo · Retenção |
| **Base legal violada** | **Art. 37** · **Art. 15** · **Art. 16** |
| **Princípio PbD** | (3) Privacidade no Design · (1) Proativo e Preventivo |
| **Impacto** | **Médio-Alto** |

**Problema.** Nenhuma das nove tabelas do sistema tem `finalidade`, `base_legal`, `retencao_ate`
ou `status_retentivo`. Os únicos campos temporais são carimbos (`created_at`, `updated_at`,
`recorded_at`, `timestamp`) — registram quando algo entrou, não quando deve sair.

Aproximações que **não** são retenção:
- `appeals.sla_deadline` (`_loop.py:60`) — prazo de resposta; expirar não apaga nada.
- `SESSION_TTL_DEFAULT = 1800` (`session_manager.py:26`) — TTL de cache LRU em memória.
- `BudgetWindow` (`privacy_budget.py:299-307`) — janela de contagem; as linhas nunca são removidas.

Não há migrations nem ORM: todo DDL é `CREATE TABLE IF NOT EXISTS` inline, sem versionamento
(exceto `appeal_records`, que tem `schema_version`). Isso significa que adicionar um campo de
dado pessoal não deixa rastro revisável.

A retenção precisa ser **atributo estrutural**, não tarefa eventual — é o que torna R-003
implementável.

**Recomendação.**
1. Acrescentar a cada tabela que armazene dado pessoal: `finalidade TEXT NOT NULL`,
   `base_legal TEXT NOT NULL`, `retencao_ate INTEGER NOT NULL`, `status_retentivo TEXT NOT NULL`.
2. `retencao_ate` calculado **na ingestão**, por regra de negócio (trigger ou service), nunca preenchido à mão.
3. Adotar migrations versionadas.
4. Gate de CI: DDL novo com campo de dado pessoal sem registro no catálogo → build falha.

---

#### R-023 — Dashboard Streamlit sem autenticação, exposto em `0.0.0.0:8501`

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/dashboard/app.py` (723 linhas, zero controles de auth); `ops/Dockerfile.streamlit-demo:10-11`; `ops/docker-compose.quickstart.yml:82-83`; `ops/docker-compose.yml:140-141` |
| **Categoria** | Segurança de endpoints |
| **Base legal violada** | **Art. 46** · **Art. 6º, VII** |
| **Princípio PbD** | (2) Privacy by Default |
| **Impacto** | **Médio-Alto** |

**Problema.** O dashboard não tem nenhum mecanismo de autenticação — varredura por `login`,
`password`, `st.secrets`, `session_state` de auth nas 723 linhas retorna zero. E é servido com
bind aberto:

```dockerfile
# ops/Dockerfile.streamlit-demo:10-11
CMD ["streamlit", "run", ..., "--server.address=0.0.0.0", "--server.headless=true"]
```

As páginas incluem "Validate Input" (`app.py:238`, `text_area` livre), "PII Sanitizer"
(`app.py:287`) e "Trust Score Lookup" (`app.py:313`, consulta por `session_id` arbitrário). Quem
alcança a porta 8501 consulta o trust score de qualquer sessão e submete texto ao pipeline.

**Recomendação.** Autenticação obrigatória (reverse proxy com OIDC, ou `st.login`); bind em
`127.0.0.1` com o proxy à frente; não publicar a porta nos composes de referência.

---

#### R-024 — Nenhum mecanismo de consentimento; terceiros carregados antes de qualquer interação

| Campo | |
|---|---|
| **Localização** | `demo/index.html:7-9` e mais 15 páginas; `demo/css/btv.css:2`; `docs/roadmap.html:1`; `mkdocs.yml:144-147` |
| **Categoria** | Consentimento e interface |
| **Base legal violada** | **Art. 7º, I** (consentimento) · **Art. 8º** (forma do consentimento) · **Art. 9º** (informação ao titular) · **Art. 33** (para o fluxo internacional resultante) |
| **Princípio PbD** | (2) Privacy by Default · (7) Centrado no Usuário · (5) Transparência |
| **Impacto** | **Médio-Alto** |

**Problema.** Não existe **nenhum** banner, modal, toggle ou UI de consentimento em todo o
repositório. Varredura por `consent|consentimento|cookie|banner|optin|opt-in` nos `.html`/`.js`
retorna zero ocorrências de UI de consentimento — todos os hits de `cookie` são payloads de
ataque XSS de demonstração.

Consentimento existe apenas como **conceito de backend** que o BTV avalia em terceiros
(`rust/kernel/src/validators/privacy/consent.rs`, `data/policies/compliance/lgpd.yaml`), nunca
como escolha oferecida ao próprio visitante. Não há persistência de consentimento — nem em banco,
nem em `localStorage`.

Enquanto isso, recursos de terceiros são carregados nas **linhas 7 a 9** de 16 páginas, antes de
qualquer script de aplicação e de qualquer possibilidade de gate:

```html
<!-- demo/index.html:7-9 -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:...&display=swap" rel="stylesheet">
```

E o `@import` do design system propaga a chamada a **qualquer** página que carregue o CSS,
inclusive as que não têm o `<link>`:

```css
/* demo/css/btv.css:2 */
@import url('https://fonts.googleapis.com/css2?family=Inter:...&display=swap');
```

O `preconnect` abre conexão TCP+TLS ao Google **antes de qualquer interação**, transmitindo IP e
User-Agent. Há precedente relevante: LG München I, 20.01.2022 (Az. 3 O 17493/20), que tratou
Google Fonts embutido como transferência ilícita de IP.

Google Analytics está configurado no site de documentação, **sem** o bloco `extra.consent` que o
tema MkDocs Material oferece nativamente:

```yaml
# mkdocs.yml:144-147
  analytics:
    provider: google
    property: G-XXXXXXXXXX
```

O `property` é placeholder, mas a configuração está ativa e versionada, e `docs.yml:34,47` a
publica no artefato — basta preencher para começar a rastrear.

**Recomendação.**
1. Auto-hospedar as fontes (`font-src 'self'`), eliminando a transferência. É a correção de menor
   custo e maior efeito.
2. Se o rastreamento for mantido: banner com toggles granulares por finalidade, todos **default
   OFF**, botão "Recusar tudo" com peso visual equivalente a "Aceitar tudo", consentimento
   persistido em banco vinculado a `consentId`, e carregamento de terceiros **bloqueado até** o
   toggle correspondente ser `true`.
3. Configurar `extra.consent` no MkDocs, ou remover o bloco `analytics`.
4. Publicar Política de Privacidade e Política de Cookies (R-045).
5. Revisão trimestral das tags/pixels, com remoção do que não estiver em uso.

---

#### R-025 — JWT em `sessionStorage`; histórico de vereditos em `localStorage`; `session_id` com `Math.random()`

| Campo | |
|---|---|
| **Localização** | `demo/js/api.js:9-12,20,28,47`; `demo/js/session.js:30-44,59-61` |
| **Categoria** | Frontend e storage |
| **Base legal violada** | **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default · (6) Segurança Ponta-a-Ponta |
| **Impacto** | **Médio** |

**Problema.** Três defeitos no mesmo fluxo.

**(a) JWT em `sessionStorage`** — acessível a qualquer script na página:

```js
// demo/js/api.js:20,28
    const stored = sessionStorage.getItem('btv_demo_token');
    ...
          sessionStorage.setItem('btv_demo_token', data.token);
```

O código reconhece o desvio (`api.js:9-12`: *"Em produção, o BuildToValue exige cookies HttpOnly +
Secure… NÃO é um padrão arquitetural do BTV"*). O problema é que o demo é o artefato público, é o
que o avaliador vê, e a exceção documentada não muda o risco para quem o usa.

**(b) Histórico de vereditos em `localStorage` por spread do objeto inteiro:**

```js
// demo/js/session.js:59-61
    addVerdict(verdict) {
      _data.verdict_history.unshift({ ...verdict, ts: Date.now() });
```

Alimentado por `lab-engine.js:176` com a resposta bruta de `/v1/decide`. Como `lab.html` aceita
texto livre — e o propósito declarado da página é justamente demonstrar detecção de PII —
o resultado do processamento de texto que pode conter CPF ou dado de saúde é gravado no disco do
navegador. Há TTL de 24h (`session.js:16,46-52`) e teto de 100/200 entradas, mas não há aviso ao
usuário, base legal, nem controle visível de "apagar meus dados" (existe `Session.clear()` em
`session.js:126`, não exposto em nenhum HTML).

**(c) Identificador de sessão com gerador não criptográfico:**

```js
// demo/js/session.js:39-44
  function _uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
```

Esse `session_id` é enviado à API e usado como chave de trust score — previsível, portanto
sujeito a colisão e a adivinhação por terceiros.

**Recomendação.** Cookie `HttpOnly; Secure; SameSite=Strict` para o token; `localStorage` restrito
a preferências de UI (tema, idioma, layout); histórico de vereditos apenas em memória, ou com
consentimento explícito e controle de exclusão visível; `crypto.randomUUID()` no lugar de
`Math.random()`.

---

#### R-026 — Rate limit com chave controlada pelo cliente; nenhum limite por ator

| Campo | |
|---|---|
| **Localização** | `rust/gateway/src/middleware/rate_limit.rs:87-104`; `python/buildtovalue/api/routes/auth.py:189`; `python/buildtovalue/api/_limiter.py:13` |
| **Categoria** | Segurança de endpoints |
| **Base legal violada** | **Art. 46** |
| **Princípio PbD** | (1) Proativo e Preventivo |
| **Impacto** | **Médio** |

**Problema.** O bucket do gateway é escolhido a partir de headers que o próprio cliente envia:

```rust
// rust/gateway/src/middleware/rate_limit.rs:87-104
fn extract_key(req: &Request<Body>) -> String {
    if let Some(tenant) = req.headers().get("X-BTV-Tenant-Key") {
        if let Ok(val) = tenant.to_str() {
            let hash = blake3::hash(val.as_bytes());
            return format!("tenant:{}", &hash.to_hex()[..16]);
        }
    }
    req.headers()
        .get("X-Forwarded-For")
        ...
        .unwrap_or_else(|| "ip:unknown".to_string())
}
```

Trocar `X-BTV-Tenant-Key` a cada requisição cria um bucket novo — o limite de 60 req/min é
contornado trivialmente. Sem nenhum header, todos os clientes compartilham o bucket `"ip:unknown"`,
o que permite a um cliente esgotar a cota de todos os outros. O endereço real do socket nunca é usado.

No Python, `limiter.limit` aparece **uma única vez** em todo o repositório (`auth.py:189`,
`10/minute` no login), com `key_func=get_remote_address` — por IP, não por ator. `/v1/decide`,
`/v1/multi-decide`, `/v1/scan/semantic`, `/v1/ledger/query` e `/v1/appeals` não têm limite.
O nginx também não tem `limit_req` (zero ocorrências em `ops/nginx/*.conf`).

O checklist de escopo exige rate limit **por ator** em todos os endpoints de listagem —
justamente os que permitem enumeração (R-008).

**Recomendação.** Derivar a chave do bucket da identidade autenticada (hash do `sub` do JWT ou da
API key), com fallback no peer address do socket — nunca em header arbitrário. Aplicar limite por
ator em todas as rotas de listagem. Adicionar `limit_req` no nginx como camada externa.

---

#### R-027 — Agregações do ledger sem k-anonimato, sem supressão de célula e sem autenticação

| Campo | |
|---|---|
| **Localização** | `python/buildtovalue/api/routes/metrics.py:69-79,120-149` |
| **Categoria** | Logging e agregação |
| **Base legal violada** | **Art. 12, §2º** (dado que permite reversão é dado pessoal) · **Art. 46** |
| **Princípio PbD** | (2) Privacy by Default |
| **Impacto** | **Médio** |

**Problema.** `GET /v1/metrics` varre o ledger inteiro da janela, sem cap e sem autenticação
(R-015), e devolve agregações sem nenhuma proteção estatística:

```python
# python/buildtovalue/api/routes/metrics.py:69-79
def _collect_window(since_ms: int) -> List[Entry]:
    out: List[Dict[str, object]] = []
    page = 1
    while True:
        res = _reader.query(LedgerQuery(start_ts=since_ms, page=page, limit=1000))
        out.extend(res.data)
```

O retorno inclui `heatmap` (7 dias × 24 horas), `top_vectors` e um feed de atividade com
`profile`, `verdict_id`, `risk` e `ago_s` (`metrics.py:120-129`). Em volume baixo — o caso de
qualquer instalação nova — uma célula do heatmap com contagem 1, combinada com `profile:
"healthcare"` e `ago_s`, singulariza um titular específico e revela que ele foi tratado num
contexto de saúde.

Não há k-anonimato (k ≥ 5), não há supressão de célula e não há alerta no audit log quando uma
célula é suprimida — os três itens do bloco 6 do checklist.

**Recomendação.** Autenticar a rota; aplicar k-anonimato com k ≥ 5, suprimindo células abaixo do
limiar; registrar cada supressão no log de auditoria; remover `verdict_id` e `ago_s` do feed
público ou arredondar o tempo para faixas largas.

---

### P2 — Médio

---

#### R-028 — CSP ausente no nginx que serve todo o frontend

**Localização:** `ops/nginx/nginx.conf:10-13,56`; `ops/nginx/nginx.vps.conf:9-12,71` · **Categoria:** Frontend/CSP · **Base legal:** Art. 46 · **PbD:** (6) · **Impacto:** Médio

O CSP existe e é bem construído — mas só nas respostas da **API** (`api/response_sanitizer.py:74-92`).
O nginx, que entrega todos os `.html` do demo e da documentação, não emite `Content-Security-Policy`
(zero ocorrências em `ops/nginx/*`), nem `Permissions-Policy`; `Referrer-Policy` existe apenas no
`.vps.conf:12`. Nenhum dos 19 HTMLs tem `<meta http-equiv="Content-Security-Policy">`.

Superfície relevante: 110+ usos de `innerHTML` nas páginas do demo (`Compliance Studio.html`: 21,
`lab.html`: 17, `ledger-explorer.html`: 10). Combinado com JWT em `sessionStorage` (R-025), um XSS
resulta em roubo de token e, via R-016, em resolução de contestações de terceiros.

Nota adicional: o CSP da API, se aplicado ao frontend como está, **quebraria o próprio site** —
`font-src 'self'` bloquearia `fonts.gstatic.com` e `script-src 'self'` bloquearia os scripts
inline. Corrigir R-024 (auto-hospedar fontes) é pré-requisito para aplicar o CSP ao frontend.

**Recomendação:** emitir CSP no nginx com nonce para os inline; migrar os `innerHTML` para
`textContent`/`createElement` onde houver dado do usuário.

---

#### R-029 — Zero Subresource Integrity

**Localização:** todos os recursos externos (`demo/*.html:7-9`, `docs/roadmap.html:1`, `demo/css/btv.css:2`) · **Categoria:** Frontend · **Base legal:** Art. 46 · **PbD:** (6) · **Impacto:** Médio

Nenhum `<link>` ou `<script>` externo tem `integrity=`. Zero ocorrências no repositório inteiro.
Um comprometimento no publisher ou na CDN entrega código arbitrário às páginas que manipulam
input do titular e mantêm o JWT em `sessionStorage`.

**Recomendação:** auto-hospedar (resolve R-024 e R-029 de uma vez) ou adicionar `integrity` +
`crossorigin` a todos os recursos remanescentes.

---

#### R-030 — Quatro bancos de runtime versionados contra a própria política

**Localização:** `git ls-files` vs `.gitignore:30,32,41`; `.pre-commit-config.yaml:40-53` · **Categoria:** Governança de dados · **Base legal:** Art. 46 · **PbD:** (1) · **Impacto:** Médio

| Arquivo | Regra ignorada | Conteúdo |
|---|---|---|
| `data/trust.db` | `.gitignore:41` (`data/*.db`) | 15 sessões com `trust_score`, `offenses` |
| `python/data/appeals.db` | `.gitignore:30` | **54 contestações** com `user_id`, `reason`, `reviewer_notes` |
| `python/data/threats.db` | `.gitignore:30` | 5 registros |
| `ops/runtime/threats.db` | `.gitignore:32` | vazio |
| `ops/nginx/btv-dev.crt` | `.gitignore:48` | certificado de dev |
| `ops/resp.bin` | — | veredito real serializado |

Os dados são sintéticos (`u1`, `alice`, `e2e-tester`, CPFs de documentação da ABNT, `example.com`)
— **não há PII real**. O risco é estrutural: as regras foram adicionadas *depois* dos commits, o
`.gitignore` não destrackeia, e o hook `btv-no-secrets-tracked` (que existe justamente para isso)
foi criado depois. O diretório de runtime está dentro da árvore versionada, então um operador que
rode o sistema localmente e faça `git add -A` commita dados de titulares reais.

**Recomendação:** `git rm --cached` nos seis arquivos; mover o runtime para fora da árvore
(`/var/lib/btv`); estender o hook para rodar também em `pre-push`.

---

#### R-031 — Nenhum gate de privacidade no CI/CD

**Localização:** `.github/workflows/` (11 workflows); `scripts/ci/lint_guards.sh` (3 guards) · **Categoria:** Governança · **Base legal:** Art. 46, Art. 50 (boas práticas) · **PbD:** (1) · **Impacto:** Médio

O que existe: `bandit -lll` (só HIGH), `cargo audit`, TruffleHog `--only-verified`, cobertura ≥75%,
e três guards (G1 `sqlite3.connect`, G2 sentinelas HMAC, G3 CORS `["*"]`).

O que falta:

| Ausente | Consequência |
|---|---|
| Linter de PII em URL | R-008 passou sem detecção |
| Gate de catálogo de dados / ROPA | R-022 passou sem detecção; nada bloqueia tabela nova sem registro |
| `pull_request_template.md` com checklist de finalidade/base legal por campo novo | Bloco 1 do checklist de escopo (PR discipline) não é praticado |
| `CODEOWNERS` | Sem revisor obrigatório para mudanças que tocam dado pessoal |
| `dependabot.yml`, `pip-audit`, `npm audit` | Sem auditoria de dependências Python/JS |
| Scanner de IaC/container (trivy, checkov, kubesec) | R-041 passou sem detecção |
| CodeQL/Semgrep; bandit MEDIUM/LOW | Cobertura SAST rasa |

Observação: TruffleHog `--only-verified` por design **ignora segredos não verificáveis** — chave
HMAC, JWT secret, senha de banco. É exatamente a classe presente em `ops/k8s/00-namespace.yaml`
(R-041). O hook equivalente no pre-commit degrada para no-op se o binário não estiver instalado
(`.pre-commit-config.yaml:35`).

**Recomendação:** implementar os gates acima; priorizar o linter de PII em URL e o gate de
catálogo, que são os que teriam barrado os achados P0 deste relatório.

---

#### R-032 — Webhook sem assinatura, sem allowlist de destino, revelando contexto sensível

**Localização:** `python/buildtovalue/api/webhook_dispatcher.py:47-74,121-127,210-218`; `routes/webhooks.py:48,58,83` · **Categoria:** Fornecedores · **Base legal:** Art. 11, Art. 39 (contrato com operador), Art. 46 · **PbD:** (6) · **Impacto:** Médio

O design está correto no essencial — o payload por construção não inclui o input original
(`webhook_dispatcher.py:49`: *"What gets sent — never includes original input"*). Mas:

1. **Sem assinatura HMAC de saída** (`:214-218`, headers são apenas `Content-Type`, `User-Agent`,
   `X-BTV-Event`) — o receptor não pode autenticar a origem.
2. **Sem validação de URL de destino** (`:121-127` aceita qualquer `w["url"]` do YAML) — SSRF se
   o YAML for gravável, e `POST /v1/webhooks/reload` (`webhooks.py:48`) relê o arquivo a qualquer
   momento sem trilha de auditoria.
3. **`profile` no payload** (`:69`): o valor `"healthcare"` revela ao terceiro que aquela sessão
   foi tratada em contexto de saúde. Combinado com `session_id` (`:70`), é inferência de dado
   sensível transmitida a um destinatário sem DPA verificado.
4. `POST /v1/webhooks/test` devolve `last_error` bruto do httpx (`:233`), vazando topologia interna.

**Recomendação:** assinatura HMAC com chave por parceiro (rotacionável — revogar a chave inutiliza
os dados); allowlist de destinos com HTTPS obrigatório; remover `profile` ou substituí-lo por um
identificador opaco; filtrar o payload pelo contrato de dados do parceiro antes de enviar.

---

#### R-033 — `ExplanationStore` nunca é instanciado; o direito à explicação não é persistido

**Localização:** `python/buildtovalue/governance/explanation_store.py:38,153-164,173-179` · **Categoria:** Direitos do titular · **Base legal:** Art. 20 · **PbD:** (5) · **Impacto:** Médio

`grep -rn "ExplanationStore"` fora dos testes retorna **apenas a definição da classe**. O módulo
que implementa a persistência do direito à explicação (Art. 20) é código morto.

E, se fosse ligado, gravaria dois problemas:

```python
# python/buildtovalue/governance/explanation_store.py:173-179
            context={
                ...
                'ip_address': context.ip_address,     # ← dado pessoal, em claro
            },
```

```python
# python/buildtovalue/governance/explanation_store.py:153-164
            findings_detail=[
                {
                    ...
                    'title': f.title,                  # ← = matched_text (R-001)
                    'description': f.description,
```

O comentário do módulo diz `input_hash: int  # Input original (hash, não o texto real por
privacidade)` (`:28`) — mas `title` vem de `matched_text` via FFI
(`rust/kernel/src/ffi/bridge/serialization.rs:51-53`), o que anula a intenção declarada.

**Recomendação:** decidir — ou ligar o store (e então mascarar `title`/`description` e hashear
`ip_address`), ou removê-lo. Código morto que promete um direito é pior que ausência: cria a
impressão documental de que o direito está implementado.

---

#### R-034 — ADR-0052 (cifra + máscara + TTL) está 0% implementado, mas o catálogo o lista como existente

**Localização:** `docs/adr/0052-forensic-audit-storage.md:3,74-75` vs `docs/mapa-de-dados/README.md:103` · **Categoria:** Governança documental · **Base legal:** Art. 37 · **PbD:** (5) · **Impacto:** Médio

O ADR-0052 especifica AES-256-GCM + máscara + TTL de 90 dias para o armazenamento de auditoria
forense, com status **"🔒 Planejado"**. Verificação:

| Artefato prometido | Existe? |
|---|---|
| `governance/audit_store.py` | ❌ |
| `governance/audit_ttl_runner.py` | ❌ |
| `audit/entries/*.enc` | ❌ |
| `BTV_AUDIT_KEY`, `BTV_AUDIT_TTL_DAYS`, `BTV_AUDIT_HASH_LEDGER` | ❌ zero ocorrências em código |

Ainda assim, `docs/mapa-de-dados/README.md:103` lista essas variáveis no catálogo global **com
defaults** (`90 / data/ledger/audit_hashes.jsonl`), como se estivessem implementadas. Um auditor
externo que leia o catálogo conclui que existe cifra e TTL de auditoria. Não existe.

**Recomendação:** marcar explicitamente no catálogo o que é planejado vs implementado; ou
implementar o ADR-0052, que resolveria parte de R-002 e R-003.

---

#### R-035 — O runbook oficial de Direito ao Esquecimento é inexecutável

**Localização:** `docs/runbooks/BTV-RUN-008.md:9,39-43,76,104,121,124,137` · **Categoria:** Retenção · **Base legal:** Art. 18, VI · Art. 16 · **PbD:** (7) · **Impacto:** Médio

O `BTV-RUN-008` — "Retenção, Custódia e Cripto-Shredding", v1.0.0, com campo *"Aprovado por:
DPO / Compliance Officer (Accountable)"* (`:137`) — é o procedimento oficial de eliminação. O
Procedimento A instrui:

```bash
./btv-validator --execute-shred \
  --tenant-id="TENANT_ID_PLACEHOLDER" \
  --ephemeral-key-id="EPHEMERAL_KEY_ID_PLACEHOLDER" \
  --change-ticket="CHANGE_TICKET_ID"
```

Verificação no repositório: `execute-shred` → 0 ocorrências. `ephemeral_key` → 0.
`aws kms enable-key-rotation` (`:76`) → nenhum uso de KMS. `/mgmt/cache/flush-all` (`:104`) →
rota inexistente. O documento cita ainda "host Java", "buffer JNI" e "Adaptadores JVM"
(`:9,121,124`) — não há JVM neste repositório, que é Rust + Python.

Um runbook aprovado pelo DPO, referenciando um binário e uma arquitetura que não existem, é pior
que a ausência de runbook: numa fiscalização, ele é apresentado como evidência de conformidade e
a inexecutabilidade se torna prova de que o controle nunca foi testado.

**Recomendação:** reescrever o runbook a partir do que existe, ou marcá-lo como **não
implementado** até que R-002 e R-003 sejam resolvidos. Testar o procedimento end-to-end antes de
qualquer nova aprovação do DPO.

---

#### R-036 — Σ (transparency log) com store em memória e chave Ed25519 efêmera

**Localização:** `rust/btv-sigma/src/store.rs:22-23`; `rust/btv-sigma/src/signer.rs:21-32` · **Categoria:** Auditoria e criptografia · **Base legal:** Art. 37, Art. 46 · **PbD:** (6) · **Impacto:** Médio

```rust
// rust/btv-sigma/src/store.rs:22-23
/// In-memory store — reference implementation for tests and development.
pub struct InMemoryStore {
```

```rust
// rust/btv-sigma/src/signer.rs:21-32
    /// In production, load from HSM — see DEPLOYMENT.md.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self { signing_key: SigningKey::from_bytes(&secret) }
    }
```

A cada reinício do processo, o log de transparência passa a ser assinado por **outra identidade** —
o que invalida a verificação de qualquer recibo emitido antes. Os próprios comentários reconhecem
que a implementação é de referência.

**Recomendação:** store persistente e chave Ed25519 carregada de HSM/KMS com pinagem
out-of-band da chave pública. Enquanto isso, não apresentar Σ como controle de conformidade.

---

#### R-037 — Pipeline de treino do SLM sem pseudonimização, consentimento ou teste de disparidade

**Localização:** `python/buildtovalue/intelligence/training/dataset_loader.py`; `fine_tune_slm.py` · **Categoria:** Governança de ML · **Base legal:** Art. 6º, I (finalidade) · Art. 7º, IX · Art. 11 · **PbD:** (3) · **Impacto:** Médio

O pipeline carrega JSONL (`{"text", "label", "source", "confidence"}`) e o converte para formato
de chat, sem nenhuma etapa de: pseudonimização do `text`, verificação de consentimento por
registro, remoção de features proxy, teste de disparidade, nem canary/membership inference antes
do deploy.

Os datasets atuais são sintéticos, o que mitiga o risco **hoje**. Mas nada no código impede que
inputs reais capturados em produção sejam usados como corpus de treino — que é a evolução natural
de um detector de injeção de prompt. Um dado coletado com a finalidade "validação de segurança"
não pode alimentar modelo sem base legal nova (Art. 6º, I).

Também não existe AIA versionado junto ao modelo (existe o `fria_generator.py`, mas nenhum
documento gerado no repositório).

**Recomendação:** pseudonimização obrigatória na ingestão do corpus; verificação de consentimento
por registro no pipeline; teste de disparidade em toda feature candidata; canary + membership
inference antes de promover qualquer modelo; AIA versionado no repo junto ao modelo, atualizado a
cada release.

---

#### R-038 — Chamadas a LLM de terceiro sem auditoria, sem detecção de PII e sem gate de DPA

**Localização:** `python/buildtovalue/agentic/policy_elicitor.py:109-125`; `intelligence/llm_async_client.py:354`; `demo/js/deepseek.js:27`; `sdk/mcp-server/btv_mcp/server.py:462-474` · **Categoria:** Governança de LLM · **Base legal:** Art. 33, Art. 39, Art. 46 · **PbD:** (1) · **Impacto:** Médio

```python
# python/buildtovalue/agentic/policy_elicitor.py:118-125
        client = anthropic.AsyncAnthropic(api_key=self._api_key)
        message = await client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text
```

Nenhuma detecção de PII no prompt, nenhuma pseudonimização, nenhum registro de auditoria da
chamada, nenhuma verificação de DPA ou de opt-out de treino, nenhuma sanitização pós-inferência
do output.

É o achado mais irônico do conjunto: **o produto de governança de chamadas LLM não governa as
próprias chamadas LLM**. Todos os controles que o BTV vende — scan do prompt, veredito, ledger,
evidência — existem para o tráfego do cliente e estão ausentes no tráfego do próprio BTV.

O MCP server ainda usa chave HMAC literal (`server.py:474`, `hmac_key=b"btv-mcp-elicitor-v1"`) e
devolve `str(exc)` em quatro handlers (`:332,334,504,548`).

**Recomendação:** rotear as chamadas internas de LLM pelo próprio `/v1/proxy` — o produto deve
ser seu primeiro cliente. Auditar cada chamada com preview do prompt e PII detectada; exigir DPA
aprovado programaticamente antes de liberar o provedor; para dado de saúde ou biometria, exigir
modelo on-prem.

---

#### R-039 — Rotas fantasma quebram o canal de contestabilidade via gateway

**Localização:** `rust/gateway/src/routes/appeals.rs:26,71`; `health_bias.rs:48` · **Categoria:** Direitos do titular · **Base legal:** Art. 20 · **PbD:** (7) · **Impacto:** Médio

O gateway proxeia para três endpoints que **não existem** no serviço Python:

| Gateway chama | Python define |
|---|---|
| `POST {gov}/v1/appeals/submit` (`appeals.rs:26`) | `POST /v1/appeals` (`appeals.py:47`) |
| `GET {gov}/v1/appeals/pending` (`appeals.rs:71`) | — |
| `GET {gov}/v1/bias/status` (`health_bias.rs:48`) | — |

Requisições caem no catch-all 404 (`app.py:287`) e o gateway devolve `BAD_GATEWAY`. Ou seja:
**`POST /v1/appeals` pelo gateway sempre falha**. O canal de contestação de decisão automatizada
— o único direito do titular que o sistema alega implementar — está quebrado no caminho
documentado como principal.

**Recomendação:** corrigir os três paths; adicionar teste de contrato e2e que exercite o fluxo
completo de appeal via gateway.

---

#### R-040 — Eficácia medida do detector de PII muito abaixo da declarada

**Localização:** `ops/red-team/reports/RT-002-20260226-202212.json`; `RT-001-20260226-202007.json`; contraste com `docs/compliance.md:29-36` · **Categoria:** Adequação da medida de segurança · **Base legal:** Art. 46 (medidas **aptas**) · **PbD:** (5) Transparência · **Impacto:** Médio-Alto

Os próprios relatórios de red-team versionados no repositório medem:

| Cenário | Detecção | Bypass medido | FNR declarado |
|---|---|---|---|
| RT-002 (evasão de PII) | **32,5%** | **42,5%** | 18,0% |
| RT-001 (injeção, 26/02) | 44,1% | 41,2% | 18,0% |
| RT-001 (injeção, 24/02) | 51,1% | 26,7% | 18,0% |

```json
"bias_declaration_comparison": {
  "declared_fnr_pct": 18.0,  "declared_fpr_pct": 8.0,
  "measured_bypass_rate_pct": 42.5, "measured_fpr_pct": 22.5 }
```

O bypass medido é **2,4× o declarado**; o FPR medido é 2,8× o declarado. Enquanto isso,
`docs/compliance.md:29-36` afirma sem ressalva: *"Sim. O kernel Rust tem detectores nativos
para: CPF e CNPJ (com validação de dígito verificador)…"*.

O Art. 46 não exige medidas de segurança quaisquer — exige medidas **aptas** a proteger os dados.
Uma medida com 32,5% de eficácia medida, documentada pelo próprio fornecedor, tem sua aptidão em
questão. E o desalinhamento com a `BiasDeclaration` significa que o número que o sistema publica
sobre si mesmo está errado.

Agravante correlato (**R-046**): os logs de red-team versionados (`RT-006-*.log`,
`testes1/testesGit.txt`) listam explicitamente os bypasses conhecidos — publicando um mapa de
evasões não mitigadas.

**Recomendação:** atualizar a `BiasDeclaration` para os valores medidos (transparência primeiro);
ajustar `docs/compliance.md` para declarar a eficácia real e as limitações; tratar a lacuna de
detecção como backlog priorizado; mover os logs de bypass para um repositório privado enquanto
não mitigados.

---

#### R-041 — Secret k8s em texto plano; Deployment que o próprio PSS rejeitaria; egress mal configurado

**Localização:** `ops/k8s/00-namespace.yaml:48-58`; `ops/k8s/compliance-deployment.yaml:16-50`; `ops/k8s/security/pod-security-policy.yaml:110-119` · **Categoria:** Infraestrutura · **Base legal:** Art. 46 · **PbD:** (6) · **Impacto:** Médio

```yaml
# ops/k8s/00-namespace.yaml:48-58
kind: Secret
metadata: { name: buildtovalue-secrets, namespace: buildtovalue }
type: Opaque
stringData:
  DATABASE_URL: "postgresql://btv_prod:SECURE_PASSWORD@postgres-service:5432/buildtovalue"
  SIGNING_KEY: "REPLACE_WITH_ACTUAL_KEY_32_BYTES_LONG_SECURE_KEY"
  SMTP_PASSWORD: "email_password_here"
```

Os valores são placeholders, mas o template convida à substituição in-place e commit — e o
TruffleHog `--only-verified` não detectaria essa classe (R-031). Convive de forma contraditória
com o `sealed-secret.yaml` do mesmo diretório. O `SMTP_PASSWORD` indica um canal de e-mail
(notificações → possível PII) não mapeado em nenhum ROPA.

`compliance-deployment.yaml:16-50` não define `securityContext` algum — nem `runAsNonRoot`, nem
`allowPrivilegeEscalation: false`, nem `capabilities.drop`, nem `seccompProfile`. Sob o Pod
Security Admission `restricted` que o próprio namespace enforça
(`pod-security-policy.yaml:17-26`), esse Deployment **seria rejeitado pelo admission controller**
e suas 3 réplicas nunca subiriam. Ele monta o PVC `wal-pvc` (10 Gi) em `/data` com
`WAL_PATH=/data/threats.wal` — volume de dados forenses sem `StorageClass` nem criptografia
declarada.

A regra de egress rotulada "Allow HTTPS external" usa `namespaceSelector: {}`, que seleciona pods
do cluster, não endereços externos (detalhado em R-009) — não faz o que o comentário afirma.

**Positivo a preservar:** PSS `restricted` no namespace, NetworkPolicy com default-deny,
`runAsNonRoot`/`runAsUser: 1000` em `10-deployment.yaml:35-38`, segredos via `secretKeyRef`,
SealedSecret, e nenhum `privileged`/`hostNetwork`/`docker.sock` em lugar nenhum.

**Recomendação:** remover o Secret com `stringData` (usar apenas SealedSecret); adicionar
`securityContext` ao `compliance-deployment.yaml`; corrigir o egress para `ipBlock` com CIDR
explícito; habilitar criptografia no `StorageClass`; adicionar `seccompProfile` a todos os pods.

---

#### R-042 — Containers rodando como root; credencial default no compose

**Localização:** `ops/Dockerfile.streamlit-demo`; `ops/emulator/Dockerfile`; `ops/docker-compose.yml:103,123` · **Categoria:** Infraestrutura · **Base legal:** Art. 46 · **PbD:** (6) · **Impacto:** Baixo-Médio

Dois Dockerfiles sem diretiva `USER` — rodam como root: `Dockerfile.streamlit-demo` (que ainda
faz `--server.address=0.0.0.0`, R-023) e `ops/emulator/Dockerfile`. Os outros sete estão
corretos (`Dockerfile.python:25`, `.rust:58`, `.streamlit:47`, `.playground:20` — todos com
`USER btv`).

`ops/docker-compose.yml:103` — `GF_SECURITY_ADMIN_PASSWORD=${GF_ADMIN_PASSWORD:-changeme}`;
`:123` — `BTV_API_KEY=${BTV_API_KEY:-dev-key}`. Defaults funcionais em vez de falha.

Ponto de contraste positivo: `ops/docker-compose.yml:48` faz o certo —
`BTV_HMAC_KEY=${BTV_HMAC_KEY:?generate_with_openssl}` falha se não definida.

**Recomendação:** adicionar `USER` aos dois Dockerfiles; trocar `:-default` por `:?erro` em todas
as credenciais dos composes.

---

#### R-043 — Paginação sem cursor; `total` exposto; listagens sem cap

**Localização:** `ledger_reader.py:67`; `_models.py:92,148,207,232`; `rust/gateway/src/routes/appeals.rs:67`; `routes/agents.py:344` · **Categoria:** Anti-enumeração · **Base legal:** Art. 6º, III · Art. 46 · **PbD:** (2) · **Impacto:** Médio

Duas rotas paginam corretamente com hard limit (`/v1/ledger/query` `le=1000`, `/v1/appeals`
`le=100`) — o resto não:

| Rota | Paginação | Cap |
|---|---|---|
| `GET /v1/fleet` | ❌ | — |
| `GET /v1/metrics` | ❌ | varre a janela inteira |
| `POST /v1/intelligence/query` | ❌ | `limit: int = 50` sem `le=` |
| `POST /v1/compliance/art20/report` | ❌ | `max_decisions: int = 500` sem `le=` |
| `GET /v1/appeals/pending` (gateway) | ❌ | lista integral |
| `GET /v1/delegation/{id}/chain` | ❌ | cadeia inteira |
| `POST /v1/multi-decide` | n/a | `agent_ids: List[str]` sem `max_items` |

**Não há paginação por cursor em lugar nenhum** — só offset/page, que é o padrão mais favorável à
enumeração. E `total` é exposto em ambos os envelopes paginados (`ledger_reader.py:67`,
`_models.py:148`) para qualquer role, permitindo estimar o volume de titulares tratados.

**Recomendação:** cursor-based em todas as listagens; hard limit em todas; ocultar `total` de
roles não confiáveis.

---

#### R-044 — Documentação afirma "100% on-premises, nenhum dado enviado a servidores externos"

**Localização:** `docs/compliance.md:113,137` · **Categoria:** Transparência · **Base legal:** Art. 6º, VI · Art. 9º · **PbD:** (5) · **Impacto:** Médio

> *"O BTV é software on-premises — você o opera na sua infraestrutura. Não há transmissão de dados
> para servidores Anthropic ou BuildToValue."* (`:113`)
>
> *"Não. O BTV é 100% on-premises. O gateway Rust e o judiciário Python rodam na sua
> infraestrutura. Nenhum dado é enviado para servidores externos."* (`:137`)

Contraditado por R-009 e R-038. A afirmação está na trilha "DPO / CISO" — exatamente o público que
a usaria para decidir se o produto é adequado. É informação que induz a erro na avaliação de
adequação, o que sob o Art. 9º compromete a informação clara ao titular por parte do
controlador-cliente.

**Recomendação:** reescrever a seção declarando exatamente quais fluxos saem da infraestrutura do
cliente, em que condições, e como desligá-los. O `BTV_PROXY_UPSTREAM_URL` **pode** apontar para um
modelo local — esse é o argumento honesto, e é forte.

---

#### R-045 — Documentos de conformidade ausentes; sem canal do titular

**Localização:** ausência em `docs/`, raiz; `SECURITY.md:8` · **Categoria:** Governança documental · **Base legal:** Art. 9º, Art. 37, Art. 38, Art. 39, Art. 41 · **PbD:** (5) (7) · **Impacto:** Médio

| Documento | Artigo | Status |
|---|---|---|
| Política de Privacidade / aviso ao titular | Art. 9º | ❌ — há site público sem aviso |
| ROPA preenchido (existe só o gerador) | Art. 37 | ❌ |
| RIPD / DPIA | Art. 38 | ❌ — endereçado por esta entrega |
| DPA / contrato de operador | Art. 39 | ❌ |
| SCC / mecanismo de transferência internacional | Art. 33-35 | ❌ |
| Registro de subprocessadores | Art. 37 | ❌ — OpenAI, Anthropic, DeepSeek, AWS, Google, Fly.io não listados |
| Política de retenção formal | Art. 15-16 | ❌ |
| Política de cookies | Art. 9º | ❌ |
| Plano de resposta a incidente de dados pessoais + SLA de notificação à ANPD | Art. 48 | ⚠️ existe `BTV-RUN-010`, mas de escopo estreito (só poluição cruzada entre tenants) |
| Nomeação formal do encarregado (DPO) + canal do titular | Art. 41 | ❌ — `SECURITY.md:8` traz um Gmail pessoal, para vulnerabilidades |

O Art. 41, §1º exige que a identidade e as informações de contato do encarregado sejam divulgadas
publicamente, de forma clara e objetiva.

**Recomendação:** produzir os documentos acima; publicar a Política de Privacidade no site;
nomear formalmente o encarregado com canal dedicado, distinto do canal de vulnerabilidades.

---

#### R-046 — Logs de red-team versionados publicam mapa de evasões não mitigadas

**Localização:** `ops/red-team/reports/RT-006-2026*.log`; `ops/red-team/testes1/testesGit.txt` (613 linhas) · **Categoria:** Governança de divulgação · **Base legal:** Art. 46 · **PbD:** (1) · **Impacto:** Baixo-Médio

```
❌ [BYPASS]   phishing-account-compromised → action=ALLOW findings=0 (EXPECTED BLOCK)
❌ [BYPASS]   impersonation-pt-receita-federal → action= findings=0 (EXPECTED BLOCK)
```

Não é PII, mas é divulgação de vulnerabilidade não mitigada em repositório público. Os mesmos
arquivos registram um bug operacional (`RT-006-20260226-2129.log:16`: `line 55: $5: unbound
variable`), o que sugere que parte da suíte não executa corretamente.

**Recomendação:** mover os logs de bypass para repositório privado enquanto não mitigados;
manter públicas apenas as métricas agregadas.

---

#### R-047 — Artefatos de runtime e arquivos órfãos versionados

**Localização:** `ops/resp.bin` (935 B); `ops/exporting`, `ops/naming`, `ops/resolving`, `ops/unpacking` (0 B) · **Categoria:** Higiene de repositório · **Impacto:** Baixo

`ops/resp.bin` contém um veredito real serializado
(`{"verdict_id":"VRD-1771642389-000006","action":"LOG","mercy_scenario":"S5_REPEAT_LENIENCY","trust_score":0.52,...}`).
Os quatro arquivos de 0 byte são resíduo de saída de terminal.

**Recomendação:** `git rm` nos cinco.

---

#### R-048 — Excisão pendente de `ops/.env` do histórico — requer confirmação em clone completo

**Localização:** `scripts/ci/lint_guards.sh:86`; commit `d726430` ("chore(security): untrack ops/.env") · **Categoria:** Secrets · **Base legal:** Art. 46, Art. 48 · **Impacto:** A determinar

O script de guards contém o comentário:

```bash
# ops/.env will be excised by the scheduled git filter-repo.
```

O tempo verbal indica que a reescrita de histórico ainda **não havia ocorrido** quando o comentário
foi escrito. Neste ambiente a verificação é impossível: o clone é raso
(`.git/shallow`, 50 commits) e `git log --all -- ops/.env` retorna vazio — o que é consistente
tanto com "já foi excisado" quanto com "está além da profundidade do clone".

**Este item não é um achado confirmado.** É uma pendência de verificação obrigatória.

**Recomendação.** Em clone completo (`git clone --no-single-branch` sem `--depth`), executar:

```bash
git log --all --diff-filter=A -- 'ops/.env'
git rev-list --all | xargs -I{} git ls-tree -r {} --name-only 2>/dev/null | grep -c '^ops/\.env$'
```

Se houver qualquer ocorrência: tratar como incidente de segurança — rotacionar **todas** as
credenciais que constavam do arquivo, executar `git filter-repo`, forçar a atualização de todos
os forks e clones, e registrar o incidente na cadeia de evidências (Art. 48).

---

## 4. Cobertura do checklist de escopo

Item a item, os 13 blocos do escopo da revisão. `✅` conforme · `❌` não conforme · `⚠️` parcial · `n/a` não aplicável.

### 1. Consentimento e interface do usuário

| Item | Status | Risco |
|---|---|---|
| Toggles granulares por finalidade | ❌ | R-024 |
| Default OFF | ❌ (não há toggle) | R-024 |
| "Recusar tudo" com peso visual equivalente | ❌ | R-024 |
| Consentimento persistido em banco vinculado a `userId`/`consentId` | ❌ | R-024 |
| PR discipline (finalidade, base legal, impacto da remoção) | ❌ sem PR template, sem CODEOWNERS | R-031 |
| Consentimento como trigger de scripts de terceiros | ❌ carregam nas linhas 7-9 | R-024 |

### 2. Minimização e limitação de finalidade

| Item | Status | Risco |
|---|---|---|
| Cada rota declara a finalidade | ❌ | R-005 |
| Handler não retorna mais campos que a finalidade permite | ❌ DTO de escopo único | R-008 |
| Nunca retornar entidade de ORM direto | ⚠️ 12 rotas com `response_model`; 10+ com `to_dict()` cru | R-021 |
| Campos sensíveis mascarados mesmo para admin | ❌ | R-001, R-021 |
| Limite contrato vs. marketing cruzado | n/a | — |
| Legítimo interesse não vale para dado sensível | ❌ ROPA declara Art. 7º, IX para dado do Art. 11 | R-010 |

### 3. Segurança de endpoints e PII

| Item | Status | Risco |
|---|---|---|
| PII nunca na URL; linter bloqueia | ❌ `?user_id=`; sem linter | R-008, R-031 |
| Checagem de posse explícita | ❌ zero ocorrências | R-008 |
| 404, nunca 403 | ⚠️ retorna 404, mas de inexistência — sem posse não há distinção | R-008 |
| UUID no path para rotas públicas | ⚠️ `session_id`/`appeal_id` opacos, mas sem validação | R-008 |
| Busca por CPF/e-mail via POST com hash | ❌ | R-008 |
| Rate limit por ator em listagens | ❌ por header controlado pelo cliente / por IP | R-026 |
| Paginação obrigatória com hard limit; `TotalItems` oculto | ⚠️ 2 de 9 listagens; `total` sempre exposto | R-043 |
| Cursor-based | ❌ zero | R-043 |
| Propósito obrigatório | ❌ | R-005 |
| Middleware de admin com propósito explícito | ❌ | R-005, R-016 |
| Webhook = evento, não dados | ⚠️ sem input original ✅, mas envia `profile` e sem assinatura | R-032 |

### 4. Autenticação, sessão e tokens

| Item | Status | Risco |
|---|---|---|
| JWT em cookie HttpOnly ou header via memória | ❌ `sessionStorage` no demo | R-025 |
| `localStorage` só para preferências de UI | ❌ guarda histórico de vereditos | R-025 |
| `sessionStorage` sem PII sensível | ❌ guarda o token | R-025 |
| MFA obrigatório para dados pessoais | ❌ inexistente | R-017 |
| Eliminação permanente com verificação descartada após uso | ❌ não há endpoint | R-004 |
| Propósito no token é revogável | ❌ não há claim de propósito | R-005, R-017 |

### 5. Frontend, terceiros e CSP

| Item | Status | Risco |
|---|---|---|
| CSP obrigatório | ⚠️ só na API, ausente no nginx que serve o frontend | R-028 |
| SRI obrigatório | ❌ zero ocorrências | R-029 |
| Review trimestral de tags/pixels | ❌ sem processo | R-024 |
| Default: bloquear tudo antes do consentimento | ❌ | R-024 |
| Review periódico dos dashboards de terceiros | ❌ | R-024 |

### 6. Logging, auditoria e observabilidade

| Item | Status | Risco |
|---|---|---|
| Log append-only com ator, recurso, propósito, base legal, campos, timestamp | ❌ faltam 4 dos 6 | R-020 |
| Propósito registrado em cada acesso | ❌ | R-005, R-020 |
| Nenhum log de produção contém PII | ❌ `message` verbatim | R-019 |
| Stack trace nunca logada em produção | ❌ | R-019 |
| Retenção: operacional 30d, auditoria 5 anos sem PII | ❌ inexistente | R-003 |
| Erros sem stack trace nem dados do titular; `errorId` | ❌ 422 ecoa o payload; sem `errorId` | R-018 |
| k-anonimato (k ≥ 5) com alerta de supressão | ❌ | R-027 |

### 7. Criptografia, chaves e backup

| Item | Status | Risco |
|---|---|---|
| Envelope encryption (DEK + KEK no KMS); nunca chave hardcoded | ❌ inexistente; 11 chaves hardcoded | R-002, R-012 |
| Rotação automática com recifragem gradual | ❌ API existe, sem caller nem agendamento | R-002 |
| Chave própria por campo sensível | ❌ | R-002 |
| Acesso ao KMS auditado | ❌ não há KMS | R-002 |
| Backup com TTL, chave segregada, expurgo pós-restore | ❌ não há backup; `cp -r` em claro no killswitch | R-002 |
| Destruição de backup documentada e auditada | ❌ | R-002, R-035 |

### 8. Retenção, expurgo e ciclo de vida

| Item | Status | Risco |
|---|---|---|
| Atributos de ciclo de vida por tabela/campo | ❌ nenhuma das 9 tabelas | R-022 |
| `retencao_ate` calculada na ingestão | ❌ | R-022 |
| Job de expurgo diário com evidência | ❌ | R-003 |
| Retenção como atributo estrutural | ❌ | R-003, R-022 |
| `DELETE /me/dados` com efeito cascata | ❌ | R-004 |

### 9. Catálogo, ROPA e linhagem

| Item | Status | Risco |
|---|---|---|
| Todo campo com dado pessoal registrado antes de produção; CI bloqueia | ❌ sem gate | R-022, R-031 |
| Catálogo como fonte única de verdade | ⚠️ `docs/mapa-de-dados/` existe, mas manual, sem classificação de sensibilidade e parcialmente desatualizado | R-022, R-034 |
| ROPA gerado do catálogo | ❌ hardcoded | R-010 |
| Linhagem imutável por pipeline ETL | ❌ | R-022 |
| Queries de impacto pré-definidas (5 min para a ANPD) | ❌ | R-004 |
| Nunca conceder acesso à zona bruta | n/a arquitetura não tem zonas | — |
| Views mascaradas como padrão | ❌ | R-002 |

### 10. Governança de ML/AI e LLMs

| Item | Status | Risco |
|---|---|---|
| Decisão automatizada com explicação legível + canal de revisão | ⚠️ `explain` existe; canal quebrado e sem RBAC | R-016, R-039 |
| Log de revisão imutável com decisão original e justificativa | ❌ `reviewer_id` auto-declarado | R-016 |
| Dado de uma finalidade não alimenta modelo sem base legal nova | ❌ sem verificação no pipeline | R-037 |
| Dataset de treino pseudonimizado por padrão | ❌ | R-037 |
| Teste de disparidade por feature | ❌ | R-037 |
| Features proxy discriminatórias removidas | ❌ | R-037 |
| AIA versionado junto ao modelo | ❌ gerador existe, documento não | R-037 |
| Teste de extração (canary + membership inference) | ❌ | R-037 |
| Sanitização pós-inferência | ⚠️ `OutputSanitizer` na resposta HTTP; não no output de LLM interno | R-038 |
| Leak detectado → modelo bloqueado e retreinado | ❌ | R-037 |
| Nada sensível para LLM de terceiro sem DPA + opt-out + pseudonimização | ❌ | R-038 |
| Saúde/biometria em modelo on-prem | ❌ sem gate | R-009, R-038 |
| Cada chamada a LLM externo auditada com preview e PII detectada | ❌ | R-038 |

### 11. Fornecedores e transferência internacional

| Item | Status | Risco |
|---|---|---|
| DPA validado programaticamente antes da integração | ❌ | R-009, R-045 |
| Fornecedor sem DPA não recebe dados (bloqueio no gateway) | ❌ | R-009 |
| Nada sensível sai do Brasil sem mecanismo válido | ❌ | R-009 |
| Gateway bloqueia região sem SCC/adequação | ❌ | R-009 |
| SCCs versionadas com hash | ❌ | R-045 |
| Contrato de dados por parceiro com allowlist de campos | ❌ | R-032 |
| Gateway filtra payload pelo contrato | ❌ encaminha o corpo íntegro | R-009 |
| Chave de criptografia por parceiro, rotacionável | ❌ | R-002, R-032 |
| Revogação automatizada com SLA de 24h | ❌ | R-045 |

### 12. Direitos dos titulares

Todos os nove incisos do Art. 18: ❌ — ver R-004. Art. 20 existe mas quebrado (R-039) e sem
controle de posse (R-008, R-016).

### 13. Incidentes de segurança

| Item | Status | Risco |
|---|---|---|
| Plano de resposta documentado e testado | ⚠️ `BTV-RUN-010` cobre só poluição cruzada entre tenants | R-045 |
| Cadeia de evidências preservada | ⚠️ ledger existe; sem ator/propósito, e falha silenciosa | R-020 |
| SLA de notificação à ANPD em automação e alertas | ❌ | R-045 |
| Análise de cenário de incidente em cada review | ❌ sem PR template | R-031 |

---

## 5. Correções aplicadas ao levantamento

Registradas por transparência metodológica — em três pontos a evidência primária contradisse a
leitura inicial, e a versão abaixo é a correta:

1. **Sync remoto do WAL não é automático.** `rust/kernel/src/ledger/remote/sync.rs:41` traz
   `enabled: false`. O achado correto (R-009) é que o *default de região*, quando o operador
   habilita a replicação, é `us-east-1` — falha de Privacy by Default, não exfiltração automática.
2. **O `LedgerEntry` binário de 384 B não contém PII.** Ele carrega apenas hashes
   (`entry.rs:52-70`). A PII bruta está no `WalEntry.evidence_snapshot` (`wal.rs:32-45`), que é
   um sink distinto. R-001 se refere ao WAL, não ao ledger encadeado.
3. **O `FALLBACK_HMAC_KEY` de `compute_verdict_id` é praticamente inalcançável** — HMAC aceita
   chave de qualquer comprimento, então `new_from_slice` não falha. O problema real de R-011 é
   `finalize()` (`entry.rs:120-128`), que passa `&[0u8; 32]` **explicitamente**.

Também corrigida a leitura da NetworkPolicy: a regra "Allow HTTPS external"
(`pod-security-policy.yaml:110-119`) usa `namespaceSelector: {}` e portanto **não** libera
destinos externos — não é um "allow 0.0.0.0/0:443". O achado é que a regra não faz o que declara
e que, de todo modo, não existe gate de jurisdição (R-009, R-041).

---

## 6. Plano de remediação priorizado

### Onda 1 — bloqueia qualquer deploy com dado pessoal real

| Ordem | Risco | Ação | Esforço | Depende de |
|---|---|---|---|---|
| 1 | **R-001** | Mascarar `matched_text` no validador do Art. 11 e nos 3 ramos restantes | Baixo | — |
| 2 | **R-006** | Roteamento explícito de estáticos; remover bypass por sufixo | Baixo | — |
| 3 | **R-014** | CORS por allowlist no gateway, fail-closed em produção | Baixo | — |
| 4 | **R-015** | Adicionar `dependencies` de auth a `metrics`, `fleet`, `intelligence` | Baixo | — |
| 5 | **R-018** | Remover `input` do 422; `errorId` no problem body | Baixo | — |
| 6 | **R-016** | `require_role`; `reviewer_id` do JWT | Médio | — |
| 7 | **R-007** | Remover auto-login; origem restrita; papel `viewer` no demo | Baixo | R-016 |
| 8 | **R-008** | Checagem de posse; escopo derivado do token; DTOs por escopo | Médio | R-005 |
| 9 | **R-009** | Gate de jurisdição no proxy; redação antes do encaminhamento | Médio | — |
| 10 | **R-010** | Corrigir base legal e `cross_border_transfer` no ROPA | Baixo | R-022 |

*Correções 1-5 e 7 são de baixo risco de regressão e alto efeito — são o ponto de partida natural.*

### Onda 2 — estrutural

| Risco | Ação | Esforço |
|---|---|---|
| **R-022** | Atributos de ciclo de vida em todas as tabelas; migrations versionadas | Médio |
| **R-005** | Header/claim `X-Purpose` obrigatório; enum de finalidades | Médio |
| **R-002** | Envelope encryption com DEK/KEK em KMS; chave por campo sensível | Alto |
| **R-003** | Job de expurgo diário com evidência; cripto-shredding para o ledger | Alto |
| **R-004** | Sete endpoints do Art. 18, com prazo, MFA e log | Alto |
| **R-020** | Ator, propósito, base legal e campos no log de auditoria; falha não silenciosa | Médio |
| **R-011** | Tornar `signing_key` obrigatório; depreciar `finalize()` | Médio |

### Onda 3 — governança e defesa em profundidade

R-012, R-013, R-017, R-019, R-021, R-023 a R-047 — com prioridade para **R-031** (gates de CI),
porque é o que impede a reintrodução de tudo o mais, e para **R-024** (auto-hospedar fontes),
que resolve consentimento, CSP e SRI de uma só vez.

### Onda 0 — imediata, independente de código

- **R-048**: verificar `ops/.env` em clone completo. Se confirmado, tratar como incidente (Art. 48).
- **R-030, R-047**: `git rm --cached` nos artefatos de runtime.
- **R-044**: corrigir `docs/compliance.md` — é uma afirmação incorreta em documento público de conformidade.
- **R-040**: alinhar a `BiasDeclaration` aos valores medidos.
- **R-046**: mover os logs de bypass para repositório privado.

---

## 7. Referências

- Lei nº 13.709/2018 (LGPD), com as alterações da Lei nº 13.853/2019
- Cavoukian, A. *Privacy by Design — The 7 Foundational Principles*
- ANPD — Guia Orientativo sobre Tratamento de Dados Pessoais pelo Poder Público; Guia de Segurança da Informação para Agentes de Tratamento de Pequeno Porte
- LG München I, 20.01.2022, Az. 3 O 17493/20 (Google Fonts / transferência de IP)
- Documentos internos: [`docs/mapa-de-dados/`](../mapa-de-dados/README.md), [`docs/adr/`](../adr/0000-adr-index.md), [`docs/runbooks/`](../runbooks/README.md), [`SECURITY.md`](../../SECURITY.md)

---

*Documento gerado por revisão de engenharia. Complementado por [RIPD.md](RIPD.md).*
