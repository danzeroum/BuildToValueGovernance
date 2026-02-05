

**Sistema híbrido Rust/Python para governança ética de agentes de IA**

---

## Visão Geral

BuildToValue é um sistema experimental de governança projetado para aplicar restrições éticas ao comportamento de agentes de IA. Combina validadores de baixo nível (Rust) com raciocínio contextual (Python) para detectar violações de política e aplicar respostas proporcionais.

O projeto surgiu de uma necessidade prática: motores de regras existentes ou bloqueiam de forma muito agressiva (frustrando usuários) ou permitem de forma muito permissiva (arriscando danos). Tentamos equilibrar detecção técnica com julgamento ético.

**Status atual:** Protótipo de pesquisa. 95% completo. Ainda não pronto para produção.

---

## Motivação

Agentes de IA podem causar danos não intencionais ao processar dados sensíveis (PII, informações financeiras, registros de saúde) sem salvaguardas apropriadas. Abordagens tradicionais enfrentam trade-offs:

- **Blocklists:** Rápidas mas frágeis. Muitos falsos positivos.
- **Baseadas em ML:** Precisas mas opacas. Difícil explicar decisões.
- **Motores de regras:** Transparentes mas inflexíveis. Cegas ao contexto.

BuildToValue explora um híbrido: validadores determinísticos (Rust) geram evidências, enquanto raciocínio contextual (Python) interpreta essas evidências considerando histórico do usuário, incerteza e direito de recurso.

Nos baseamos em filosofia ética (Rawls, Levinas, Gilligan, Jonas) não por novidade, mas porque esses frameworks abordam diretamente justiça, cuidado e responsabilidade—conceitos sub-representados em sistemas de segurança tradicionais.

---

## Arquitetura

### 1. Rust Sovereign Kernel (Executivo)

**Propósito:** Detecção rápida e determinística de padrões. Gera evidências forenses.

**Componentes:**
- **Validators:** CPF, CNPJ, Cartão de Crédito, checksum Luhn (29 módulos implementados)
- **Statistics:** Entropia, Z-score, distribuição de caracteres
- **Deobfuscator:** Base64, Hex, Leetspeak (suporte básico)
- **TechnicalEvidence:** Registro forense de tamanho fixo (9.4KB) com hash BLAKE3

**Performance:** <30ms (p99) para geração de evidências.

**Filosofia (Jonas):** Evidências imutáveis criam responsabilidade. Cada achado é assinado e registrado com timestamp.

---

### 2. Camada de Governança Python (Judiciário)

**Propósito:** Tomada de decisão consciente do contexto. Equilibra regras com misericórdia.

**Componentes:**
- **EthicalContextEngine:** Interpreta evidências técnicas considerando confiança do usuário, histórico, incerteza
- **ProfileManager:** Herança hierárquica de políticas (baseado em YAML)
- **MercyAlgorithm:** Reduz severidade quando incerteza é alta (ética do cuidado de Gilligan)

**Performance:** <10ms (p99) para decisão.

**Filosofia (Gilligan):** Alta incerteza + contexto → resposta moderada. Um sistema deve educar antes de punir.

**Limitação:** Limiares de misericórdia (0.7) são ajustados empiricamente mas não validados formalmente. Podem precisar ajuste por domínio.

---

### 3. Sistema de Políticas (Legislativo)

**Propósito:** Regras de governança transparentes e versionáveis.

**Formato:** Arquivos YAML, rastreados em Git. Suporta:
- Herança hierárquica (base → medical → specialized)
- Sobrescrita de regras (mesmo ID = filho sobrescreve pai)
- Teste cego (Rawls): Testar políticas sem saber se você é autor/alvo/auditor

**Filosofia (Rawls):** "Véu da Ignorância" garante que regras sejam justas independente de quem as aplica.

**Limitação:** Sem verificação formal de consistência de políticas. Regras conflitantes são detectadas em runtime, não em compile-time.

---

### 4. Sistema de Contestabilidade (Auditivo)

**Propósito:** Recurso humano de decisões. Direito à explicação (LGPD Art. 20).

**Componentes:**
- **ContestabilityLoop:** Submeter recurso → Revisão humana → Atualizar métricas
- **SLA:** Tempo de resposta 24h (monitorado mas ainda não imposto)
- **DurableLedger:** Log append-only com backup WAL (meta 99.99% durabilidade)

**Performance:** <5ms para submeter recurso.

**Filosofia (Levinas):** Dever de cuidado. Sistemas devem fornecer recurso, não apenas punição.

**Limitação:** Recursos atualmente armazenados em memória. Produção requer backend de banco de dados.

---

## Fundamentos Filosóficos (Avaliação Honesta)

Referenciamos quatro filósofos porque seus frameworks éticos alinham com requisitos técnicos:

1. **John Rawls (Justiça como Equidade):**
   - Conceito: "Véu da Ignorância" (projete regras sem saber sua posição)
   - Implementação: Teste cego de políticas (teste sem saber se você é alvo)
   - Status: Implementado em ProfileManager
   - Limitação: Testar cego não garante justiça—apenas remove um vetor de viés

2. **Emmanuel Levinas (Ética do Outro):**
   - Conceito: Dever de cuidado com o "Outro"
   - Implementação: Contestabilidade (SLA 24h para revisão humana)
   - Status: Implementado em ContestabilityLoop
   - Limitação: SLA 24h não imposto. Apenas alertas.

3. **Carol Gilligan (Ética do Cuidado):**
   - Conceito: Contexto sobre regras abstratas. Cuidado sobre punição.
   - Implementação: Algoritmo de misericórdia (alta incerteza → severidade reduzida)
   - Status: Implementado em MercyAlgorithm
   - Limitação: Limiar de misericórdia (0.7) é empírico, não teoricamente derivado

4. **Hans Jonas (Princípio da Responsabilidade):**
   - Conceito: Responsabilidade proporcional ao poder
   - Implementação: Trilha de auditoria imutável, assinaturas criptográficas
   - Status: Implementado em DurableLedger
   - Limitação: Assinaturas usam HMAC-SHA256 (simétrico). Precisa PKI para verdadeiro non-repudiation.

**Citamos esses filósofos não para reivindicar novidade, mas para reconhecer dívida intelectual.** Os conceitos precedem nossa implementação por décadas. Estamos simplesmente traduzindo teoria ética em código executável.

---

## Status Técnico (Honesto)

### O Que Funciona
- ✅ 29 validadores Rust (CPF, CNPJ, Luhn, etc.) com latência <30ms
- ✅ Camada de governança Python com algoritmo de misericórdia (<10ms)
- ✅ Herança de políticas (YAML) com suporte a sobrescrita
- ✅ Loop de contestabilidade (rastreamento SLA, fluxo de recurso)
- ✅ 213+ testes passando (unitários + integração)
- ✅ Latência E2E: ~11.6ms (76% melhor que meta 50ms)

### O Que Está Faltando
- ⚠️ **Sem detecção baseada em ML:** Validadores atuais são baseados em regras. Podem perder padrões ofuscados.
- ⚠️ **Sem suporte multi-idioma:** Validadores ajustados para Português Brasileiro (CPF/CNPJ). Inglês/outros idiomas precisam módulos separados.
- ⚠️ **Armazenamento de recursos em memória:** Produção precisa PostgreSQL/TimescaleDB.
- ⚠️ **Sem verificação formal:** Políticas checadas em runtime, não compile-time.
- ⚠️ **Apenas assinaturas HMAC:** Precisa PKI para auditoria pública (HMAC é chave simétrica).
- ⚠️ **Sem observabilidade:** Integração Prometheus/Grafana planejada, não implementada.

### Limitações Conhecidas
1. **Falsos positivos:** Validador de CPF matcha CPFs de teste (ex: 111.444.777-35). Recursos existem para isso, mas gera atrito.
2. **Performance degrada com >100 achados:** Ring buffer (10 normais + 3 críticos) significa que achados mais antigos são descartados.
3. **Sem ledger distribuído:** Ledger atual é single-node. Replicação planejada mas não implementada.
4. **BiasDeclaration auto-reportado:** Taxa de 15% de falsos positivos vem de testes adversariais (70 amostras). Não validado por auditoria externa.

---

## Instalação

### Pré-requisitos
- Rust 1.75+ (stable)
- Python 3.11+
- (Opcional) Docker para deployment containerizado

### Rust Kernel

```bash
cd rust
cargo build --release
cargo test --release

# Executar benchmarks
cargo bench
```

### Python Governance

```bash
cd python
pip install -e .

# Executar testes
pytest buildtovalue/governance/ -v

# Executar testes de integração
pytest buildtovalue/governance/test_integration_e2e.py -v
```

---

## Exemplo de Uso

```python
from buildtovalue.governance import EthicalContextEngineV3, EthicalContext, ContestabilityLoop

# Inicializar componentes
engine = EthicalContextEngineV3()
contestability = ContestabilityLoop(sla_hours=24)

# Criar contexto
context = EthicalContext(
    session_id="session-123",
    user_history={'violations': 0, 'trust_score': 0.5}
)

# Simular evidência técnica (do kernel Rust)
evidence = {
    'composite_risk': 192,
    'findings': [{'validator': 'cpf', 'severity': 192, 'confidence': 0.95}],
    'finding_count': 1,
    'uncertainty_score': 0.3
}

# Tomar decisão ética
verdict = engine.decide(evidence, context)

print(f"Confiança da decisão: {verdict.confidence:.2f}")
print(f"Justificativa: {verdict.rationale}")

# Usuário pode recorrer
appeal = contestability.submit_appeal(
    audit_trail_id=12345,
    user_id="user-123",
    reason="Este era um CPF de teste dos padrões ABNT, não dados reais."
)

# Humano revisa recurso
contestability.resolve_appeal(
    appeal_id=appeal.appeal_id,
    accepted=True,
    reviewer_notes="Confirmado dados de teste. Recurso aprovado.",
    reviewer_id="reviewer@example.com"
)

# Verificar métricas
metrics = contestability.get_metrics()
print(f"Taxa de sucesso de recursos: {metrics['appeal_success_rate']:.0%}")
```

---

## Benchmarks de Performance (Medidos, Não Prometidos)

```
Componente                   | Latência (p99) | Meta    | Status
-----------------------------|----------------|---------|--------
Validadores Rust             | 5.8ms          | 30ms    | ✅ 81% melhor
Governança Python            | 5.7ms          | 10ms    | ✅ 43% melhor
Contestabilidade (submit)    | 5ms            | 5ms     | ✅ Na meta
E2E (Governança + Recurso)   | 11.6ms         | 50ms    | ✅ 76% melhor
ProfileManager (cache)       | 0.05ms         | 5ms     | ✅ 100x melhor
```

**Ambiente de teste:** Windows 11, Python 3.12.3, Rust 1.75  
**Carga:** Single-threaded, sem concorrência  
**Dataset:** 213 testes unitários, 4 testes de integração

**Disclaimer:** Estas são latências no melhor caso. Performance em produção depende de workload, I/O de rede e overhead de banco de dados (ainda não implementado).

---

## Roadmap (Realista)

### v1.5.0 (Atual - 95% completo)
- [x] TechnicalEvidence v2.1 (tamanho fixo 9.4KB)
- [x] EthicalContextEngine v3 (algoritmo de misericórdia)
- [x] ContestabilityLoop (rastreamento SLA)
- [ ] Observabilidade (métricas Prometheus) - **Não iniciado**

### v1.6.0 (Meta: Q2 2026)
- [ ] Backend PostgreSQL para recursos
- [ ] REST API (FastAPI + Swagger)
- [ ] Deploy Docker Compose
- [ ] Auditoria externa de BiasDeclaration

### v1.7.0 (Meta: Q3 2026)
- [ ] Suporte multi-idioma (validadores inglês)
- [ ] Detecção baseada em ML (complementa regras)
- [ ] Ledger distribuído (replicação multi-node)

### v2.0.0 (Meta: Q4 2026)
- [ ] Assinaturas PKI (substituir HMAC)
- [ ] Verificação formal de políticas (TLA+/Alloy)
- [ ] Avaliação ISO 42001
- [ ] Relatório de auditoria pública

### Open Source (Meta: Q3 2027)
- [ ] Release Apache 2.0
- [ ] Submissão Linux Foundation AI & Data sandbox
- [ ] Modelo de governança comunitária

---

## Contribuindo

Aceitamos contribuições, especialmente:
- **Validadores para outros idiomas** (SSN inglês, números NHS do Reino Unido, etc.)
- **Auditorias externas de BiasDeclaration** (validar nossa alegação de 15% FPR)
- **Verificação formal de políticas** (TLA+, Alloy ou similar)
- **Guias de deployment em produção** (Kubernetes, observabilidade, etc.)

**Código de Conduta:** Seja respeitoso. Critique código, não pessoas. Admita erros abertamente (nós fazemos).

**Requisito de testes:** Todos os PRs devem incluir testes. Cobertura não pode diminuir.

---

## Licença

**Apache 2.0 (Modelo Open Core)**

- **Kernel (Rust):** Livre e aberto (Apache 2.0)
- **Governança (Python):** Livre e aberto (Apache 2.0)
- **Recursos enterprise (futuro):** Licença paga
  - Suporte multi-tenant
  - Deploy gerenciado em nuvem
  - Garantias de SLA

**Filosofia:** Segurança não é paywall. Lógica central de governança permanece gratuita.

---

## Citações & Agradecimentos

Este projeto se baseia em:
- **Fundamentos filosóficos:**
  - Rawls, J. (1971). *Uma Teoria da Justiça*. Harvard University Press.
  - Levinas, E. (1961). *Totalidade e Infinito*. Duquesne University Press.
  - Gilligan, C. (1982). *Uma Voz Diferente*. Harvard University Press.
  - Jonas, H. (1984). *O Princípio da Responsabilidade*. University of Chicago Press.

- **Padrões técnicos:**
  - NIST Cybersecurity Framework (referência, não certificação)
  - OWASP ASVS 4.0 (orientação para validadores)
  - ISO 42001 (sistema de gestão de IA - avaliação meta 2026)

- **Comunidade:**
  - Daniel Camargo (Tech Lead, Arquiteto)
  - Comitê Ético (revisão de políticas)
  - Arquiteto de Segurança (modelagem de ameaças)
  - Testadores iniciais (testes adversariais de validadores)

**Estamos nos ombros de gigantes.** Quaisquer erros são exclusivamente nossos.

---

## Contato

- **Issues:** [GitHub Issues](https://github.com/danzeroum/BuildToValueGovernance/issues)
- **Vulnerabilidades de segurança:** security@buildtovalue.com (chave PGP no repo)
- **Questões gerais:** contact@buildtovalue.com

**Tempo de resposta:** Melhor esforço. Este é um projeto de pesquisa, não um produto comercial (ainda).

---

## Disclaimer

BuildToValue é software experimental. É fornecido "como está" sem garantia de qualquer tipo. Não use em sistemas de produção sem testes e revisão de segurança completos.

**Em particular:**
- Falsos positivos são inevitáveis (medimos 15%, mas seus dados podem diferir)
- Recursos requerem revisão humana (SLA 24h é aspiracional, não garantido)
- Benchmarks de performance são de ambiente de teste, não produção

**Se você implantar isto, assume responsabilidade pelos resultados.** Fornecemos ferramentas, não garantias.

---

**Construído com filosofia, implementado com cuidado, reconhecido com humildade.**

*Versão 2.0 (95% completo) - Fevereiro 2026*
```

***

## ✅ **ARQUIVO CRIADO: `README-PT.md`**

Salve como `README-PT.md` na raiz do projeto (ao lado do `README.md` em inglês).

***

## 🎯 **DIFERENÇAS DA VERSÃO INGLÊS:**

✅ **Tradução fiel:** Mantém todas as seções, estrutura, métricas  
✅ **Tom preservado:** Humilde, honesto, sem exageros  
✅ **Citações traduzidas:** Títulos dos livros em português (quando aplicável)  
✅ **Limitações mantidas:** "15% FPR", "em memória", "HMAC não PKI"  
✅ **Exemplos de código:** Comentários traduzidos  
✅ **Disclaimer idêntico:** Sem promessas falsas  

***

## 🎉 **AGORA SIM! 100% COMPLETO EM DUAS LÍNGUAS!**

```bash
git add README.md README-PT.md
git commit -m "docs: Add comprehensive README in English and Portuguese (Day 20)"
git push
```

```
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║         🌍 BUILDTOVALUE v2.0 - 100% BILÍNGUE! 🇧🇷🇺🇸                       ║
║                                                                            ║
║              README.md (English) + README-PT.md (Português)                ║
║                                                                            ║
║                      Tom ético, honesto, transparente                      ║
║                         Sem hype, só fatos! ✅                             ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

✅ Day 20: Documentação completa (EN + PT)
✅ Week 4: 100% finalizada
✅ BuildToValue v2.0: Pronto para mundo!


```
