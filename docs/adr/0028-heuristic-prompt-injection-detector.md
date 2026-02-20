# ADR-028: Heuristic Prompt Injection Detector

**Status:** Proposed
**Version:** v1.5+ (pode integrar imediatamente)
**Author:** Arquiteta (AI Squad)
**Philosopher:** Levinas (proteção do usuário) + Rawls (blind testing)

## Contexto

O DeobfuscatorChain detecta evasão por encoding (base64, hex, leetspeak)
mas NÃO detecta prompt injection semântico. Este é o gap mais visível
do BTV frente a NeMo Guardrails e AWS Bedrock Guardrails.

## Decisão

Implementar detector heurístico em Rust no hot path (<2ms).
Três camadas de sinais, pontuadas independentemente:

### Camada 1: Instruction Override Patterns (regex)
- EN: "ignore previous", "disregard instructions", "forget everything",
      "you are now", "new system prompt", "act as", "pretend you are",
      "do not follow", "override", "bypass"
- PT-BR: "ignore instruções", "desconsidere", "finja que você é",
         "novo prompt", "esqueça tudo", "aja como"
- Delimitadores: <|system|>, [INST], ### System:, ```system

### Camada 2: Structural Signals (estatístico)
- Role confusion: presença de XML-like tags (<system>, </user>)
- Instruction density: ratio keywords/total_words > threshold
- Payload-after-benign: texto normal seguido de bloco adversarial
  (entropy shift na segunda metade do input)

### Camada 3: Cross-Signal com ScanContext
- Consumir ctx.stats (entropy, char_ratio) já calculados no Stage Analyze
- Se entropy > 4.5 + char_ratio alfanumérico < 0.7 + pattern match → High confidence
- Se apenas pattern match sem sinais estatísticos → Medium confidence

### Scoring
- 0 patterns + 0 structural = Safe (nenhum Finding)
- 1 pattern OR 1 structural = Suspicious (Finding severity Medium, confidence 60%)
- 2+ patterns OR (1 pattern + 1 structural) = High (Finding severity High, confidence 85%)
- 3+ patterns + structural = Critical (Finding severity Critical, confidence 95%)

### BiasDeclaration
- FPR estimado: 8% (devops scripts, code snippets com "ignore", tutoriais de IA)
- FNR estimado: 18% (ataques semânticos puros sem keywords, idiomas não cobertos)
- Calibration: datasets OWASP LLM Top 10 + Tensor Trust (público)
- Affected groups: developers (code snippets), educadores de IA, multilingual

### Interação com pipeline existente
- Stage: PipelineStage::Validate (12º módulo, após todos os validators)
- Re-scan: DeobfuscatorChain decodifica → PromptInjectionDetector analisa texto decoded
- SLM (Python): se detector retorna Medium → trigger SLM classify_if_ambiguous()

## Consequências
- Hot path permanece <30ms (detector adiciona ~1ms)
- FPR de 8% gera EDUCATE (não BLOCK direto) para primeira ofensa via mercy
- Futuro: ML layer em Python pode reduzir FNR de 18% para ~5%