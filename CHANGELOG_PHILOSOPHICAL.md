# Changelog Filosófico

Este changelog registra decisões cujo significado transcende a mudança técnica
que as motivou — decisões em que **o que mudou no código foi pequeno, mas o que
mudou no entendimento do sistema foi grande**. Ele é complementar (não substituto)
ao `CHANGELOG.md` técnico e ao corpo de ADRs em `docs/adr/`.

Cada entrada deve responder a três perguntas:

1. **Qual fato do sistema esta entrada torna explícito?**
2. **Por que esse fato não cabia em um ADR técnico isolado?**
3. **O que um futuro leitor — humano ou agente — precisa entender para não tropeçar?**

---

## 2026-05 — Bootstrap: por que existimos

**Fato tornado explícito.** A struct `TechnicalEvidence` possui **dois tamanhos
canônicos coexistentes** no repositório:

- **9632 bytes** — definição em `rust/kernel/src/core/types.rs`, representa o
  formato operacional do kernel, com campos reservados para atestação de
  hardware (C8) e metadados de habilidade (Prop-031).
- **9596 bytes** — definição em `rust/btv-types/src/lib.rs`, representa o
  formato constitucional de wire produzido por `Verdict::to_technical_evidence()`
  e transmitido entre componentes.

Ambos os tamanhos são validados em tempo de compilação via `const_assert_eq!` e
documentados em [`docs/adr/0063-technical-evidence-size-invariant.md`](docs/adr/0063-technical-evidence-size-invariant.md).

**Por que isso exigiu um changelog desta natureza.** Três propostas independentes
de planejamento do Portal do Desenvolvedor (Maio/2026) afirmaram, cada uma com
convicção e citações, que o tamanho da evidência era um número fixo *diferente*:
9596, 9632, ou simplesmente "o tamanho". Nenhuma das propostas estava errada
sobre o número que mencionava — estavam erradas sobre a *unicidade* dele. Um
ADR técnico isolado não resolveria isso, porque o problema não era a ausência
de documentação técnica (ADR-063 já existia) mas sim a **ausência de um lugar
onde a coexistência de duas verdades parciais fosse declarada como decisão
arquitetural deliberada**, e não como contradição.

**O que o futuro leitor precisa entender.** Se você encontrar uma referência
a "tamanho da evidência" sem qualificador (operacional/constitucional, kernel/wire,
9632/9596), trate-a como **incompleta** e exija a qualificação antes de agir.
Esta é a primeira pedra: toda entrada futura deste changelog deve seguir o
mesmo padrão — tornar explícito um fato que, ao ser implícito, gera divergências
sustentáveis entre observadores honestos.
