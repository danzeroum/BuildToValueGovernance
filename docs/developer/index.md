---
title: Portal do Desenvolvedor
---

# Portal do Desenvolvedor

Bem-vindo ao **Trust OS** do BuildToValue. Este portal é organizado em **três
trilhas pedagógicas** que refletem os poderes da República Algorítmica
([ADR-001](../adr/0001-hybrid-architecture.md)). Escolha a sua trilha:

<div class="grid cards" markdown>

-   :material-cog: **Trilha do Integrador**

    Você **consome** o gateway via HTTP/SDK. Aprende a interpretar evidências,
    tratar bloqueios `HTTP 451` e verificar provas criptográficas.

    [Começar →](tutorials/01-handle-failure.md)

-   :material-gavel: **Trilha do Legislador**

    Você **propõe** novos ADRs e políticas YAML. Aprende o Protocolo de Emenda
    Constitucional (CAP) e a trilha de ADRs.

    [Começar →](cap-protocol.md)

-   :material-scale-balance: **Trilha do Juiz**

    Você **calibra** thresholds éticos e avalia contestações via
    `ContestabilityLoop` ([ADR-0017](../adr/0017-contestability-loop.md) +
    [ADR-0047](../adr/0047-contestability-structured-mediation-protocol.md)).

    [Começar →](tutorials/04-propose-policy.md)

</div>

## Princípios deste portal

1. **Orquestração, não duplicação.** Conteúdo canônico vive em `docs/adr/`,
   `rust/` e `demo/`. O portal **referencia**, não copia.
2. **Fonte da verdade automatizada.** Invariantes (tamanhos, hashes, IDs de ADR)
   são extraídos do código Rust em build time por
   [`scripts/autogen_reference.py`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/scripts/autogen_reference.py).
3. **Fail-secure first.** O [primeiro tutorial](tutorials/01-handle-failure.md)
   ensina o bloqueio — é no `BLOCK` que a confiança é verdadeiramente testada.
4. **Transparência radical.** [Débitos técnicos ativos](compliance/sizing-guide.md)
   são visíveis antes da decisão de adoção.

## Mapa do portal

- [Conceitos](concepts/evidence-anatomy.md) — anatomia da evidência, fail-secure, contestabilidade.
- [Tutoriais](tutorials/01-handle-failure.md) — caminhos passo a passo.
- [Referência técnica](reference/index.md) — **gerada** a partir do Kernel Rust.
- [Compliance e dimensionamento](compliance/sizing-guide.md) — quando o BTV é economicamente justificável.
- [Trilha de ADRs](adr-trail/README.md) — índice curado dos 70+ ADRs canônicos.
- [Protocolo CAP](cap-protocol.md) — como emendar a constituição do sistema.
- [Playground interativo](https://github.com/danzeroum/BuildToValueGovernance/tree/main/demo/playground) — execute cenários no navegador.
