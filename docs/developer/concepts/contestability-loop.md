---
title: ContestabilityLoop
---

# `ContestabilityLoop`

Quando o gateway bloqueia uma operação (`HTTP 451`), o usuário final tem o
direito de **contestar** a decisão. Esse direito é operacionalizado pelo
`ContestabilityLoop`, que reúne duas decisões arquiteturais complementares:

| ADR | Responsabilidade |
| --- | --- |
| [**ADR-0017**](../../adr/0017-contestability-loop.md) | SLA de 24h para resposta a contestações. |
| [**ADR-0047**](../../adr/0047-contestability-structured-mediation-protocol.md) | Protocolo de mediação estruturada (formato dos campos, estados, transições). |

!!! note "Sobre a numeração"
    Existe um ADR-0067 que espelha parcialmente o ADR-0047 (mirror histórico) e
    um conflito de número entre `0047-contestability-structured-mediation-protocol`
    e `0047-semantic-pii-ner`. Considere **ADR-0017 + ADR-0047** como
    canônicos até a renumeração ser concluída
    ([issue #150](https://github.com/danzeroum/BuildToValueGovernance/issues/150)).

## Estados do loop

1. **`BLOCK`** — gateway emite `451`, evidência é gravada no ledger.
2. **`CONTEST_OPENED`** — usuário registra apelação; SLA de 24h inicia.
3. **`MEDIATION`** — protocolo estruturado coleta argumentos das partes.
4. **`RESOLVED`** ou **`UPHELD`** — decisão final, com nova evidência ligada à original.

## No playground

O painel de contestação é exibido **automaticamente** após qualquer `451`. Não
é necessário código adicional do integrador — o componente vem com o SDK.

!!! warning "Simulação didática"
    Painéis do playground que manipulam o tempo (para demonstrar o SLA de 24h
    em segundos) carregam o badge inamovível
    `[SIMULAÇÃO DIDÁTICA — ESTADO DO LEDGER NÃO AFETADO]`. O kernel Rust é
    alheio a essa manipulação; ela existe apenas para fins pedagógicos.
