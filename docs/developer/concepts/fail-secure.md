---
title: Fail-Secure First
---

# Fail-Secure First

O BuildToValue **falha fechado por padrão**. Quando o gateway não consegue
produzir uma evidência válida ou detecta violação de política, ele responde
com `HTTP 451 Unavailable For Legal Reasons` — **não** com `500`, **não** com
um caminho feliz silenciosamente degradado.

Esta é a invariante de segurança mais importante do sistema. Tudo o que você
aprenderá no Portal está orientado a ela:

- O [primeiro tutorial](../tutorials/01-handle-failure.md) ensina o bloqueio,
  não o caminho feliz.
- A documentação de referência é [gerada por um script fail-secure](https://github.com/danzeroum/BuildToValueGovernance/blob/main/scripts/autogen_reference.py)
  que aborta o build se um invariante esperado estiver ausente.
- O playground apresenta o bloqueio como **experiência educativa** — não como
  erro frustrante (ver [contestabilidade](contestability-loop.md)).

## Por que isso importa

Em sistemas tradicionais, "falhar aberto" é a tentação: manter o serviço de pé
custe o que custar. No BTV, o produto **é** a confiança auditável. Um sucesso
sem evidência válida é equivalente a uma falha — e uma falha sem trilha de
contestação é uma traição ao usuário final.

## A regra prática

Se você escrever código que captura uma exceção do BTV e retorna `200 OK`
silenciosamente, você quebrou o contrato. Sempre propague o `451`, sempre
exiba a [trilha de contestação](contestability-loop.md), sempre permita ao
usuário final apelar.
