# Como Contribuir para o BuildToValue

Bem-vindo. O BTV é uma **República Algorítmica** — toda contribuição passa por
um processo formal que distingue três papéis. Escolha o seu antes de abrir um PR.

## Trilhas

### 🔧 Trilha do Integrador
Você **consome** o gateway. Contribui com SDKs, exemplos, integrações,
documentação de uso. Comece pelo
[Portal do Desenvolvedor → Integrador](docs/developer/index.md).

### ⚖️ Trilha do Legislador
Você **propõe** novos ADRs e políticas YAML. Toda emenda segue o
[Protocolo CAP](docs/developer/cap-protocol.md). Tutorial:
[Propor uma Política](docs/developer/tutorials/04-propose-policy.md).

### 🧑‍⚖️ Trilha do Juiz
Você **calibra** thresholds éticos e avalia contestações via
`ContestabilityLoop` ([ADR-0017](docs/adr/0017-contestability-loop.md) +
[ADR-0047](docs/adr/0047-contestability-structured-mediation-protocol.md)).

## Regras invioláveis

1. **Nunca digite invariantes manualmente** (e.g. tamanhos de bytes da evidência).
   Eles são gerados por `scripts/autogen_reference.py`. O CI falha se você fizer
   isso (`scripts/validate_invariants.py`).
2. **Toda mudança constitucional** (novo ADR, threshold, invariante) **deve**
   ser registrada via [Protocolo CAP](docs/developer/cap-protocol.md) e, quando
   couber, em [`CHANGELOG_PHILOSOPHICAL.md`](CHANGELOG_PHILOSOPHICAL.md).
3. **Fail-secure first.** Código que captura `HTTP 451` e retorna `200 OK`
   silenciosamente quebra o contrato fundamental.

## Antes de abrir o PR

```bash
make docs-reference   # regenera reference/index.md
make docs-validate    # verifica invariantes
make docs-build       # mkdocs build --strict
make test             # bateria completa Rust + Python
```

## Onde pedir ajuda

- Discussões: GitHub Discussions.
- Bugs: GitHub Issues.
- Dúvidas sobre o portal: abrir issue com label `documentation`.
