# ADR-021: Compliance Plugin Architecture

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v2.0
**Grupo:** G — Intelligence & Compliance

## Contexto

O sistema opera em múltiplas jurisdições (Brasil/LGPD, Europa/EU AI Act, futuro: HIPAA, PCI-DSS). Cada framework regulatório tem requisitos diferentes. Um monolito de compliance não escala. Precisamos de uma arquitetura extensível onde cada framework é um plugin independente.

## Decisão

Implementar CompliancePlugin como Protocol (structural typing) com registry e API REST.

### Protocol
```python
class CompliancePlugin(Protocol):
    def framework_id(self) -> str: ...
    def framework_name(self) -> str: ...
    def generate_artifacts(self, evidence: dict, verdict: dict) -> List[ComplianceArtifact]: ...
    def validate_requirements(self) -> ComplianceReport: ...
```

### Plugins Implementados

| Plugin | Framework | Artigos Cobertos | Status |
|:---|:---|:---|:---|
| `LGPDPlugin` | LGPD (Brasil) | Art. 6, 18, 20, 46, 48 | ✅ Ativo |
| `EUAIActPlugin` | EU AI Act | Art. 5, 9, 13, 14, 15 | ✅ Ativo |

### Endpoints

| Método | Path | Função |
|:---|:---|:---|
| GET | `/v1/compliance/frameworks` | Listar plugins disponíveis |
| GET | `/v1/compliance/report/{framework}` | Relatório de compliance |
| POST | `/v1/compliance/check` | Verificar verdict contra framework |

### Cada ComplianceArtifact contém

- `framework`: identificador (LGPD, EU_AI_ACT)
- `article`: artigo específico (Art. 20)
- `requirement`: requisito em linguagem humana
- `status`: COMPLIANT / PARTIAL / NON_COMPLIANT / NOT_APPLICABLE
- `evidence`: como o sistema atende (ou não)
- `recommendation`: ação corretiva

### Invariantes

- Plugins são registrados em `COMPLIANCE_PLUGINS` dict no startup
- Novos frameworks = novo arquivo Python + registro (Open/Closed Principle)
- Plugins fazem self-assessment (verificam se capabilities existem)
- Nenhum plugin modifica o comportamento do kernel

## Fundamento Filosófico

**Rawls (1971):** Justiça como fairness requer que o sistema demonstre compliance de forma transparente e verificável. Cada plugin é um auditor independente que avalia o sistema contra um framework específico, sem conflito de interesse.

## Limitações Atuais

- Self-assessment: plugins verificam capabilities do sistema, não auditam decisões reais.
- ComplianceTranslator (PDF→YAML via LLM) existe como código mas requer API key externa.
- Sem relatórios históricos (snapshot point-in-time apenas).

## Referências

- `python/buildtovalue/compliance/plugin.py`
- `python/buildtovalue/compliance/lgpd_plugin.py`
- `python/buildtovalue/compliance/eu_ai_act_plugin.py`