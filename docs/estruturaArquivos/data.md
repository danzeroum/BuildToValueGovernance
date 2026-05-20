[BuildToValue](../../README.md) › [Documentação](../README.md) › **Estrutura de Arquivos**

![Interno](https://img.shields.io/badge/Trilha-Contribuidor%20%2F%20Interno-6e7681)

<!-- audience: internal -->

---

data/
├── infrastructure/           <-- Configurações Técnicas
│   └── monitoring/
│       ├── alertmanager.yml
│       └── prometheus.yml
│
├── intelligence/             <-- Dados Dinâmicos (Vazia por enquanto, ok)
│
├── ledger/                   <-- Persistência (NÃO TOCAR)
│   ├── snapshots/
│   └── wal/
│
└── policies/                 <-- Governança (Regras de Negócio)
    ├── _metadata/
    │   └── checksums.json
    ├── agents/               <-- Quem obedece a lei
    │   └── medical-agent.yaml
    ├── frameworks/           <-- As Leis
    │   ├── gdpr_base.yaml
    │   ├── lgpd_base.yaml
    │   └── hipaa_base.yaml
    ├── base.yaml             <-- Config global
    └── default.yaml          <-- Fallback

---

### Próximos passos / Relacionados

- [Project Context](../PROJECT_CONTEXT.md)
- [Arquitetura (Atlas)](../ARCHITECTURE_ATLAS.md)

---

<sub>[↑ Hub](../README.md) · [Trilha Engenheiro](../for-engineers.md) · [Trilha DPO/CISO](../for-dpo-ciso.md) · [Links de Referência](../reference-links.md)</sub>
