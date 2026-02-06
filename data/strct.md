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