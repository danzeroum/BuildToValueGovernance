# ADR-014: Network Context & Session Drift

**Status:** 🔒 Planejado (v1.7)
**Crate:** `btv-kernel` (network/session modules)

## Decisão
1. **IP Classifier:** Classificar origem (Tor, VPN, Datacenter) localmente.
2. **Drift:** Calcular cosseno de similaridade entre o vetor de comportamento da sessão atual e o histórico. Se desvio > threshold, acionar `IdentityChallenge`.