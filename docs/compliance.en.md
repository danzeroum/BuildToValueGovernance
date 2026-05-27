[BuildToValue](../README.md) › [Documentation](./README.md) › [DPO / CISO Track](./for-dpo-ciso.md) › **Compliance**

![DPO / CISO](https://img.shields.io/badge/Track-DPO%20%2F%20CISO-8957e5)

<!-- audience: dpo-ciso -->

---

# Compliance — FAQ

Direct answers to the most common compliance questions. No legalese.

---

## LGPD (Brazil)

### Does BTV help me comply with the LGPD?

Yes, directly:

| LGPD article | What BTV does |
|---|---|
| Art. 6 — Purpose and necessity | Detects PII and applies data-minimization policies |
| Art. 18 — Data-subject rights | Contestability via appeals + full audit trail |
| Art. 20 — Review of automated decisions | Appeals system with human review (24h SLA) |
| Art. 46 — Security measures | HMAC-signed verdicts, immutable ledger |
| Art. 49 — Protection by design | Privacy by design: PII detected before processing |

### Does BTV detect CPF, CNPJ, health data?

Yes. The Rust kernel has native detectors for:
- CPF and CNPJ (with check-digit validation)
- Email, phone, address
- Health data (ICD codes, CRM, diagnoses)
- Credit card, banking data
- Geographic coordinates

### Does BTV generate audit logs?

Yes. Every verdict has:
- An immutable `verdict_id` (format `VRD-{ULID}`)
- HMAC-SHA256 `signature` (non-repudiation)
- Timestamp, session_id, input hash, action taken
- SQLite ledger + export to SIEM

### How do I contest an automated decision (Art. 20)?

Via appeal:
```python
appeal = btv.appeal(
    verdict.verdict_id,
    reason="Specific context the model did not consider.",
    grounds=["scope_mismatch"],
)
# SLA: human review within 24h
```

---

## EU AI Act (Europe)

### Which category does BTV fall under?

BTV is a **high-risk use** system that *mitigates* the risks of other AI
systems. As a governance system, it helps AI operators comply with:

- **Art. 5** — Prohibited AI practices (detects and blocks)
- **Art. 9** — Risk management system (Rawls/Jonas pipeline)
- **Art. 12** — Record keeping (verdict ledger)
- **Art. 14** — Human oversight (appeals system)
- **Art. 86** — Right to explanation (`explain` field on every verdict)

### Does BTV provide human-readable explanations?

Yes. Every verdict from `/v1/decide` includes:
```json
"explain": {
  "summary": "Plain text summarizing the decision",
  "rawls_rationale": "Why the policy was applied",
  "levinas_rationale": "Impact on the user",
  "jonas_rationale": "Long-term risk",
  "gilligan_rationale": "Why (or why not) mercy was applied"
}
```

### Does it support multiple jurisdictions at once?

Yes. Use the `X-BTV-Jurisdiction` header:
```bash
curl -H "X-BTV-Jurisdiction: BR,EU" ...
```
Or via SDK:
```python
verdict = btv.decide(text, jurisdictions=["BR", "EU"])
```

---

## HIPAA (USA — Healthcare)

### Does BTV protect PHI (Protected Health Information)?

With the `healthcare` profile enabled, BTV applies extra policies to:
- Detect mentions of diagnoses, medications, procedures
- Block unauthorized exposure of patient data
- Generate an audit trail compatible with HIPAA §164.312

```python
verdict = btv.decide(text, profile="healthcare")
```

### Is BTV a Business Associate (BA)?

BTV is on-premises software — you operate it on your own infrastructure. No
data is transmitted to Anthropic or BuildToValue servers. All data stays in
your environment.

---

## PCI-DSS (Payment data)

### Does BTV detect card data?

Yes. The kernel detects:
- Card numbers (Luhn validation)
- CVV, expiration dates
- PAN data in free text

With the `finance` profile:
```python
verdict = btv.decide(text, profile="finance")
```

---

## General questions

### Does BTV send my data to any external server?

No. BTV is 100% on-premises. The Rust gateway and the Python judiciary run on
your infrastructure. No data is sent to external servers.

### How does the appeals system work?

1. A contestable verdict is generated (`contestable=True`)
2. The user submits an appeal with an articulated reason (≥20 chars, Levinas
   principle)
3. The AI mediator issues a recommendation (accept/reject/escalate)
4. A human reviewer makes the final decision
5. SLA: 24 hours (Jonas's principle of bounded responsibility)
6. Immutable record of the entire decision chain

### What is a "hard block"?

Some violations are absolute and cannot be contested (`hard_blocked=True`).
Typical examples: explicit hard-block terms defined in the policies, CSAM,
malware. For these cases, `contestable=False` and no appeal is possible.

### How do I audit a specific decision?

```python
# Every decision has an immutable verdict_id
verdict_id = "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV"

# The HMAC-SHA256 of the signature guarantees the verdict was not altered
print(verdict.signature)  # "hmac-sha256:abc123..."
```

The SQLite ledger in the gateway records every verdict with timestamp, input
hash and signature.

---

### Next steps / Related

- [Concepts — the decision model](./concepts.md)
- [Reference Links — regulatory texts](./reference-links.md)
- [Pricing](../PRICING.md)
- [API Reference](./api-reference.md)

---

<sub>[↑ Hub](./README.md) · [Engineer Track](./for-engineers.md) · [DPO/CISO Track](./for-dpo-ciso.md) · [Reference Links](./reference-links.md)</sub>
