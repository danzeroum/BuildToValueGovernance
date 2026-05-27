[BuildToValue](../README.md) › [Documentation](./README.md) › **Concepts**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb) ![DPO / CISO](https://img.shields.io/badge/Track-DPO%20%2F%20CISO-8957e5)

<!-- audience: both -->

---

# Concepts — The Algorithmic Republic

BTV uses political metaphors to organize its architecture. It is not
academic ornament — it is a way to make explicit *who decides what* and *why*.

---

## Separation of Powers

BTV has three "branches", as in a republic:

```
User input
      │
      ▼
┌─────────────────────────────┐
│  EXECUTIVE (Rust Kernel)    │  < 5ms
│  Applies objective rules    │
│  PII, injections, policies  │
└─────────────┬───────────────┘
              │ forwards for review
              ▼
┌─────────────────────────────┐
│  JUDICIARY (Python)         │  20-80ms
│  Ethical reasoning & mercy  │
│  Rawls→Levinas→Jonas→Gill.  │
└─────────────┬───────────────┘
              │ signed verdict
              ▼
┌─────────────────────────────┐
│  LEGISLATIVE (Contestab.)   │
│  User can appeal            │
│  LGPD Art. 20 / EU AI Act   │
└─────────────────────────────┘
```

---

## The Ethical Pipeline (Judiciary)

When the Rust Kernel surfaces evidence, Python applies four philosophical
filters in sequence:

### 1. Rawls — Fairness (veil of ignorance)

> *"Would it be fair to apply this rule if we did not know who the user was?"*

Evaluates the policy blindly — without considering history, identity, or
favorable context. If the rule says "block CPF", it blocks.

**Outcome:** initial objective action (`BLOCK`, `REDACT`, etc.)

---

### 2. Levinas — Duty of care

> *"The Other regards us. We have a duty of care."*

Considers the impact of the decision on the user as a person. A blunt BLOCK
without explanation violates Levinas. The system must *explain* what happened
and *why*.

**Outcome:** articulate rationale, mandatory reason on appeals (minimum 20 chars)

---

### 3. Jonas — Long-term responsibility

> *"Act so that the effects of your action are compatible with the continuation
> of human life."*

Evaluates systemic risk. An isolated mistake is different from a pattern that,
generalized, harms at scale. Jonas raises the weight of actions affecting
vulnerable populations.

**Outcome:** adjustment of `composite_risk` per jurisdiction and sector profile

---

### 4. Gilligan — Ethics of care (mercy)

> *"Context matters. Relationships matter. Rigidity without mercy is cruelty."*

The last filter. It asks: *does the user deserve a second chance here?* It
takes into account trust score, history of offenses, first-time vs repeat
behavior.

If the trust score is high and it is a first offense, BLOCK can turn into
EDUCATE.

**Outcome:** `mercy_applied`, `original_action` vs `action`

---

## Trust Score

Each session accumulates a confidence score in [0.0, 1.0]:

```
trust = 0.20 × base
      + 0.30 × compliance_history
      + 0.20 × accepted_appeals
      + 0.15 × (1 - temporal_decay)
      + 0.15 × behavioral_consistency
```

| Score | Level | Behavior |
|---|---|---|
| ≥ 0.8 | High | Gilligan more lenient, EDUCATE preferred |
| 0.5–0.8 | Medium | Default behavior |
| < 0.5 | Low | Gilligan stricter, less mercy |

The score **decays** with idle time and **recovers** with clean interactions.

---

## Possible actions

| Action | Meaning |
|---|---|
| `ALLOW` | Clean input, may proceed |
| `LOG` | Allowed but recorded for audit |
| `EDUCATE` | Low-to-medium risk; the user is informed (Gilligan applied) |
| `REDACT` | PII detected; output must be masked |
| `INSPECT` | Requires human review before continuing |
| `BLOCK` | Blocked (hard or soft) |

---

## Contestability

Every verdict with `contestable=True` can be challenged via an appeal:

```python
# The user can appeal within the window (default: 24h)
appeal = btv.appeal(
    verdict.verdict_id,
    reason="This CPF is from a public test dataset.",
    grounds=["technical_error", "false_positive"],
)
```

**Available grounds:**

| Ground | When to use |
|---|---|
| `rawls_equity` | The rule applied is discriminatory or unfair |
| `levinas_protection` | The block caused disproportionate harm |
| `gilligan_mercy` | The human context was not considered |
| `jonas_responsibility` | The risk was overestimated |
| `technical_error` | Bug or technical false positive |
| `scope_mismatch` | The rule does not apply to this context |
| `false_positive` | Not real PII / not a real violation |

Appeals are reviewed by a human within 24 hours (Jonas's principle of
responsibility with a deadline).

---

## Jurisdictions

BTV supports multiple jurisdictions via the `X-BTV-Jurisdiction` header bitmask:

| Code | Regulation |
|---|---|
| `BR` | LGPD (Law 13.709/2018) |
| `US` | HIPAA, CCPA, SOC 2 |
| `EU` | GDPR, EU AI Act |
| `UK` | UK GDPR, AI Principles |

```python
# Apply LGPD + GDPR rules simultaneously
verdict = btv.decide(text, jurisdictions=["BR", "EU"])
```

---

## Sector profiles

The `profile` enables sector-specific policies:

| Profile | Extra policies |
|---|---|
| `general` | Base rules |
| `healthcare` | HIPAA, health data, consent |
| `finance` | PCI-DSS, banking data, fraud |
| `legal` | Professional secrecy, sensitive data |
| `research` | Anonymized data allowed with consent |
| `education` | Protection of minors, COPPA |

---

### Next steps / Related

- [Compliance — how BTV maps to regulations](./compliance.md)
- [API Reference](./api-reference.md)
- [Architecture (Atlas)](./ARCHITECTURE_ATLAS.md)
- [ADR Index](./adr/0000-adr-index.md)

---

<sub>[↑ Hub](./README.md) · [Engineer Track](./for-engineers.md) · [DPO/CISO Track](./for-dpo-ciso.md) · [Reference Links](./reference-links.md)</sub>
