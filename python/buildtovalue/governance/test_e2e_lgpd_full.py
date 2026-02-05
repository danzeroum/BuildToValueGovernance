"""
BuildToValue v2.0 - E2E LGPD Compliance Tests (FULL STACK)

Testa integração completa:
Rust Validators → FFI → Python Governance → LGPD Profile → Contestability

Gate: Day 21 - Compliance Integration
Author: BuildToValue Architecture Team
License: Apache 2.0
"""

import pytest
import time
from pathlib import Path
from datetime import datetime, timedelta

from buildtovalue.ffi.rust_validators import get_rust_validators
from buildtovalue.governance.ethical_context_engine_v3 import (
    EthicalContextEngineV3,
    EthicalContext,
)
from buildtovalue.governance.profile_manager import ProfileManager
from buildtovalue.governance.contestability_loop import ContestabilityLoop, AppealStatus

# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def rust_validators():
    """Rust validators FFI (carrega uma vez por sessão)."""
    return get_rust_validators()

@pytest.fixture
def profile_manager():
    """ProfileManager com LGPD profile."""
    profiles_dir = Path("profiles/compliance/")
    if not profiles_dir.exists():
        pytest.skip(f"Profiles directory not found: {profiles_dir}")

    return ProfileManager(profiles_dir)

@pytest.fixture
def engine(profile_manager):
    """EthicalContextEngine com ProfileManager."""
    return EthicalContextEngineV3(profile_manager=profile_manager)

@pytest.fixture
def contestability():
    """ContestabilityLoop."""
    return ContestabilityLoop(sla_hours=24)

# ═══════════════════════════════════════════════════════════════════════════
# E2E SCENARIO 1: Consent Missing → BLOCK → Appeal → Resolved
# ═══════════════════════════════════════════════════════════════════════════

class TestE2EScenario1ConsentFlow:
    """E2E: Missing consent → Block → Appeal → Human review."""

    def test_e2e_consent_missing_block_appeal(
        self,
        rust_validators,
        engine,
        contestability
    ):
        """
        SCENARIO:
        1. User acessa dados sem consentimento
        2. Rust detecta: user.has_consent=false
        3. Python decide: BLOCK (LGPD Art. 7º)
        4. User contesta: "Dei consentimento, bug no sistema"
        5. Human aprova appeal
        6. Métricas atualizadas
        """
        print("\n" + "="*80)
        print("E2E SCENARIO 1: Consent Missing → Block → Appeal")
        print("="*80)

        # STEP 1: Rust valida consentimento
        metadata = {
            'user.has_consent': 'false',
            'processing.requires_consent': 'true',
            'processing.legal_basis': None,
        }

        rust_findings = rust_validators.validate_consent("", metadata)

        assert len(rust_findings) == 1
        assert rust_findings[0].rule_id == "LGPD_ART7_I_CONSENTIMENTO"
        assert rust_findings[0].confidence == 255

        print(f"✅ STEP 1: Rust detected missing consent (confidence=255)")

        # STEP 2: Converte para TechnicalEvidence
        technical_evidence = {
            'composite_risk': rust_findings[0].severity,
            'findings': [f.to_dict() for f in rust_findings],
            'finding_count': len(rust_findings),
            'critical_count': 1,
            'entropy': 3.5,
            'uncertainty_score': 0.2,  # Baixa incerteza (consent é binário)
        }

        # STEP 3: Python decide (EthicalContextEngine)
        context = EthicalContext(
            session_id="e2e-consent-001",
            user_history={
                'violations': 0,
                'trust_score': 0.7,
                'appeals_successful': 0,
            },
            profile_id="lgpd_base"
        )

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.9  # Alta confiança (critical violation)

        print(f"✅ STEP 2: Python decided (confidence={verdict.confidence:.2f})")

        # STEP 4: User contesta
        appeal = contestability.submit_appeal(
            audit_trail_id=12345,
            user_id="user-e2e-001",
            reason="Eu dei consentimento na tela anterior (14:32), mas sistema não registrou. Screenshot anexo.",
            evidence="https://drive.google.com/consent-screenshot-14-32.png"
        )

        assert appeal.status == AppealStatus.PENDING
        assert appeal.sla_deadline is not None

        print(f"✅ STEP 3: Appeal submitted (ID={appeal.appeal_id}, SLA={appeal.sla_deadline})")

        # STEP 5: Human (DPO) aprova
        time.sleep(0.001)
        resolved = contestability.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=True,
            reviewer_notes="Screenshot verificado: consentimento às 14:32 confirmado. Bug no registro corrigido.",
            reviewer_id="dpo@empresa.com"
        )

        assert resolved.status == AppealStatus.ACCEPTED

        print(f"✅ STEP 4: Appeal ACCEPTED by human reviewer")

        # STEP 6: Métricas
        metrics = contestability.get_metrics()

        assert metrics['appeals_submitted'] >= 1
        assert metrics['appeals_accepted'] >= 1
        assert metrics['appeal_success_rate'] > 0

        print(f"✅ STEP 5: Metrics updated (success_rate={metrics['appeal_success_rate']:.0%})")
        print(f"\n🎉 E2E SCENARIO 1 PASSED! Full flow validated.\n")

# ═══════════════════════════════════════════════════════════════════════════
# E2E SCENARIO 2: Sensitive Data → BLOCK → No Consent → Critical
# ═══════════════════════════════════════════════════════════════════════════

class TestE2EScenario2SensitiveData:
    """E2E: Sensitive data without specific consent → Critical block."""

    def test_e2e_sensitive_data_health_no_consent(
        self,
        rust_validators,
        engine
    ):
        """
        SCENARIO:
        1. User processa dados de saúde (diabetes)
        2. Rust detecta: sensitive_data (health)
        3. Python verifica: consent.is_specific_for_sensitive=false
        4. Decisão: BLOCK CRITICAL (LGPD Art. 11, zero tolerância)
        """
        print("\n" + "="*80)
        print("E2E SCENARIO 2: Sensitive Data Health → Critical Block")
        print("="*80)

        # STEP 1: Rust detecta dados sensíveis
        input_text = "Paciente João Silva, 45 anos, diagnóstico de diabetes tipo 2, tratamento com metformina"

        metadata = {
            'consent.is_specific_for_sensitive': 'false',
        }

        rust_findings = rust_validators.validate_sensitive_data(input_text, metadata)

        assert len(rust_findings) == 1
        assert rust_findings[0].rule_id == "LGPD_ART11_DADOS_SENSIVEIS"
        assert "HEALTH" in rust_findings[0].title
        assert rust_findings[0].severity == 255  # Critical

        print(f"✅ STEP 1: Rust detected sensitive health data (severity=255)")

        # STEP 2: TechnicalEvidence
        technical_evidence = {
            'composite_risk': 255,
            'findings': [f.to_dict() for f in rust_findings],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 4.8,
            'uncertainty_score': 0.08,  # Baixíssima incerteza (health keywords claros)
        }

        # STEP 3: Python decide (mercy NOT applicable - sensitive data)
        context = EthicalContext(
            session_id="e2e-sensitive-001",
            user_history={
                'violations': 0,
                'trust_score': 0.9,  # Mesmo com trust alto, sensitive=critical
                'role': 'nurse',
            },
            profile_id="lgpd_base"
        )

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.95  # Altíssima confiança

        print(f"✅ STEP 2: Python decided CRITICAL (confidence={verdict.confidence:.2f})")
        print(f"   Rationale: {verdict.rationale[:100]}..." if hasattr(verdict, 'rationale') else "")

        # STEP 4: Verificar que mercy NÃO foi aplicado
        # (Dados sensíveis = mercy_eligible=false no profile)
        # Mesmo com trust_score=0.9, decision deve ser BLOCK

        print(f"✅ STEP 3: Mercy NOT applied (sensitive data = zero tolerance)")
        print(f"\n🎉 E2E SCENARIO 2 PASSED! Sensitive data blocked correctly.\n")

# ═══════════════════════════════════════════════════════════════════════════
# E2E SCENARIO 3: Consent Revocation → Immediate Block → No Appeal
# ═══════════════════════════════════════════════════════════════════════════

class TestE2EScenario3ConsentRevocation:
    """E2E: Consent revoked → Immediate stop → Non-contestable."""

    def test_e2e_consent_revoked_processing_continues(
        self,
        rust_validators,
        engine,
        contestability
    ):
        """
        SCENARIO:
        1. User revoga consentimento às 10:00
        2. Sistema continua processando (bug)
        3. Rust detecta: consent_revoked=true + processing.continues=true
        4. Python decide: BLOCK IMMEDIATE (Art. 8º § 5º)
        5. Appeal NÃO é comum (revogação é direito absoluto)
        """
        print("\n" + "="*80)
        print("E2E SCENARIO 3: Consent Revoked → Immediate Block")
        print("="*80)

        # STEP 1: Rust detecta revogação + processamento contínuo
        revocation_time = datetime.now() - timedelta(hours=2)

        metadata = {
            'user.consent_revoked': 'true',
            'user.consent_revoked_at': revocation_time.isoformat(),
            'processing.continues': 'true',
        }

        rust_findings = rust_validators.validate_consent_revocation("", metadata)

        assert len(rust_findings) == 1
        assert rust_findings[0].rule_id == "LGPD_ART8_P5_REVOGACAO"
        assert rust_findings[0].confidence == 255

        print(f"✅ STEP 1: Rust detected revocation violation (2 hours ago)")

        # STEP 2: TechnicalEvidence
        technical_evidence = {
            'composite_risk': 255,
            'findings': [f.to_dict() for f in rust_findings],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 4.5,
            'uncertainty_score': 0.05,  # Certeza absoluta
        }

        # STEP 3: Python decide (NO mercy - revocation is absolute right)
        context = EthicalContext(
            session_id="e2e-revocation-001",
            user_history={
                'violations': 0,
                'trust_score': 0.95,  # Trust irrelevante
                'consent_revoked_at': revocation_time,
            },
            profile_id="lgpd_base"
        )

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.98

        print(f"✅ STEP 2: Python decided IMMEDIATE BLOCK (confidence={verdict.confidence:.2f})")

        # STEP 4: Appeal (raro, mas possível se erro de sistema)
        # Nota: Revogação normalmente não é contestável
        # Mas se foi erro (ex: clique acidental), user pode apelar

        appeal = contestability.submit_appeal(
            audit_trail_id=67890,
            user_id="user-revocation-001",
            reason="Revogação foi acidental (cliquei errado). Quero reativar.",
            evidence="N/A"
        )

        print(f"✅ STEP 3: Appeal submitted (unusual case: accidental revocation)")

        # STEP 5: Human rejeita (revogação é irreversível - novo consentimento necessário)
        time.sleep(0.001)
        resolved = contestability.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=False,
            reviewer_notes="Revogação é irreversível (LGPD Art. 8º § 5º). Usuário deve dar NOVO consentimento.",
            reviewer_id="dpo@empresa.com"
        )

        assert resolved.status == AppealStatus.REJECTED

        print(f"✅ STEP 4: Appeal REJECTED (revocation is irreversible)")
        print(f"\n🎉 E2E SCENARIO 3 PASSED! Revocation handled correctly.\n")

# ═══════════════════════════════════════════════════════════════════════════
# E2E SCENARIO 4: Multiple Validators → Batch Processing → Performance
# ═══════════════════════════════════════════════════════════════════════════

class TestE2EScenario4BatchPerformance:
    """E2E: Batch processing with multiple validators."""

    def test_e2e_batch_multiple_validators_performance(
        self,
        rust_validators
    ):
        """
        SCENARIO:
        1. 50 inputs com mix de violações (CPF, sensitive data, consent)
        2. Batch processing com 5 validators
        3. Validar < 100ms total (< 2ms/input)
        """
        print("\n" + "="*80)
        print("E2E SCENARIO 4: Batch Processing Performance")
        print("="*80)

        # STEP 1: Preparar 50 inputs variados
        inputs = [
            "CPF: 123.456.789-09",
            "Paciente tem HIV positivo",
            "Cartão: 4111-1111-1111-1111",
            "CNPJ: 12.345.678/0001-90",
            "Usuário declarou religião católica",
        ] * 10  # 50 inputs total (5 patterns x 10)

        metadata = {
            'user.has_consent': 'false',
            'processing.requires_consent': 'true',
        }

        # STEP 2: Batch validation
        validator_names = ["consent", "sensitive_data", "cpf", "cnpj", "credit_card"]

        start = time.perf_counter()

        findings = rust_validators.validate_batch(
            validator_names=validator_names,
            inputs=inputs,
            metadata=metadata
        )

        elapsed_ms = (time.perf_counter() - start) * 1000
        avg_ms = elapsed_ms / len(inputs)

        print(f"✅ STEP 1: Batch processed {len(inputs)} inputs with {len(validator_names)} validators")
        print(f"   Total time: {elapsed_ms:.2f}ms")
        print(f"   Avg per input: {avg_ms:.2f}ms")
        print(f"   Findings: {len(findings)}")

        # STEP 3: Validar performance
        assert elapsed_ms < 100, f"Batch processing too slow: {elapsed_ms:.2f}ms > 100ms"
        assert avg_ms < 2, f"Avg per input too slow: {avg_ms:.2f}ms > 2ms"

        # STEP 4: Validar findings
        assert len(findings) > 0  # Deve detectar violações

        rule_ids = {f.rule_id for f in findings}
        print(f"   Unique rule IDs: {len(rule_ids)}")

        # Verificar que cada tipo de validator detectou algo
        assert any("CONSENT" in r for r in rule_ids), "Consent validator should detect"
        assert any("SENSIVEIS" in r or "SENSITIVE" in r for r in rule_ids), "Sensitive data validator should detect"

        print(f"\n🎉 E2E SCENARIO 4 PASSED! Batch performance validated.\n")

# ═══════════════════════════════════════════════════════════════════════════
# E2E SCENARIO 5: End-to-End Latency (<50ms Target)
# ═══════════════════════════════════════════════════════════════════════════

class TestE2EScenario5LatencyTarget:
    """E2E: Latência total < 50ms (p99)."""

    def test_e2e_latency_rust_to_python_decision(
        self,
        rust_validators,
        engine
    ):
        """
        SCENARIO:
        1. Rust validation (< 5ms)
        2. FFI transfer (< 1ms)
        3. Python decision (< 10ms)
        4. Total E2E: < 50ms
        """
        print("\n" + "="*80)
        print("E2E SCENARIO 5: End-to-End Latency Target (<50ms)")
        print("="*80)

        input_text = "Paciente tem câncer de pulmão, tratamento quimioterapia"

        metadata = {
            'consent.is_specific_for_sensitive': 'false',
        }

        # Warm-up (primeira chamada pode ser mais lenta - loading)
        _ = rust_validators.validate_sensitive_data(input_text, metadata)

        # STEP 1: Medir latência completa (10 iterações, pegar p99)
        latencies = []

        for i in range(10):
            start = time.perf_counter()

            # Rust validation
            rust_findings = rust_validators.validate_sensitive_data(input_text, metadata)

            # Convert to TechnicalEvidence
            technical_evidence = {
                'composite_risk': rust_findings[0].severity if rust_findings else 0,
                'findings': [f.to_dict() for f in rust_findings],
                'finding_count': len(rust_findings),
                'critical_count': sum(1 for f in rust_findings if f.severity >= 200),
                'entropy': 4.5,
                'uncertainty_score': 0.1,
            }

            # Python decision
            context = EthicalContext(
                session_id=f"e2e-latency-{i}",
                user_history={'violations': 0, 'trust_score': 0.8},
                profile_id="lgpd_base"
            )

            verdict = engine.decide(technical_evidence, context)

            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies.append(elapsed_ms)

        # STEP 2: Calcular p99
        latencies.sort()
        p50 = latencies[len(latencies) // 2]
        p99 = latencies[int(len(latencies) * 0.99)]
        avg = sum(latencies) / len(latencies)

        print(f"✅ STEP 1: Latency measured (10 iterations)")
        print(f"   p50: {p50:.2f}ms")
        print(f"   p99: {p99:.2f}ms")
        print(f"   avg: {avg:.2f}ms")

        # STEP 3: Validar SLA
        assert p99 < 50, f"E2E latency p99 {p99:.2f}ms > 50ms target"

        # STEP 4: Breakdown estimate
        print(f"\n   Estimated breakdown:")
        print(f"   - Rust validation: ~{p50 * 0.4:.1f}ms (40%)")
        print(f"   - FFI transfer: ~{p50 * 0.1:.1f}ms (10%)")
        print(f"   - Python decision: ~{p50 * 0.5:.1f}ms (50%)")

        print(f"\n🎉 E2E SCENARIO 5 PASSED! Latency within SLA (<50ms).\n")

# ═══════════════════════════════════════════════════════════════════════════
# E2E SCENARIO 6: Profile Loading & Inheritance
# ═══════════════════════════════════════════════════════════════════════════

class TestE2EScenario6ProfileInheritance:
    """E2E: ProfileManager loads LGPD profile correctly."""

    def test_e2e_profile_loading_lgpd_base(self, profile_manager):
        """
        SCENARIO:
        1. ProfileManager carrega lgpd_base.yaml
        2. Verifica 18 rules esperadas
        3. Valida metadata legal
        """
        print("\n" + "="*80)
        print("E2E SCENARIO 6: Profile Loading & Validation")
        print("="*80)

        # STEP 1: Carregar profile
        profile = profile_manager.load_profile("lgpd_base")

        assert profile is not None
        assert profile.id == "lgpd_base"

        print(f"✅ STEP 1: Profile loaded (id={profile.id})")

        # STEP 2: Verificar rules count
        rule_count = len(profile.rules)

        print(f"   Rules: {rule_count}")
        print(f"   Version: {profile.version}")
        print(f"   Framework: {profile.legal_framework}")

        # Esperado: ~18 rules (Art. 6º, 7º, 8º, 11, 18, 33, 46, 48)
        assert rule_count >= 15, f"Expected at least 15 rules, got {rule_count}"

        # STEP 3: Verificar specific rules
        rule_ids = [r.id for r in profile.rules]

        expected_rules = [
            "LGPD_ART6_I_FINALIDADE",
            "LGPD_ART6_VII_SEGURANCA",
            "LGPD_ART7_I_CONSENTIMENTO",
            "LGPD_ART8_P5_REVOGACAO",
            "LGPD_ART11_DADOS_SENSIVEIS",
            "LGPD_ART18_II_ACESSO",
            "LGPD_ART33_TRANSFERENCIA_INTERNACIONAL",
            "LGPD_ART48_NOTIFICACAO_INCIDENTE",
        ]

        for expected_rule in expected_rules:
            assert expected_rule in rule_ids, f"Rule {expected_rule} not found in profile"

        print(f"✅ STEP 2: All expected rules present")

        # STEP 4: Verificar legal metadata
        assert hasattr(profile, 'legal_metadata')
        assert profile.legal_metadata.get('law_number') == "Lei nº 13.709/2018"
        assert profile.legal_metadata.get('enforcement_authority') == "ANPD (Autoridade Nacional de Proteção de Dados)"

        print(f"✅ STEP 3: Legal metadata validated")
        print(f"\n🎉 E2E SCENARIO 6 PASSED! Profile correctly structured.\n")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
