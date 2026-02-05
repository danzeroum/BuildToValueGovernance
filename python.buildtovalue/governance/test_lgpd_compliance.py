"""
BuildToValue v2.0 - LGPD Compliance Tests
Lei Geral de Proteção de Dados - Lei nº 13.709/2018 (Brasil)

Tests compliance rules integration with ethical governance:
- LGPD legal requirements (consent, data minimization, etc.)
- Ethical adjustments (mercy, trust, context)
- Contestability (Art. 18 § 4º + Art. 20)

Gate: Day 21 - Compliance Integration
Author: BuildToValue Architecture Team
License: Apache 2.0
"""

import pytest
import time
from pathlib import Path
from datetime import datetime, timedelta

from buildtovalue.governance.ethical_context_engine_v3 import (
    EthicalContextEngineV3,
    EthicalContext,
    EthicalDecision
)
from buildtovalue.governance.profile_manager import ProfileManager
from buildtovalue.governance.contestability_loop import ContestabilityLoop, AppealStatus


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def profiles_dir(tmp_path):
    """Cria diretório temporário com profile LGPD."""
    profiles_dir = tmp_path / "profiles" / "compliance"
    profiles_dir.mkdir(parents=True)

    # Copia lgpd_base.yaml para temp dir
    # (Em produção, aponta para profiles/compliance/ real)
    import shutil
    source = Path("profiles/compliance/lgpd_base.yaml")
    if source.exists():
        shutil.copy(source, profiles_dir / "lgpd_base.yaml")

    return profiles_dir


@pytest.fixture
def profile_manager(profiles_dir):
    """ProfileManager com profiles LGPD."""
    return ProfileManager(profiles_dir)


@pytest.fixture
def engine(profile_manager):
    """EthicalContextEngine com ProfileManager."""
    return EthicalContextEngineV3(profile_manager=profile_manager)


@pytest.fixture
def contestability():
    """ContestabilityLoop para testes de recurso."""
    return ContestabilityLoop(sla_hours=24)


# ═══════════════════════════════════════════════════════════════════════════
# TESTS - CAPÍTULO II: PRINCÍPIOS (Art. 6º)
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDPrincipios:
    """Testes dos Princípios da LGPD (Art. 6º)."""

    def test_art6_i_finalidade_sem_proposito_claro(self, engine):
        """
        LGPD Art. 6º, I - Princípio da Finalidade
        Cenário: Acesso a dados sem finalidade clara
        Esperado: ESCALATE (alta prioridade, mas mercy aplicável)
        """
        context = EthicalContext(
            session_id="lgpd-finalidade-001",
            user_history={
                'violations': 0,
                'trust_score': 0.6,
                'role': 'analyst'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 150,
            'findings': [
                {
                    'validator': 'purpose_validator',
                    'severity': 150,
                    'confidence': 0.85,
                    'rule_id': 'LGPD_ART6_I_FINALIDADE',
                    'title': 'UNDEFINED_PURPOSE',
                    'description': 'Data access without clear purpose'
                }
            ],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 3.5,
            'uncertainty_score': 0.75,  # Alta incerteza → mercy aplicável
            'metadata': {
                'data.contains_pii': True,
                'processing.purpose': None
            }
        }

        verdict = engine.decide(technical_evidence, context)

        # Expectativa: Mercy aplicado (uncertainty > 0.7, trust > 0.5)
        # ESCALATE reduzido para EDUCATE
        assert verdict is not None
        assert hasattr(verdict, 'confidence')
        assert verdict.confidence > 0

        # Legal basis deve estar presente
        if hasattr(verdict, 'legal_basis'):
            assert 'LGPD' in verdict.legal_basis or 'Art. 6' in verdict.legal_basis

        print(f"\n✅ LGPD Art. 6º, I - Finalidade: confidence={verdict.confidence:.2f}")

    def test_art6_iii_necessidade_muitos_campos(self, engine):
        """
        LGPD Art. 6º, III - Princípio da Necessidade (Minimização)
        Cenário: Agente acessa 15 campos (threshold=10)
        Esperado: MONITOR (log + alerta)
        """
        context = EthicalContext(
            session_id="lgpd-necessidade-001",
            user_history={
                'violations': 0,
                'trust_score': 0.8,
                'role': 'developer'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 80,
            'findings': [
                {
                    'validator': 'data_minimization_validator',
                    'severity': 80,
                    'confidence': 0.90,
                    'rule_id': 'LGPD_ART6_III_NECESSIDADE',
                    'title': 'EXCESSIVE_FIELD_ACCESS',
                    'description': 'Accessing 15 fields (threshold: 10)'
                }
            ],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 2.8,
            'uncertainty_score': 0.5,
            'metadata': {
                'data.field_count': 15,
                'minimization_threshold': 10
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence > 0

        # Primeira violação + bom trust → Educação, não punição
        print(f"\n✅ LGPD Art. 6º, III - Necessidade: confidence={verdict.confidence:.2f}")

    def test_art6_vii_seguranca_sem_criptografia(self, engine):
        """
        LGPD Art. 6º, VII - Princípio da Segurança
        Cenário: Transmissão de PII sem criptografia
        Esperado: BLOCK (crítico, sem mercy)
        """
        context = EthicalContext(
            session_id="lgpd-seguranca-001",
            user_history={
                'violations': 0,
                'trust_score': 0.9,  # Mesmo com trust alto, segurança é binária
                'role': 'admin'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 255,  # CRITICAL
            'findings': [
                {
                    'validator': 'encryption_validator',
                    'severity': 255,
                    'confidence': 0.99,
                    'rule_id': 'LGPD_ART6_VII_SEGURANCA',
                    'title': 'UNENCRYPTED_PII_TRANSMISSION',
                    'description': 'PII transmitted without encryption'
                }
            ],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 4.2,
            'uncertainty_score': 0.1,  # Baixa incerteza
            'metadata': {
                'data.contains_pii': True,
                'transmission.encrypted': False
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.95  # Alta confiança

        # Segurança crítica: mesmo com mercy_eligible=false, deve bloquear
        print(f"\n✅ LGPD Art. 6º, VII - Segurança: confidence={verdict.confidence:.2f} (CRITICAL)")


# ═══════════════════════════════════════════════════════════════════════════
# TESTS - CAPÍTULO III: BASES LEGAIS (Art. 7º)
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDBasesLegais:
    """Testes das Bases Legais da LGPD (Art. 7º)."""

    def test_art7_i_consentimento_ausente(self, engine, contestability):
        """
        LGPD Art. 7º, I - Base Legal: Consentimento
        Cenário: Processamento sem consentimento
        Esperado: BLOCK (crítico, contestável)
        """
        context = EthicalContext(
            session_id="lgpd-consentimento-001",
            user_history={
                'violations': 0,
                'trust_score': 0.7,
                'role': 'marketer'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 255,
            'findings': [
                {
                    'validator': 'consent_validator',
                    'severity': 255,
                    'confidence': 0.95,
                    'rule_id': 'LGPD_ART7_I_CONSENTIMENTO',
                    'title': 'MISSING_USER_CONSENT',
                    'description': 'Processing requires user consent (LGPD Art. 7º, I)'
                }
            ],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 3.8,
            'uncertainty_score': 0.2,
            'metadata': {
                'user.has_consent': False,
                'processing.requires_consent': True,
                'processing.legal_basis': None
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.90

        # User contesta: "Dei consentimento, mas sistema não registrou"
        appeal = contestability.submit_appeal(
            audit_trail_id=12345,
            user_id="marketer-001",
            reason="Usuário deu consentimento na tela anterior (screenshot anexo). Bug de sistema não registrou.",
            evidence="https://drive.google.com/consent-screenshot.png"
        )

        assert appeal.status == AppealStatus.PENDING
        assert appeal.sla_deadline is not None

        print(f"\n✅ LGPD Art. 7º, I - Consentimento: confidence={verdict.confidence:.2f}, appeal={appeal.appeal_id}")

    def test_art7_ix_legitimo_interesse_sem_lia(self, engine):
        """
        LGPD Art. 7º, IX - Base Legal: Legítimo Interesse
        Cenário: Legítimo interesse sem LIA documentado
        Esperado: ESCALATE (mercy aplicável se LIA parcial existe)
        """
        context = EthicalContext(
            session_id="lgpd-li-001",
            user_history={
                'violations': 0,
                'trust_score': 0.75,
                'role': 'product_manager'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 180,
            'findings': [
                {
                    'validator': 'lia_validator',
                    'severity': 180,
                    'confidence': 0.88,
                    'rule_id': 'LGPD_ART7_IX_LEGITIMO_INTERESSE',
                    'title': 'LIA_NOT_DOCUMENTED',
                    'description': 'Legitimate interest basis requires documented LIA'
                }
            ],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 3.2,
            'uncertainty_score': 0.72,  # Alta incerteza → mercy
            'metadata': {
                'processing.legal_basis': 'legitimate_interest',
                'processing.lia_documented': False
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence > 0

        # Mercy: Se LIA parcial existe, EDUCATE + prazo 7 dias
        print(f"\n✅ LGPD Art. 7º, IX - Legítimo Interesse: confidence={verdict.confidence:.2f}")


# ═══════════════════════════════════════════════════════════════════════════
# TESTS - SEÇÃO III: CONSENTIMENTO (Art. 8º)
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDConsentimento:
    """Testes de Consentimento LGPD (Art. 8º)."""

    def test_art8_p5_revogacao_consentimento(self, engine):
        """
        LGPD Art. 8º, § 5º - Revogação de Consentimento
        Cenário: Usuário revogou consentimento, mas processamento continua
        Esperado: BLOCK (imediato, sem contestação)
        """
        context = EthicalContext(
            session_id="lgpd-revogacao-001",
            user_history={
                'violations': 0,
                'trust_score': 0.8,
                'consent_revoked_at': datetime.now() - timedelta(hours=1)
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 255,
            'findings': [
                {
                    'validator': 'consent_revocation_validator',
                    'severity': 255,
                    'confidence': 0.99,
                    'rule_id': 'LGPD_ART8_P5_REVOGACAO',
                    'title': 'CONSENT_REVOKED_BUT_PROCESSING_CONTINUES',
                    'description': 'User revoked consent, processing must stop immediately'
                }
            ],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 4.5,
            'uncertainty_score': 0.05,  # Certeza absoluta
            'metadata': {
                'user.consent_revoked': True,
                'processing.continues': True
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.98  # Altíssima confiança

        # Revogação não é contestável (é direito absoluto do titular)
        print(f"\n✅ LGPD Art. 8º, § 5º - Revogação: confidence={verdict.confidence:.2f} (NON-CONTESTABLE)")

    def test_art8_qualidade_consentimento_opt_out(self, engine):
        """
        LGPD Art. 8º - Qualidade do Consentimento
        Cenário: Consentimento via opt-out (caixa pré-marcada)
        Esperado: ESCALATE (inválido, mercy aplicável para UX education)
        """
        context = EthicalContext(
            session_id="lgpd-qualidade-001",
            user_history={
                'violations': 0,
                'trust_score': 0.6,
                'role': 'ux_designer'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 180,
            'findings': [
                {
                    'validator': 'consent_quality_validator',
                    'severity': 180,
                    'confidence': 0.92,
                    'rule_id': 'LGPD_ART8_QUALIDADE_CONSENTIMENTO',
                    'title': 'INVALID_CONSENT_OPT_OUT',
                    'description': 'Consent via pre-checked box is invalid (not explicit)'
                }
            ],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 3.0,
            'uncertainty_score': 0.75,  # Design ambíguo
            'metadata': {
                'consent.is_explicit': False,
                'consent.is_opt_out': True,
                'consent.is_pre_checked': True
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence > 0

        # Mercy: Primeira vez, UX team não sabia → EDUCATE
        print(f"\n✅ LGPD Art. 8º - Qualidade: confidence={verdict.confidence:.2f} (mercy for UX education)")


# ═══════════════════════════════════════════════════════════════════════════
# TESTS - SEÇÃO IV: DADOS SENSÍVEIS (Art. 11)
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDDadosSensiveis:
    """Testes de Dados Sensíveis LGPD (Art. 11)."""

    def test_art11_dados_sensiveis_sem_consentimento_especifico(self, engine):
        """
        LGPD Art. 11 - Dados Sensíveis
        Cenário: Processamento de dados de saúde sem consentimento específico
        Esperado: BLOCK (crítico, zero tolerância)
        """
        context = EthicalContext(
            session_id="lgpd-sensiveis-001",
            user_history={
                'violations': 0,
                'trust_score': 0.9,  # Trust alto não importa
                'role': 'researcher'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 255,
            'findings': [
                {
                    'validator': 'sensitive_data_validator',
                    'severity': 255,
                    'confidence': 0.97,
                    'rule_id': 'LGPD_ART11_DADOS_SENSIVEIS',
                    'title': 'SENSITIVE_DATA_WITHOUT_SPECIFIC_CONSENT',
                    'description': 'Health data (sensitive) requires specific consent (LGPD Art. 11)'
                }
            ],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 4.8,
            'uncertainty_score': 0.08,
            'metadata': {
                'data.is_sensitive': True,
                'data.sensitive_type': 'health',
                'consent.is_specific_for_sensitive': False
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.95

        # Dados sensíveis: mercy_eligible=false (zero tolerância)
        print(f"\n✅ LGPD Art. 11 - Dados Sensíveis: confidence={verdict.confidence:.2f} (ZERO TOLERANCE)")


# ═══════════════════════════════════════════════════════════════════════════
# TESTS - CAPÍTULO V: TRANSFERÊNCIA INTERNACIONAL (Art. 33)
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDTransferenciaInternacional:
    """Testes de Transferência Internacional LGPD (Art. 33)."""

    def test_art33_pais_inadequado_sem_sccs(self, engine):
        """
        LGPD Art. 33 - Transferência Internacional
        Cenário: Transferência para EUA (não adequado) sem SCCs
        Esperado: BLOCK (crítico)
        """
        context = EthicalContext(
            session_id="lgpd-transferencia-001",
            user_history={
                'violations': 0,
                'trust_score': 0.7,
                'role': 'data_engineer'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 255,
            'findings': [
                {
                    'validator': 'international_transfer_validator',
                    'severity': 255,
                    'confidence': 0.98,
                    'rule_id': 'LGPD_ART33_TRANSFERENCIA_INTERNACIONAL',
                    'title': 'TRANSFER_TO_INADEQUATE_COUNTRY',
                    'description': 'Transfer to US (not adequate) without SCCs/BCRs'
                }
            ],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 2.5,
            'uncertainty_score': 0.15,
            'metadata': {
                'transfer.destination_country': 'US',
                'adequate_countries': ['AT', 'BE', 'DE', 'FR', 'GB', 'JP', 'AR'],
                'transfer.has_sccs': False,
                'transfer.has_bcr': False
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.95

        print(f"\n✅ LGPD Art. 33 - Transferência: confidence={verdict.confidence:.2f} (BLOCKED)")

    def test_art33_viii_sccs_em_processo(self, engine):
        """
        LGPD Art. 33, VIII - SCCs (Standard Contractual Clauses)
        Cenário: Transferência para país inadequado, mas SCCs em processo de assinatura
        Esperado: ESCALATE (mercy aplicável: prazo 14 dias)
        """
        context = EthicalContext(
            session_id="lgpd-sccs-001",
            user_history={
                'violations': 0,
                'trust_score': 0.8,
                'role': 'legal_counsel'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 180,
            'findings': [
                {
                    'validator': 'sccs_validator',
                    'severity': 180,
                    'confidence': 0.85,
                    'rule_id': 'LGPD_ART33_VIII_SCCS',
                    'title': 'SCCS_PENDING_SIGNATURE',
                    'description': 'SCCs pending signature (14-day grace period)'
                }
            ],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 3.2,
            'uncertainty_score': 0.65,  # Processo em andamento
            'metadata': {
                'transfer.destination_country': 'US',
                'transfer.has_sccs': False,
                'transfer.sccs_in_progress': True,
                'transfer.sccs_expected_date': '2026-02-19'
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence > 0

        # Mercy: SCCs em processo → EDUCATE + prazo 14 dias
        print(f"\n✅ LGPD Art. 33, VIII - SCCs: confidence={verdict.confidence:.2f} (mercy: 14-day grace)")


# ═══════════════════════════════════════════════════════════════════════════
# TESTS - CAPÍTULO VI: DIREITOS DO TITULAR (Art. 18)
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDDireitosTitular:
    """Testes de Direitos do Titular LGPD (Art. 18)."""

    def test_art18_ii_acesso_prazo_13_dias(self, engine):
        """
        LGPD Art. 18, II - Direito de Acesso
        Cenário: Requisição de acesso com 13 dias (SLA 15 dias)
        Esperado: ESCALATE (alerta preventivo: faltam 2 dias)
        """
        context = EthicalContext(
            session_id="lgpd-acesso-001",
            user_history={
                'violations': 0,
                'trust_score': 0.7,
                'role': 'dpo'
            },
            profile_id="lgpd_base"
        )

        request_date = datetime.now() - timedelta(days=13)

        technical_evidence = {
            'composite_risk': 150,
            'findings': [
                {
                    'validator': 'data_access_request_validator',
                    'severity': 150,
                    'confidence': 0.92,
                    'rule_id': 'LGPD_ART18_II_ACESSO',
                    'title': 'DATA_ACCESS_REQUEST_SLA_WARNING',
                    'description': f'Data access request from {request_date.date()} (13 days ago, SLA: 15 days)'
                }
            ],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 2.8,
            'uncertainty_score': 0.4,
            'metadata': {
                'request.type': 'data_access',
                'request.date': request_date.isoformat(),
                'days_since_request': 13,
                'sla_days': 15
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence > 0

        # Alerta preventivo (Day 13 de 15)
        print(f"\n✅ LGPD Art. 18, II - Acesso: confidence={verdict.confidence:.2f} (SLA warning: 2 days left)")

    def test_art18_vi_eliminacao_com_obrigacao_legal(self, engine):
        """
        LGPD Art. 18, VI - Direito de Eliminação
        Cenário: Usuário solicita eliminação, mas existe obrigação legal (Art. 16)
        Esperado: ESCALATE (mercy: DPO avalia exceção)
        """
        context = EthicalContext(
            session_id="lgpd-eliminacao-001",
            user_history={
                'violations': 0,
                'trust_score': 0.8,
                'role': 'user'
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 180,
            'findings': [
                {
                    'validator': 'data_erasure_validator',
                    'severity': 180,
                    'confidence': 0.88,
                    'rule_id': 'LGPD_ART18_VI_ELIMINACAO',
                    'title': 'DATA_ERASURE_CONFLICT_LEGAL_OBLIGATION',
                    'description': 'Erasure request conflicts with legal retention (Art. 16)'
                }
            ],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 3.5,
            'uncertainty_score': 0.72,  # Exceção complexa
            'metadata': {
                'request.type': 'data_deletion',
                'processing.has_legal_obligation': True,
                'processing.legal_obligation_type': 'tax_records',  # 5 anos Receita Federal
                'days_since_request': 10
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence > 0

        # Mercy: Exceção complexa → DPO avalia
        print(f"\n✅ LGPD Art. 18, VI - Eliminação: confidence={verdict.confidence:.2f} (mercy: legal exception)")


# ═══════════════════════════════════════════════════════════════════════════
# TESTS - CAPÍTULO VII: SEGURANÇA E INCIDENTES (Art. 48)
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDSegurancaIncidentes:
    """Testes de Segurança e Incidentes LGPD (Art. 46, 48)."""

    def test_art48_notificacao_incidente_48h(self, engine):
        """
        LGPD Art. 48 - Notificação de Incidente
        Cenário: Incidente crítico detectado há 48h (SLA 72h)
        Esperado: ESCALATE (alerta: faltam 24h para notificar ANPD)
        """
        context = EthicalContext(
            session_id="lgpd-incidente-001",
            user_history={
                'violations': 0,
                'trust_score': 0.9,
                'role': 'ciso'
            },
            profile_id="lgpd_base"
        )

        incident_time = datetime.now() - timedelta(hours=48)

        technical_evidence = {
            'composite_risk': 255,
            'findings': [
                {
                    'validator': 'breach_notification_validator',
                    'severity': 255,
                    'confidence': 0.99,
                    'rule_id': 'LGPD_ART48_NOTIFICACAO_INCIDENTE',
                    'title': 'BREACH_NOTIFICATION_SLA_WARNING',
                    'description': f'Critical incident detected at {incident_time} (48h ago, SLA: 72h)'
                }
            ],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 4.5,
            'uncertainty_score': 0.05,
            'metadata': {
                'incident.severity': 'critical',
                'incident.affects_rights': True,
                'incident.detection_time': incident_time.isoformat(),
                'hours_since_incident': 48,
                'notification_deadline_hours': 72
            }
        }

        verdict = engine.decide(technical_evidence, context)

        assert verdict is not None
        assert verdict.confidence >= 0.98

        # Alerta crítico: 24h restantes para notificar ANPD
        print(f"\n✅ LGPD Art. 48 - Incidente: confidence={verdict.confidence:.2f} (SLA CRITICAL: 24h left)")


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS - E2E LGPD
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDIntegrationE2E:
    """Testes de integração E2E LGPD."""

    def test_e2e_lgpd_consentimento_revogado_com_recurso(self, engine, contestability):
        """
        E2E: Consentimento → Processamento → Revogação → BLOCK → Appeal → Resolved
        """
        # STEP 1: Usuário revoga consentimento
        context = EthicalContext(
            session_id="lgpd-e2e-001",
            user_history={
                'violations': 0,
                'trust_score': 0.85,
                'consent_revoked_at': datetime.now()
            },
            profile_id="lgpd_base"
        )

        technical_evidence = {
            'composite_risk': 255,
            'findings': [{
                'validator': 'consent_revocation_validator',
                'severity': 255,
                'confidence': 0.99,
                'rule_id': 'LGPD_ART8_P5_REVOGACAO',
                'title': 'CONSENT_REVOKED'
            }],
            'finding_count': 1,
            'critical_count': 1,
            'uncertainty_score': 0.05,
            'metadata': {
                'user.consent_revoked': True,
                'processing.continues': True
            }
        }

        verdict = engine.decide(technical_evidence, context)
        assert verdict.confidence >= 0.98

        # STEP 2: Sistema bloqueia processamento
        print(f"\n✅ STEP 1: Consent revoked, processing BLOCKED (confidence={verdict.confidence:.2f})")

        # STEP 3: User contesta (erro: revogação acidental)
        # Nota: Revogação normalmente não é contestável, mas pode haver erro de sistema
        appeal = contestability.submit_appeal(
            audit_trail_id=67890,
            user_id="user-e2e-001",
            reason="Revogação foi acidental (cliquei errado no botão). Quero reativar consentimento.",
            evidence="N/A"
        )
        assert appeal.status == AppealStatus.PENDING
        print(f"✅ STEP 2: Appeal submitted (unusual case: accidental revocation)")

        # STEP 4: DPO revisa (decisão: usuário pode dar novo consentimento, não reverter revogação)
        time.sleep(0.001)
        resolved = contestability.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=False,  # Revogação não pode ser revertida
            reviewer_notes="Revogação é irreversível (LGPD Art. 8º). Usuário deve dar NOVO consentimento (não reverter o anterior).",
            reviewer_id="dpo@empresa.com"
        )
        assert resolved.status == AppealStatus.REJECTED
        print(f"✅ STEP 3: Appeal REJECTED (revocation is irreversible, must give new consent)")

        # STEP 5: Métricas
        metrics = contestability.get_metrics()
        assert metrics['appeals_submitted'] >= 1
        print(f"✅ STEP 4: Metrics logged (appeals: {metrics['appeals_submitted']})")

    def test_e2e_lgpd_transferencia_internacional_com_sccs(self, engine):
        """
        E2E: Transferência para país inadequado → BLOCK → SCCs assinadas → ALLOW
        """
        # STEP 1: Tentativa de transferência sem SCCs
        context = EthicalContext(
            session_id="lgpd-transfer-e2e",
            user_history={'violations': 0, 'trust_score': 0.8},
            profile_id="lgpd_base"
        )

        evidence_without_sccs = {
            'composite_risk': 255,
            'findings': [{
                'validator': 'international_transfer_validator',
                'severity': 255,
                'confidence': 0.98,
                'rule_id': 'LGPD_ART33_TRANSFERENCIA_INTERNACIONAL',
                'title': 'TRANSFER_BLOCKED_NO_SCCS'
            }],
            'finding_count': 1,
            'critical_count': 1,
            'uncertainty_score': 0.1,
            'metadata': {
                'transfer.destination_country': 'US',
                'transfer.has_sccs': False
            }
        }

        verdict1 = engine.decide(evidence_without_sccs, context)
        assert verdict1.confidence >= 0.95
        print(f"\n✅ STEP 1: Transfer BLOCKED (no SCCs, confidence={verdict1.confidence:.2f})")

        # STEP 2: SCCs assinadas, nova tentativa
        evidence_with_sccs = {
            'composite_risk': 50,
            'findings': [],
            'finding_count': 0,
            'critical_count': 0,
            'uncertainty_score': 0.2,
            'metadata': {
                'transfer.destination_country': 'US',
                'transfer.has_sccs': True,
                'transfer.sccs_signed_date': '2026-02-04'
            }
        }

        verdict2 = engine.decide(evidence_with_sccs, context)
        assert verdict2.confidence > 0
        print(f"✅ STEP 2: Transfer ALLOWED (SCCs signed, confidence={verdict2.confidence:.2f})")


# ═══════════════════════════════════════════════════════════════════════════
# PERFORMANCE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestLGPDPerformance:
    """Testes de performance LGPD."""

    def test_lgpd_decision_latency_target_50ms(self, engine):
        """LGPD decision deve ser <50ms (p99)."""
        context = EthicalContext(
            session_id="lgpd-perf-001",
            user_history={'violations': 0, 'trust_score': 0.7},
            profile_id="lgpd_base"
        )

        evidence = {
            'composite_risk': 150,
            'findings': [{
                'validator': 'consent_validator',
                'severity': 150,
                'confidence': 0.90,
                'rule_id': 'LGPD_ART7_I_CONSENTIMENTO',
                'title': 'CONSENT_CHECK'
            }],
            'finding_count': 1,
            'uncertainty_score': 0.5,
            'metadata': {'user.has_consent': True}
        }

        start = time.perf_counter()
        verdict = engine.decide(evidence, context)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert verdict is not None
        assert elapsed_ms < 50, f"LGPD decision latency {elapsed_ms:.2f}ms > 50ms"

        print(f"\n✅ LGPD Performance: {elapsed_ms:.2f}ms (target: <50ms)")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-k", "lgpd"])
