"""SkillBehaviorMonitor — Cenário 33: Supply Chain de Plugins (Cavalo de Troia).

Detecta desvio estatístico de comportamento de skills/plugins ao longo de múltiplas
sessões. Compara a distribuição de categorias de ação recentes com o baseline histórico
armazenado no DurableLedger (imutável).

Dependência: E7 (goal_drift_ffi.rs) para cálculo de drift de categoria via FFI.
Se FFI não disponível, cai para análise puramente Python (baseline simples).

Integração: ToolCallGuard.validate_post_with_audit() chama detect_anomaly() após
registrar o output de cada tool call.

Invariantes:
  - Fail-secure: erro → retorna SkillAnomalyFinding de segurança
  - explain_decision obrigatório em SkillAnomalyFinding
  - Baseline persistido no DurableLedger (append-only)
  - Funções ≤ 50 linhas
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.skill_behavior_monitor")

# Threshold: se categoria nova aparece com freq > X do total → anomalia
_ANOMALY_THRESHOLD = 0.30

# Categorias de ação que sempre disparam alerta se forem novas
_HIGH_RISK_CATEGORIES = frozenset({
    "FINANCIAL_TRANSFER",
    "DATA_EXFILTRATION",
    "CREDENTIAL_ACCESS",
    "IDENTITY_IMPERSONATION",
    "PRIVATE_KEY_ACCESS",
})


@dataclass(frozen=True)
class SkillAnomalyFinding:
    """Anomalia detectada no comportamento de uma skill."""
    skill_id: str
    anomalous_category: str   # categoria que disparou a anomalia
    baseline_rate: float      # taxa histórica da categoria (0.0 se nova)
    current_rate: float       # taxa na janela atual
    explain_decision: str     # obrigatório (Levinas)


class SkillBehaviorMonitor:
    """Monitora e detecta desvio comportamental de skills ao longo de sessões."""

    def __init__(self, anomaly_threshold: float = _ANOMALY_THRESHOLD) -> None:
        self._threshold = anomaly_threshold
        # Cache in-memory da sessão atual: skill_id → Counter de categorias
        self._session_actions: Dict[str, Counter] = {}

    def record_action(
        self,
        skill_id: str,
        action_category: str,
        ledger: DurableLedger,
    ) -> None:
        """Registra uma ação da skill no cache de sessão e no DurableLedger.

        Fail-secure: erro no ledger → loga mas não bloqueia (registro assíncrono).
        """
        # Atualiza cache in-memory
        if skill_id not in self._session_actions:
            self._session_actions[skill_id] = Counter()
        self._session_actions[skill_id][action_category] += 1

        # Persiste no ledger imutável
        try:
            ledger.append({
                "type": "skill_action",
                "skill_id": skill_id,
                "action_category": action_category,
                "explain_decision": (
                    f"Ação registrada: skill={skill_id} category={action_category}"
                ),
            })
        except Exception as exc:  # noqa: BLE001
            logger.warning("Falha ao persistir skill_action no ledger: %s", exc)

    def detect_anomaly(
        self,
        skill_id: str,
        ledger: Optional[DurableLedger] = None,
        window_sessions: int = 10,
    ) -> Optional[SkillAnomalyFinding]:
        """Detecta anomalia comparando distribuição atual com baseline histórico.

        Retorna `SkillAnomalyFinding` se anomalia encontrada, `None` caso contrário.
        Fail-secure: erro interno → retorna SkillAnomalyFinding (BLOCK).
        """
        try:
            return self._detect_inner(skill_id, ledger, window_sessions)
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro no SkillBehaviorMonitor.detect_anomaly: %s", exc)
            return SkillAnomalyFinding(
                skill_id=skill_id,
                anomalous_category="INTERNAL_ERROR",
                baseline_rate=0.0,
                current_rate=1.0,
                explain_decision=(
                    f"Erro interno no SkillBehaviorMonitor: {exc}. "
                    "BLOCK por fail-secure."
                ),
            )

    def _detect_inner(
        self,
        skill_id: str,
        ledger: Optional[DurableLedger],
        window_sessions: int,
    ) -> Optional[SkillAnomalyFinding]:
        """Lógica de detecção: compara sessão atual com baseline do ledger."""
        current = self._session_actions.get(skill_id, Counter())
        if not current:
            return None  # nenhuma ação registrada nesta sessão

        current_total = sum(current.values())
        if current_total == 0:
            return None

        # Obtém baseline histórico do ledger (se disponível)
        baseline = self._load_baseline(skill_id, ledger) if ledger else Counter()

        for category, count in current.items():
            current_rate = count / current_total
            baseline_total = sum(baseline.values())
            baseline_rate = (baseline.get(category, 0) / baseline_total
                             if baseline_total > 0 else 0.0)

            is_new_high_risk = category in _HIGH_RISK_CATEGORIES and baseline_rate == 0.0
            is_rate_spike = (current_rate - baseline_rate) > self._threshold

            if is_new_high_risk or is_rate_spike:
                return SkillAnomalyFinding(
                    skill_id=skill_id,
                    anomalous_category=category,
                    baseline_rate=baseline_rate,
                    current_rate=current_rate,
                    explain_decision=(
                        f"Anomalia detectada na skill '{skill_id}': "
                        f"categoria '{category}' aparece com taxa {current_rate:.1%} "
                        f"(baseline: {baseline_rate:.1%}). "
                        f"Possível Cavalo de Troia / Supply Chain Attack."
                    ),
                )
        return None

    def _load_baseline(
        self, skill_id: str, ledger: DurableLedger
    ) -> Counter:
        """Carrega histórico de ações da skill do DurableLedger."""
        baseline: Counter = Counter()
        for entry in ledger.entries():
            payload = entry.payload
            if (
                payload.get("type") == "skill_action"
                and payload.get("skill_id") == skill_id
            ):
                cat = payload.get("action_category", "")
                if cat:
                    baseline[cat] += 1
        return baseline


# ---------------------------------------------------------------------------
# Testes unitários
# ---------------------------------------------------------------------------

class TestSkillBehaviorMonitor:
    """pytest: pytest -k SkillBehaviorMonitor"""

    def _make_ledger(self) -> DurableLedger:
        return DurableLedger(hmac_key=b"test-key")

    def test_no_anomaly_normal_behavior(self) -> None:
        monitor = SkillBehaviorMonitor()
        ledger  = self._make_ledger()
        for _ in range(5):
            monitor.record_action("dentist-booker", "CALENDAR_WRITE", ledger)
        result = monitor.detect_anomaly("dentist-booker", ledger)
        assert result is None

    def test_high_risk_new_category_flagged(self) -> None:
        monitor = SkillBehaviorMonitor()
        ledger  = self._make_ledger()
        # Baseline: apenas CALENDAR_WRITE
        for _ in range(5):
            monitor.record_action("dentist-booker", "CALENDAR_WRITE", ledger)
        # Nova sessão: FINANCIAL_TRANSFER aparece (novo, high risk)
        monitor._session_actions["dentist-booker"]["FINANCIAL_TRANSFER"] = 2
        result = monitor.detect_anomaly("dentist-booker", ledger)
        assert result is not None
        assert result.anomalous_category == "FINANCIAL_TRANSFER"

    def test_empty_session_no_anomaly(self) -> None:
        monitor = SkillBehaviorMonitor()
        ledger  = self._make_ledger()
        assert monitor.detect_anomaly("unknown-skill", ledger) is None
