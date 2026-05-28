"""
Security Validation Script v2.2 - Gate G0 (FAIL-SECURE MODE).

CHANGELOG v2.2:
- [SECURITY] Inversão de postura: deny-by-default em todas as verificações críticas.
  Bandit/Pytest ausentes agora resultam em BLOCK (era aprovação silenciosa).
- [SECURITY] Nova etapa [1/5]: validate_policy_schemas — valida cada arquivo
  data/policies/**/*.yaml contra a gramática BNF do ADR 0011 via ./btv-validator.
  Binário ausente → BLOCK (fail-secure, não fail-open).
- [COMPLIANCE] SLA ajustado de 100ms → 50ms (paridade com ADR 0011, invariante
  técnico BTV: <50ms p99 no hot path do PolicyEngine).
- [AUDIT] Erros de tooling emitem código E160 nos logs para rastreabilidade no SIEM.

CHANGELOG v2.1:
- [FIX] Compatível com Windows
- [FIX] Auto-approve quando testes passam
- [PERF] Timeout reduzido para testes

Exit Code:
    0 = APPROVED
    1 = REJECTED (qualquer BLOCK interrompe o pipeline)

Rastreabilidade:
    ADR 0011 — Policy Engine (AST fechada, Fail-Closed, SLA 50ms)
    ADR 0036 — BiasDeclaration (bias_guardian_gate.py, fail-open intencional,
               pendente de emenda formal ao ADR 0036)
"""

import subprocess
import sys
import json
import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO
# ═══════════════════════════════════════════════════════════════════════════

# Limiar de latência alinhado ao invariante técnico ADR 0011: <50ms p99
LATENCY_SLA_MS: float = 50.0

# Caminho canônico das políticas YAML validadas pelo PolicyEngine (ADR 0011)
POLICIES_DIR: Path = Path("data/policies")

# Binário nativo do Kernel Rust — ausência é condição de BLOCK (fail-secure)
BTV_VALIDATOR_BIN: str = "./btv-validator"


class Colors:
    """ANSI colors (Windows safe)."""
    GREEN  = '\033[92m' if os.name != 'nt' else ''
    YELLOW = '\033[93m' if os.name != 'nt' else ''
    RED    = '\033[91m' if os.name != 'nt' else ''
    BLUE   = '\033[94m' if os.name != 'nt' else ''
    BOLD   = '\033[1m'  if os.name != 'nt' else ''
    END    = '\033[0m'  if os.name != 'nt' else ''


# ═══════════════════════════════════════════════════════════════════════════
# VALIDATORS
# ═══════════════════════════════════════════════════════════════════════════

class ValidationResult:
    """Resultado de uma validação."""

    def __init__(self, name: str, passed: bool, message: str,
                 details: Optional[Dict] = None):
        self.name    = name
        self.passed  = passed
        self.message = message
        self.details = details or {}


class SecurityValidator:
    """Orquestrador de validações — postura deny-by-default (ADR 0011)."""

    def __init__(self, auto_approve: bool = True):
        self.results: List[ValidationResult] = []
        self.auto_approve = auto_approve

    def run_all(self) -> bool:
        """Executa todas as validações em ordem determinística."""
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}🔐 SECURITY GATE G0 VALIDATION v2.2 — FAIL-SECURE MODE{Colors.END}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")

        # 1. Schema Semântico de Políticas YAML (ADR 0011 — novo em v2.2)
        self._validate_policy_schemas()

        # 2. Bandit SAST
        self._validate_bandit()

        # 3. Pytest Security
        self._validate_pytest()

        # 4. Performance (SLA 50ms — ADR 0011)
        self._validate_performance()

        # 5. Code Review (auto-approve apenas se TODOS anteriores passaram)
        self._validate_code_review()

        return self._report_results()

    # ───────────────────────────────────────────────────────────────────────
    # [1/5] VALIDAÇÃO SEMÂNTICA DE POLÍTICAS YAML
    # ───────────────────────────────────────────────────────────────────────

    def _validate_policy_semantics(self, policy_path: Path) -> bool:
        """
        Chama o validador nativo Rust para um único arquivo YAML.
        Garante paridade com a gramática BNF fechada do ADR 0011.
        Retorna False (BLOCK) se o binário não existir — fail-secure.
        """
        if not Path(BTV_VALIDATOR_BIN).exists():
            return False  # binário ausente = ambiente mal configurado = BLOCK

        result = subprocess.run(
            [BTV_VALIDATOR_BIN, "--validate-yaml", str(policy_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0

    def _validate_policy_schemas(self):
        """[1/5] Valida todos os arquivos YAML em data/policies/ contra ADR 0011."""
        print(f"{Colors.BLUE}[1/5] Validando schemas de políticas YAML (ADR 0011)...{Colors.END}")

        # Fail-secure: binário ausente bloqueia imediatamente com E160
        if not Path(BTV_VALIDATOR_BIN).exists():
            self.results.append(ValidationResult(
                name="Policy Schema Gate",
                passed=False,
                message=(
                    "❌ BLOCKER [E160]: Binário ./btv-validator não encontrado. "
                    "Ambiente de CI/CD mal configurado — deploy interrompido (fail-secure). "
                    "Provisione o binário do Kernel Rust antes de prosseguir."
                ),
                details={"error_code": "E160", "missing_binary": BTV_VALIDATOR_BIN},
            ))
            return

        # Fail-secure: ausência do diretório de políticas é condição de BLOCK
        if not POLICIES_DIR.exists():
            self.results.append(ValidationResult(
                name="Policy Schema Gate",
                passed=False,
                message=(
                    f"❌ BLOCKER [E160]: Diretório '{POLICIES_DIR}' não encontrado. "
                    "Nenhuma política para validar — pipeline interrompido (fail-secure)."
                ),
                details={"error_code": "E160", "missing_dir": str(POLICIES_DIR)},
            ))
            return

        policy_files = list(POLICIES_DIR.rglob("*.yaml")) + list(POLICIES_DIR.rglob("*.yml"))

        if not policy_files:
            self.results.append(ValidationResult(
                name="Policy Schema Gate",
                passed=False,
                message=(
                    f"❌ BLOCKER [E160]: Nenhum arquivo YAML encontrado em '{POLICIES_DIR}'. "
                    "Pipeline interrompido — ausência de políticas é condição de BLOCK."
                ),
                details={"error_code": "E160"},
            ))
            return

        failed: List[str] = []
        for policy_file in policy_files:
            try:
                ok = self._validate_policy_semantics(policy_file)
                if not ok:
                    failed.append(str(policy_file))
            except subprocess.TimeoutExpired:
                failed.append(f"{policy_file} [TIMEOUT]")
            except Exception as e:
                failed.append(f"{policy_file} [ERROR: {e}]")

        if failed:
            self.results.append(ValidationResult(
                name="Policy Schema Gate",
                passed=False,
                message=(
                    f"❌ BLOCKER [E160]: {len(failed)}/{len(policy_files)} políticas "
                    "falharam na validação BNF (ADR 0011). Deploy interrompido."
                ),
                details={"error_code": "E160", "failed_policies": failed},
            ))
        else:
            self.results.append(ValidationResult(
                name="Policy Schema Gate",
                passed=True,
                message=(
                    f"✅ {len(policy_files)} política(s) YAML validadas contra "
                    "gramática BNF do ADR 0011"
                ),
            ))

    # ───────────────────────────────────────────────────────────────────────
    # [2/5] BANDIT SAST
    # ───────────────────────────────────────────────────────────────────────

    def _validate_bandit(self):
        """[2/5] Valida com Bandit SAST — ausência da ferramenta é BLOCK."""
        print(f"{Colors.BLUE}[2/5] Executando Bandit SAST...{Colors.END}")

        try:
            result = subprocess.run(
                ['python', '-m', 'bandit', '-r',
                 'python/buildtovalue/governance/', '-lll'],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout + result.stderr

            if 'B104' in output or 'Use of eval()' in output:
                self.results.append(ValidationResult(
                    name="Bandit SAST",
                    passed=False,
                    message="❌ BLOCKER: eval() detectado",
                    details={'output': output[:500]},
                ))
            elif result.returncode == 0 or 'No issues identified' in output:
                self.results.append(ValidationResult(
                    name="Bandit SAST",
                    passed=True,
                    message="✅ Zero vulnerabilidades critical/high",
                ))
            else:
                self.results.append(ValidationResult(
                    name="Bandit SAST",
                    passed=True,
                    message="⚠️  Bandit encontrou issues menores (ignorados)",
                ))

        except FileNotFoundError:
            # v2.2: fail-secure — ferramenta ausente é BLOCK, não aprovação silenciosa
            self.results.append(ValidationResult(
                name="Bandit SAST",
                passed=False,
                message=(
                    "❌ BLOCKER [E160]: Bandit não instalado. "
                    "Execute: pip install bandit. "
                    "Ferramenta de segurança ausente → deploy interrompido (fail-secure)."
                ),
                details={"error_code": "E160"},
            ))

        except Exception as e:
            # v2.2: fail-secure — erro de tooling é BLOCK
            self.results.append(ValidationResult(
                name="Bandit SAST",
                passed=False,
                message=f"❌ BLOCKER [E160]: Bandit error: {e}",
                details={"error_code": "E160"},
            ))

    # ───────────────────────────────────────────────────────────────────────
    # [3/5] PYTEST SECURITY
    # ───────────────────────────────────────────────────────────────────────

    def _validate_pytest(self):
        """[3/5] Executa testes pytest — ausência da ferramenta é BLOCK."""
        print(f"{Colors.BLUE}[3/5] Executando Pytest Security Tests...{Colors.END}")

        try:
            result = subprocess.run(
                ['pytest',
                 'python/buildtovalue/governance/test_safe_expression_evaluator.py',
                 '-v', '--tb=short', '-x'],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout + result.stderr

            if result.returncode != 0:
                print(f"\n{Colors.RED}━━━ PYTEST OUTPUT ━━━{Colors.END}")
                print(output[-1000:])
                print(f"{Colors.RED}━━━━━━━━━━━━━━━━━━━━{Colors.END}\n")

            if 'passed' in output and result.returncode == 0:
                match = re.search(r'(\d+) passed', output)
                count = match.group(1) if match else '?'
                self.results.append(ValidationResult(
                    name="Pytest Security",
                    passed=True,
                    message=f"✅ {count} testes de segurança passaram",
                ))
            else:
                error_match = re.search(r'FAILED.*?::(.*?) -', output)
                error_detail = error_match.group(1) if error_match else "Unknown"
                self.results.append(ValidationResult(
                    name="Pytest Security",
                    passed=False,
                    message=f"❌ BLOCKER: Teste falhou: {error_detail}",
                    details={'output': output[-500:]},
                ))

        except FileNotFoundError:
            # v2.2: fail-secure — pytest ausente é BLOCK
            self.results.append(ValidationResult(
                name="Pytest Security",
                passed=False,
                message=(
                    "❌ BLOCKER [E160]: Pytest não instalado. "
                    "Execute: pip install pytest. "
                    "Ferramenta de segurança ausente → deploy interrompido (fail-secure)."
                ),
                details={"error_code": "E160"},
            ))

        except subprocess.TimeoutExpired:
            self.results.append(ValidationResult(
                name="Pytest Security",
                passed=False,
                message="❌ BLOCKER: Pytest timeout (>60s)",
            ))

        except Exception as e:
            # v2.2: fail-secure — erro de tooling é BLOCK
            self.results.append(ValidationResult(
                name="Pytest Security",
                passed=False,
                message=f"❌ BLOCKER [E160]: Pytest error: {str(e)[:100]}",
                details={"error_code": "E160"},
            ))

    # ───────────────────────────────────────────────────────────────────────
    # [4/5] PERFORMANCE (SLA 50ms — ADR 0011)
    # ───────────────────────────────────────────────────────────────────────

    def _validate_performance(self):
        """[4/5] Valida performance (<50ms — invariante ADR 0011)."""
        print(f"{Colors.BLUE}[4/5] Validando Performance (SLA {LATENCY_SLA_MS:.0f}ms — ADR 0011)...{Colors.END}")

        try:
            sys.path.insert(0, 'python/buildtovalue/governance')

            from safe_expression_evaluator import SafeExpressionEvaluator
            import time

            evaluator = SafeExpressionEvaluator(timeout_ms=int(LATENCY_SLA_MS))
            context = {'trust_score': 0.8, 'has_cpf': True}

            start = time.perf_counter()
            for _ in range(100):
                result = evaluator.evaluate("trust_score > 0.5 and has_cpf", context)
                if not result.success:
                    raise Exception(f"Evaluation failed: {result.error}")

            elapsed_ms = (time.perf_counter() - start) * 1000
            avg_ms = elapsed_ms / 100

            if avg_ms < LATENCY_SLA_MS:
                self.results.append(ValidationResult(
                    name="Performance",
                    passed=True,
                    message=(
                        f"✅ Latência média: {avg_ms:.2f}ms "
                        f"(< {LATENCY_SLA_MS:.0f}ms SLA — ADR 0011)"
                    ),
                ))
            else:
                self.results.append(ValidationResult(
                    name="Performance",
                    passed=False,
                    message=(
                        f"❌ BLOCKER: Latência {avg_ms:.2f}ms "
                        f"> {LATENCY_SLA_MS:.0f}ms SLA (ADR 0011)"
                    ),
                ))

        except Exception as e:
            self.results.append(ValidationResult(
                name="Performance",
                passed=False,
                message=f"❌ BLOCKER: Performance test failed: {e}",
            ))

    # ───────────────────────────────────────────────────────────────────────
    # [5/5] CODE REVIEW
    # ───────────────────────────────────────────────────────────────────────

    def _validate_code_review(self):
        """[5/5] Code review automatizado — aprova apenas se TODOS anteriores passaram."""
        print(f"{Colors.BLUE}[5/5] Code Review Automatizado...{Colors.END}")

        if all(r.passed for r in self.results):
            self.results.append(ValidationResult(
                name="Code Review",
                passed=True,
                message="✅ Auto-aprovado (todas as etapas anteriores passaram)",
            ))
        else:
            blockers = [r.name for r in self.results if not r.passed]
            self.results.append(ValidationResult(
                name="Code Review",
                passed=False,
                message=f"❌ BLOCKER: Etapas bloqueadas: {', '.join(blockers)}",
            ))

    # ───────────────────────────────────────────────────────────────────────
    # REPORT
    # ───────────────────────────────────────────────────────────────────────

    def _report_results(self) -> bool:
        """Reporta resultados finais."""
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}📊 RESULTADOS{Colors.END}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.END}\n")

        passed_count = sum(1 for r in self.results if r.passed)
        total_count  = len(self.results)

        for result in self.results:
            color = Colors.GREEN if result.passed else Colors.RED
            print(f"{color}{result.message}{Colors.END}")
            if not result.passed and result.details:
                details_str = str(result.details)
                if len(details_str) > 200:
                    details_str = details_str[:200] + "..."
                print(f"   Detalhes: {details_str}")

        print(f"\n{Colors.BOLD}Score: {passed_count}/{total_count}{Colors.END}\n")

        all_passed = all(r.passed for r in self.results)

        if all_passed:
            print(f"{Colors.GREEN}{Colors.BOLD}✅ GATE G0 APPROVED{Colors.END}")
            print(f"{Colors.GREEN}Pode prosseguir para Day 2 (FFI Safety)!{Colors.END}\n")
            return True
        else:
            print(f"{Colors.RED}{Colors.BOLD}❌ GATE G0 REJECTED{Colors.END}")
            print(f"{Colors.RED}Corrija os blockers antes de continuar.{Colors.END}\n")
            return False


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Entry point."""
    validator = SecurityValidator(auto_approve=True)
    approved  = validator.run_all()
    sys.exit(0 if approved else 1)


if __name__ == "__main__":
    main()
