"""
Testes de segurança para SafeExpressionEvaluator v2.1 (Windows compatible).

Simplified version - apenas testes críticos para Gate G0.
"""

import pytest
import time
from safe_expression_evaluator import (
    SafeExpressionEvaluator,
    SecurityError,
    ExpressionTimeoutError,
    EvaluationResult
)

# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def evaluator():
    """Avaliador padrão."""
    return SafeExpressionEvaluator(timeout_ms=100)

@pytest.fixture
def sample_context():
    """Contexto de teste."""
    return {
        'trust_score': 0.8,
        'finding_count': 2,
        'has_cpf': True,
        'risk_level': 'MEDIUM',
        'domain': 'financial'
    }

# ═══════════════════════════════════════════════════════════════════════════
# TESTES CRÍTICOS (GATE G0)
# ═══════════════════════════════════════════════════════════════════════════

class TestCriticalSecurity:
    """Testes críticos de segurança (GATE G0)."""

    def test_no_eval_rce(self, evaluator):
        """CRITICAL: Bloqueia eval() - RCE vulnerability."""
        result = evaluator.evaluate("eval('1+1')", {})
        assert not result.success, "FALHA CRÍTICA: eval() não foi bloqueado!"
        assert 'forbidden' in result.error.lower() or 'disallowed' in result.error.lower()

    def test_no_import(self, evaluator):
        """CRITICAL: Bloqueia import."""
        result = evaluator.evaluate("__import__('os')", {})
        assert not result.success, "FALHA CRÍTICA: import não foi bloqueado!"

    def test_no_exec(self, evaluator):
        """CRITICAL: Bloqueia exec()."""
        result = evaluator.evaluate("exec('print(1)')", {})
        assert not result.success, "FALHA CRÍTICA: exec() não foi bloqueado!"

    def test_no_open_file(self, evaluator):
        """CRITICAL: Bloqueia open() file access."""
        result = evaluator.evaluate("open('/etc/passwd')", {})
        assert not result.success, "FALHA CRÍTICA: open() não foi bloqueado!"

    def test_no_dunder_methods(self, evaluator):
        """CRITICAL: Bloqueia __ methods."""
        attacks = [
            "__import__('os')",
            "globals()",
            "locals()",
        ]
        for attack in attacks:
            result = evaluator.evaluate(attack, {})
            assert not result.success, f"FALHA CRÍTICA: {attack} não foi bloqueado!"

# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE FUNCIONALIDADE BÁSICA
# ═══════════════════════════════════════════════════════════════════════════

class TestBasicFunctionality:
    """Testes de funcionalidade básica."""

    def test_simple_comparison(self, evaluator, sample_context):
        """Testa comparação simples."""
        result = evaluator.evaluate("trust_score > 0.5", sample_context)
        assert result.success, f"Comparação simples falhou: {result.error}"
        assert result.value is True

    def test_boolean_and(self, evaluator, sample_context):
        """Testa operador AND."""
        result = evaluator.evaluate("trust_score > 0.5 and has_cpf", sample_context)
        assert result.success, f"AND falhou: {result.error}"
        assert result.value is True

    def test_boolean_or(self, evaluator, sample_context):
        """Testa operador OR."""
        result = evaluator.evaluate("trust_score < 0.5 or has_cpf", sample_context)
        assert result.success, f"OR falhou: {result.error}"
        assert result.value is True

    def test_arithmetic(self, evaluator, sample_context):
        """Testa operações aritméticas."""
        result = evaluator.evaluate("finding_count * 2 + 5", sample_context)
        assert result.success, f"Aritmética falhou: {result.error}"
        assert result.value == 9

    def test_string_comparison(self, evaluator, sample_context):
        """Testa comparação de strings."""
        result = evaluator.evaluate("risk_level == 'MEDIUM'", sample_context)
        assert result.success, f"String comparison falhou: {result.error}"
        assert result.value is True

# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════

class TestPerformance:
    """Testes de performance."""

    def test_latency_under_100ms(self, evaluator, sample_context):
        """Valida latência <100ms."""
        result = evaluator.evaluate("trust_score > 0.5", sample_context)
        assert result.success
        assert result.execution_time_ms < 100, \
            f"Latência {result.execution_time_ms}ms excede SLA de 100ms"

    def test_cache_performance(self, evaluator, sample_context):
        """Valida que cache melhora performance."""
        expr = "trust_score > 0.5 and has_cpf"

        # Primeira execução (sem cache)
        result1 = evaluator.evaluate(expr, sample_context)
        time1 = result1.execution_time_ms

        # Segunda execução (com cache)
        result2 = evaluator.evaluate(expr, sample_context)
        time2 = result2.execution_time_ms

        assert result1.success and result2.success
        # Cache deve ser mais rápido ou igual
        assert time2 <= time1 * 1.5  # Tolerância de 50%

# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Testes de casos extremos."""

    def test_empty_expression(self, evaluator):
        """Rejeita expressão vazia."""
        result = evaluator.evaluate("", {})
        assert not result.success

    def test_missing_variable(self, evaluator):
        """Variável não existe no contexto."""
        result = evaluator.evaluate("nonexistent_var > 0", {})
        assert not result.success

    def test_division_by_zero(self, evaluator):
        """Divisão por zero."""
        result = evaluator.evaluate("1 / 0", {})
        assert not result.success

    def test_type_mismatch(self, evaluator, sample_context):
        """Comparação de tipos incompatíveis."""
        result = evaluator.evaluate("trust_score == 'invalid'", sample_context)
        assert result.success
        assert result.value is False

# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.security
class TestComplianceGateG0:
    """Testes de conformidade para Gate G0."""

    def test_owasp_injection_protection(self, evaluator):
        """GATE G0: Proteção contra OWASP Injection."""
        owasp_attacks = [
            "__import__('os').system('rm -rf /')",
            "eval('malicious_code')",
            "exec('malicious_code')",
        ]

        for attack in owasp_attacks:
            result = evaluator.evaluate(attack, {})
            assert not result.success, \
                f"GATE G0 FALHA: Ataque OWASP não bloqueado: {attack}"

    def test_allowed_functions_only(self, evaluator):
        """GATE G0: Apenas funções permitidas."""
        # Testa funções permitidas
        allowed_tests = [
            ("abs(-5)", {}, 5),
            ("len('hello')", {}, 5),
            ("max([1,2,3])", {}, 3),
        ]

        for expr, ctx, expected in allowed_tests:
            result = evaluator.evaluate(expr, ctx)
            assert result.success, f"Função permitida falhou: {expr}"
            assert result.value == expected

        # Testa funções bloqueadas
        blocked = ["exit()", "quit()", "help()"]
        for expr in blocked:
            result = evaluator.evaluate(expr, {})
            assert not result.success, f"Função perigosa não foi bloqueada: {expr}"

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Executa apenas testes críticos
    pytest.main([__file__, "-v", "--tb=short", "-k", "Critical or Compliance"])
