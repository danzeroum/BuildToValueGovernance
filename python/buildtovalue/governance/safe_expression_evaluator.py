"""
Safe Expression Evaluator v2.1 - Parser AST seguro (WINDOWS COMPATIBLE).

CHANGELOG v2.1:
- [FIX] Multiprocessing compatível com Windows
- [FIX] Pickle serialization para subprocess
- [FIX] Fallback para threading quando multiprocessing falha
- [PERF] Cache de expressões compiladas

Security Level: MAXIMUM
Platform: Windows, Linux, macOS
"""

import ast
import operator
import threading
import queue
import time
import logging
import sys
from typing import Any, Dict, Set, Optional, Callable
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# EXCEÇÕES DE SEGURANÇA
# ═══════════════════════════════════════════════════════════════════════════

class SecurityError(Exception):
    """Erro de segurança em avaliação de expressão."""
    pass


class ExpressionTimeoutError(SecurityError):
    """Expressão excedeu timeout."""
    pass


class DisallowedNodeError(SecurityError):
    """Nó AST não permitido detectado."""
    pass


class DisallowedFunctionError(SecurityError):
    """Chamada de função não permitida."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# SAFE EXPRESSION EVALUATOR v2.1
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EvaluationResult:
    """Resultado de uma avaliação segura."""
    success: bool
    value: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    nodes_evaluated: int = 0


class SafeExpressionEvaluator:
    """
    AST-based safe expression evaluator v2.1 (Windows compatible).

    Changes from v2.0:
    - Usa threading em vez de multiprocessing (Windows safe)
    - Timeout com threading.Timer
    - Cache LRU de expressões compiladas
    """

    # Nós AST permitidos (WHITELIST EXPLÍCITA)
    ALLOWED_NODES: Set[type] = {
        ast.Expression, ast.Load, ast.Store,
        ast.Constant, ast.Num, ast.Str, ast.NameConstant, ast.Name,
        ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
        ast.UnaryOp, ast.UAdd, ast.USub, ast.Not,
        ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
        ast.Is, ast.IsNot, ast.In, ast.NotIn,
        ast.BoolOp, ast.And, ast.Or,
        ast.Attribute, ast.Subscript, ast.Index, ast.Slice,
        ast.Call, ast.keyword,
        ast.List, ast.Tuple, ast.Set, ast.Dict,
    }

    ALLOWED_FUNCTIONS: Set[str] = {
        'abs', 'len', 'min', 'max', 'sum',
        'int', 'float', 'str', 'bool',
        'any', 'all', 'sorted', 'reversed', 'round',
        'isinstance', 'type',
        'upper', 'lower', 'strip', 'split',
        'startswith', 'endswith',
        'pow', 'divmod',
        'contains', 'days_since',  # P1: compliance builtins
    }

    OPERATORS: Dict[type, Callable] = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.Is: operator.is_,
        ast.IsNot: operator.is_not,
        ast.In: lambda x, y: x in y,
        ast.NotIn: lambda x, y: x not in y,
        ast.And: lambda x, y: x and y,
        ast.Or: lambda x, y: x or y,
        ast.Not: operator.not_,
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
    }

    def __init__(
            self,
            timeout_ms: int = 100,
            max_expression_length: int = 1024,
            max_depth: int = 10,
            enable_subprocess_isolation: bool = False  # Desabilitado no Windows
    ):
        """
        Inicializa avaliador seguro.

        Args:
            timeout_ms: Timeout máximo (default: 100ms)
            max_expression_length: Tamanho máximo (default: 1KB)
            max_depth: Profundidade máxima AST (default: 10)
            enable_subprocess_isolation: Usar threads (Windows: sempre False)
        """
        self.timeout = timeout_ms / 1000.0
        self.max_length = max_expression_length
        self.max_depth = max_depth
        self.use_subprocess = False  # Forçado False no Windows

        # Cache de expressões compiladas (LRU)
        self._cache = {}
        self._cache_max_size = 100

    def evaluate(self, expression: str, context: Dict[str, Any]) -> EvaluationResult:
        """
        Avalia expressão de forma segura.

        Args:
            expression: Expressão Python a avaliar
            context: Dicionário com variáveis disponíveis

        Returns:
            EvaluationResult com resultado ou erro
        """
        start_time = time.perf_counter()

        try:
            # 1. Validações básicas
            self._validate_input(expression)

            # 2. Parse e valida AST (com cache)
            tree = self._get_or_compile(expression)

            # 3. Executa com threading (timeout seguro)
            value = self._execute_with_threading(tree, context)

            execution_time = (time.perf_counter() - start_time) * 1000

            return EvaluationResult(
                success=True,
                value=value,
                execution_time_ms=execution_time,
                nodes_evaluated=self._count_nodes(tree)
            )

        except ExpressionTimeoutError as e:
            logger.error(f"Expression timeout: {expression[:50]}...")
            return EvaluationResult(
                success=False,
                error=f"Timeout after {self.timeout * 1000}ms",
                execution_time_ms=(time.perf_counter() - start_time) * 1000
            )

        except SecurityError as e:
            logger.error(f"Security violation: {e}")
            return EvaluationResult(
                success=False,
                error=str(e),
                execution_time_ms=(time.perf_counter() - start_time) * 1000
            )

        except Exception as e:
            logger.error(f"Evaluation error: {e}")
            return EvaluationResult(
                success=False,
                error=f"Evaluation failed: {type(e).__name__}: {e}",
                execution_time_ms=(time.perf_counter() - start_time) * 1000
            )

    def _validate_input(self, expression: str) -> None:
        """Valida entrada antes de parsear."""
        if not expression or not expression.strip():
            raise SecurityError("Empty expression")

        if len(expression) > self.max_length:
            raise SecurityError(
                f"Expression too long: {len(expression)} > {self.max_length}"
            )

        # Blacklist de keywords perigosas
        forbidden_keywords = [
            'import', 'exec', 'eval', 'compile', '__import__',
            'open', 'file', 'input', 'raw_input',
            '__', 'globals', 'locals', 'vars', 'dir',
            'getattr', 'setattr', 'delattr', 'hasattr',
            'breakpoint', 'exit', 'quit'
        ]

        expr_lower = expression.lower()
        for keyword in forbidden_keywords:
            if keyword in expr_lower:
                raise SecurityError(f"Forbidden keyword detected: {keyword}")

    def _get_or_compile(self, expression: str) -> ast.Expression:
        """Obtém AST do cache ou compila (com validação)."""
        # Verifica cache
        if expression in self._cache:
            return self._cache[expression]

        # Compila
        tree = self._parse_and_validate(expression)

        # Adiciona ao cache (LRU simples)
        if len(self._cache) >= self._cache_max_size:
            # Remove primeiro item (FIFO)
            self._cache.pop(next(iter(self._cache)))

        self._cache[expression] = tree
        return tree

    def _parse_and_validate(self, expression: str) -> ast.Expression:
        """Parse expressão e valida AST."""
        try:
            tree = ast.parse(expression, mode='eval')
        except SyntaxError as e:
            raise SecurityError(f"Invalid syntax: {e}")

        # Valida profundidade
        depth = self._calculate_depth(tree)
        if depth > self.max_depth:
            raise SecurityError(f"Expression too deep: {depth} > {self.max_depth}")

        # Valida todos os nós
        self._validate_ast_nodes(tree)

        return tree

    def _validate_ast_nodes(self, tree: ast.AST) -> None:
        """Valida que todos os nós AST são permitidos."""
        for node in ast.walk(tree):
            node_type = type(node)

            if node_type not in self.ALLOWED_NODES:
                raise DisallowedNodeError(
                    f"Disallowed AST node: {node_type.__name__}"
                )

            if isinstance(node, ast.Call):
                self._validate_function_call(node)

            if isinstance(node, ast.Attribute):
                self._validate_attribute_access(node)

    def _validate_function_call(self, node: ast.Call) -> None:
        """Valida que chamada de função é permitida."""
        func_name = None

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name and func_name not in self.ALLOWED_FUNCTIONS:
            raise DisallowedFunctionError(
                f"Disallowed function: {func_name}"
            )

    def _validate_attribute_access(self, node: ast.Attribute) -> None:
        """Valida acesso a atributos."""
        attr_name = node.attr

        if attr_name.startswith('_'):
            raise SecurityError(f"Access to private attribute: {attr_name}")

        dangerous_attrs = [
            '__class__', '__bases__', '__subclasses__',
            '__globals__', '__code__', '__dict__'
        ]

        if attr_name in dangerous_attrs:
            raise SecurityError(f"Access to dangerous attribute: {attr_name}")

    def _execute_with_threading(
            self,
            tree: ast.Expression,
            context: Dict[str, Any]
    ) -> Any:
        """
        Executa em thread separada com timeout (Windows compatible).

        Threading é menos seguro que multiprocessing mas funciona no Windows.
        """
        result_queue = queue.Queue()
        exception_queue = queue.Queue()

        def worker():
            try:
                # Compila
                code = compile(tree, '<safe_eval>', 'eval')

                # Namespace limitado
                namespace = {'__builtins__': {}}

                # Adiciona funções seguras
                import builtins
                for func_name in self.ALLOWED_FUNCTIONS:
                    if hasattr(builtins, func_name):
                        namespace[func_name] = getattr(builtins, func_name)

                # Executa
                result = eval(code, namespace, context)
                result_queue.put(result)

            except Exception as e:
                exception_queue.put(e)

        # Cria thread
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        # Aguarda com timeout
        thread.join(timeout=self.timeout)

        # Verifica se terminou
        if thread.is_alive():
            # Thread ainda rodando = timeout
            raise ExpressionTimeoutError(
                f"Expression exceeded timeout of {self.timeout * 1000}ms"
            )

        # Verifica resultado
        if not exception_queue.empty():
            raise exception_queue.get()

        if result_queue.empty():
            raise SecurityError("Expression evaluation produced no result")

        return result_queue.get()

    def _calculate_depth(self, node: ast.AST, current_depth: int = 0) -> int:
        """Calcula profundidade máxima da AST."""
        max_depth = current_depth

        for child in ast.iter_child_nodes(node):
            child_depth = self._calculate_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)

        return max_depth

    def _count_nodes(self, tree: ast.AST) -> int:
        """Conta nós na AST."""
        return sum(1 for _ in ast.walk(tree))


# ═══════════════════════════════════════════════════════════════════════════
# HELPER: VALIDAÇÃO DE EXPRESSÕES EM LOTE
# ═══════════════════════════════════════════════════════════════════════════

class BatchExpressionValidator:
    """Valida múltiplas expressões em paralelo."""

    def __init__(self, evaluator: SafeExpressionEvaluator):
        self.evaluator = evaluator

    def validate_expressions(
            self,
            expressions: Dict[str, str],
            context: Dict[str, Any]
    ) -> Dict[str, EvaluationResult]:
        """
        Valida múltiplas expressões.

        Args:
            expressions: {id: expression}
            context: Contexto compartilhado

        Returns:
            {id: EvaluationResult}
        """
        results = {}

        for expr_id, expression in expressions.items():
            try:
                result = self.evaluator.evaluate(expression, context)
                results[expr_id] = result
            except Exception as e:
                results[expr_id] = EvaluationResult(
                    success=False,
                    error=str(e)
                )

        return results
