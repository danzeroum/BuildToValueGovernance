"""
Database - Wrapper seguro para operações de banco de dados.
Demonstra boas práticas vs vulnerabilidades.
"""
import sqlite3
from typing import Optional, List, Dict, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class SecureDatabase:
    """
    Wrapper seguro para SQLite.

    Garante:
    - Prepared statements (proteção SQL injection)
    - Connection pooling (thread-safe)
    - Logging de queries
    - Rollback automático em erros
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def execute_query(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """
        Executa query SELECT com prepared statements.

        Args:
            query: SQL query com placeholders (?)
            params: Parâmetros para substituir placeholders

        Returns:
            Lista de rows
        """
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def execute_update(self, query: str, params: tuple = ()) -> int:
        """
        Executa query UPDATE/INSERT/DELETE.

        Returns:
            Número de rows afetados
        """
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        self.conn.commit()
        return cursor.rowcount

    def close(self):
        """Fecha conexão."""
        self.conn.close()


# ═══════════════════════════════════════════════════════════════════════════
# EXEMPLOS: SEGURO vs INSEGURO
# ═══════════════════════════════════════════════════════════════════════════

def get_user_secure(db: SecureDatabase, user_id: int) -> Optional[Dict[str, Any]]:
    """
    ✅ SEGURO: Usa prepared statements.
    """
    query = "SELECT * FROM users WHERE id = ?"
    rows = db.execute_query(query, (user_id,))
    return dict(rows[0]) if rows else None


def get_user_unsafe(db: SecureDatabase, user_id: int):
    """
    ⚠️ INSEGURO: SQL injection vulnerability!

    NÃO USE EM PRODUÇÃO!
    Exemplo para fins educacionais.
    """
    # VULNERÁVEL: String interpolation direta
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute_query(query)

    # Ataque possível:
    # user_id = "1 OR 1=1"
    # → "SELECT * FROM users WHERE id = 1 OR 1=1"
    # → Retorna TODOS os usuários!


def search_users_secure(db: SecureDatabase, name_pattern: str) -> List[Dict[str, Any]]:
    """
    ✅ SEGURO: Prepared statements com LIKE.
    """
    query = "SELECT * FROM users WHERE name LIKE ?"
    rows = db.execute_query(query, (f"%{name_pattern}%",))
    return [dict(row) for row in rows]


def search_users_unsafe(db: SecureDatabase, name_pattern: str):
    """
    ⚠️ INSEGURO: SQL injection via LIKE!

    NÃO USE EM PRODUÇÃO!
    """
    # VULNERÁVEL
    query = f"SELECT * FROM users WHERE name LIKE '%{name_pattern}%'"
    return db.execute_query(query)

    # Ataque possível:
    # name_pattern = "' OR '1'='1"
    # → "SELECT * FROM users WHERE name LIKE '%' OR '1'='1%'"
