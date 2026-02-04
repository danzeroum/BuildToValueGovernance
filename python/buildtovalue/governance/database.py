
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
import logging

logger = logging.getLogger(__name__)

class SecureDatabase:
    """
    Database wrapper com proteção contra SQL injection.
    
    Princípios:
    1. NUNCA concatenar strings em queries
    2. Sempre usar parametrized queries
    3. Validar inputs antes de usar
    4. Limitar privilégios do DB user
    """
    
    def __init__(self, connection_string: str):
        # Connection string validation
        if not connection_string.startswith(('postgresql://', 'postgres://')):
            raise ValueError("Invalid database connection string")
        
        # Create engine (no privilege escalation)
        self.engine = create_engine(
            connection_string,
            poolclass=NullPool,  # No connection pooling (security)
            echo=False,  # No SQL logging (prevent credential leaks)
            isolation_level="READ COMMITTED",
        )
        
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def execute_query(self, query: str, params: dict = None) -> list:
        """
        Executa query parametrizada (SQL injection safe).
        
        CORRETO:
        >>> db.execute_query("SELECT * FROM users WHERE id = :id", {"id": user_id})
        
        INCORRETO (VULNERÁVEL):
        >>> db.execute_query(f"SELECT * FROM users WHERE id = {user_id}")
        """
        if params is None:
            params = {}
        
        # Valida que query não contém string interpolation
        if any(marker in query for marker in ['%s', '%d', '{', '}']):
            raise ValueError(
                "Query contains string interpolation markers. "
                "Use parameterized queries with :param syntax."
            )
        
        with self.SessionLocal() as session:
            try:
                result = session.execute(text(query), params)
                return result.fetchall()
            except Exception as e:
                logger.error(f"Query execution failed: {e}")
                session.rollback()
                raise
    
    def insert_appeal(self, session_id: str, verdict_id: str, reason: str) -> int:
        """
        Insere apelação (exemplo de query parametrizada).
        """
        query = """
            INSERT INTO appeals (session_id, verdict_id, reason, timestamp)
            VALUES (:session_id, :verdict_id, :reason, NOW())
            RETURNING id
        """
        
        params = {
            "session_id": session_id,
            "verdict_id": verdict_id,
            "reason": reason,  # Não sanitizado aqui (DB faz escape)
        }
        
        result = self.execute_query(query, params)
        return result[0][0]
    
    def get_trust_score(self, session_id: str) -> float:
        """
        Busca trust score (safe query).
        """
        query = """
            SELECT trust_score
            FROM user_sessions
            WHERE session_id = :session_id
        """
        
        result = self.execute_query(query, {"session_id": session_id})
        
        if result:
            return float(result[0][0])
        return 0.0

# ═══════════════════════════════════════════════════════════════
# EXEMPLOS DE USO
# ═══════════════════════════════════════════════════════════════

# ✅ CORRETO (parametrizado)
def get_user_safe(db: SecureDatabase, user_id: int):
    query = "SELECT * FROM users WHERE id = :id"
    return db.execute_query(query, {"id": user_id})

# ❌ INCORRETO (SQL injection vulnerável)
def get_user_unsafe(db: SecureDatabase, user_id: int):
    # NUNCA FAÇA ISSO!
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute_query(query)
    # Se user_id = "1 OR 1=1", retorna TODOS os usuários!

# ✅ CORRETO (múltiplos parâmetros)
def search_users_safe(db: SecureDatabase, name: str, email: str):
    query = """
        SELECT * FROM users
        WHERE name LIKE :name AND email = :email
    """
    return db.execute_query(query, {
        "name": f"%{name}%",
        "email": email,
    })

# ❌ INCORRETO (SQL injection via LIKE)
def search_users_unsafe(db: SecureDatabase, name: str):
    # NUNCA FAÇA ISSO!
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    return db.execute_query(query)
    # Se name = "'; DROP TABLE users; --", destrói tabela!