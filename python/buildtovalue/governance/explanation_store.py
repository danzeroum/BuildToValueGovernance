
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import json
import sqlite3
from pathlib import Path
import threading

from .ffi_client import TechnicalEvidence
from .ethical_context_engine import EthicalVerdict, RequestMetadata

@dataclass
class FullExplanation:
    """Explicação completa (não truncada) de uma decisão"""
    audit_trail_id: int
    timestamp: int
    
    # Input original (hash, não o texto real por privacidade)
    input_hash: int
    input_size: int
    
    # Evidências técnicas
    evidence_summary: Dict[str, Any]
    findings_detail: list[Dict[str, Any]]
    
    # Decisão ética
    verdict: Dict[str, Any]
    
    # Contexto
    context: Dict[str, Any]
    
    # Rationale completo (pode ser longo)
    full_rationale: str
    
    # Fatores de decisão (para debugging)
    decision_factors: Dict[str, Any]

class ExplanationStore:
    """
    Armazena explicações completas de todas as decisões.
    
    Propósitos:
    1. Contestabilidade: Usuário pode ver explicação completa
    2. Auditoria: Investigadores podem analisar decisões
    3. Debugging: Desenvolvedores podem entender falsos positivos
    4. Compliance: LGPD Art. 20 (direito à explicação)
    
    Storage:
    - SQLite para busca rápida
    - JSON para dados estruturados
    - Retenção: 90 dias (configurável)
    """
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Retorna conexão thread-local"""
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def _init_db(self):
        """Inicializa schema do banco"""
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS explanations (
                audit_trail_id INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                input_hash INTEGER NOT NULL,
                action TEXT NOT NULL,
                composite_risk INTEGER,
                confidence REAL,
                mercy_applied BOOLEAN,
                full_data TEXT NOT NULL,  -- JSON completo
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        """)
        
        # Índices para busca
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON explanations(timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_action 
            ON explanations(action)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_input_hash 
            ON explanations(input_hash)
        """)
        
        conn.commit()
    
    def store(
        self,
        audit_trail_id: int,
        verdict: EthicalVerdict,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
    ):
        """Armazena explicação completa"""
        
        # Cria estrutura completa
        explanation = FullExplanation(
            audit_trail_id=audit_trail_id,
            timestamp=int(time.time()),
            input_hash=evidence.original_request_hash,
            input_size=evidence.input_size,
            evidence_summary={
                'protocol_version': evidence.protocol_version,
                'composite_risk': evidence.composite_risk,
                'finding_count': evidence.finding_count,
                'critical_count': evidence.critical_count,
                'processing_time_us': evidence.processing_time_us,
                'entropy': evidence.stats.entropy,
                'z_score': evidence.stats.z_score,
            },
            findings_detail=[
                {
                    'module': f.module,
                    'severity': f.severity,
                    'rule_id': f.rule_id,
                    'title': f.title,
                    'description': f.description,
                    'confidence': f.confidence,
                    'position': f'{f.position_start}-{f.position_end}',
                }
                for f in (evidence.findings + evidence.critical)
            ],
            verdict={
                'action': verdict.action.name,
                'confidence': verdict.confidence,
                'rule_id': verdict.rule_id,
                'signature': verdict.signature.hex(),
                'trust_score': verdict.trust_score,
                'mercy_score': verdict.mercy_score,
            },
            context={
                'agent_id': context.agent_id,
                'session_id': context.session_id,
                'user_role': context.user_role,
                'domain': context.domain,
                'ip_address': context.ip_address,
            },
            full_rationale=verdict.rationale,
            decision_factors=verdict.context_factors,
        )
        
        # Serializa para JSON
        full_data_json = json.dumps(asdict(explanation), indent=2)
        
        # Insere no banco
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO explanations 
            (audit_trail_id, timestamp, input_hash, action, composite_risk, 
             confidence, mercy_applied, full_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_trail_id,
            explanation.timestamp,
            evidence.original_request_hash,
            verdict.action.name,
            evidence.composite_risk,
            verdict.confidence,
            verdict.mercy_score > 0.5,
            full_data_json,
        ))
        
        conn.commit()
    
    def get(self, audit_trail_id: int) -> Optional[FullExplanation]:
        """Recupera explicação por ID"""
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT full_data FROM explanations 
            WHERE audit_trail_id = ?
        """, (audit_trail_id,))
        
        row = cursor.fetchone()
        
        if not row:
            return None
        
        # Deserializa JSON
        data = json.loads(row['full_data'])
        return FullExplanation(**data)
    
    def search(
        self,
        action: Optional[str] = None,
        min_risk: Optional[int] = None,
        mercy_applied: Optional[bool] = None,
        start_timestamp: Optional[int] = None,
        end_timestamp: Optional[int] = None,
        limit: int = 100,
    ) -> list[FullExplanation]:
        """Busca explicações com filtros"""
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = "SELECT full_data FROM explanations WHERE 1=1"
        params = []
        
        if action:
            query += " AND action = ?"
            params.append(action)
        
        if min_risk is not None:
            query += " AND composite_risk >= ?"
            params.append(min_risk)
        
        if mercy_applied is not None:
            query += " AND mercy_applied = ?"
            params.append(mercy_applied)
        
        if start_timestamp:
            query += " AND timestamp >= ?"
            params.append(start_timestamp)
        
        if end_timestamp:
            query += " AND timestamp <= ?"
            params.append(end_timestamp)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        results = []
        for row in cursor.fetchall():
            data = json.loads(row['full_data'])
            results.append(FullExplanation(**data))
        
        return results
    
    def cleanup_old_entries(self, retention_days: int = 90):
        """Remove explicações antigas (compliance com retenção)"""
        
        import time
        cutoff_timestamp = int(time.time()) - (retention_days * 86400)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM explanations 
            WHERE timestamp < ?
        """, (cutoff_timestamp,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        
        import logging
        logging.info(f"Cleaned up {deleted_count} old explanations (>{retention_days} days)")
        
        return deleted_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do store"""
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Total de explicações
        cursor.execute("SELECT COUNT(*) as total FROM explanations")
        total = cursor.fetchone()['total']
        
        # Por ação
        cursor.execute("""
            SELECT action, COUNT(*) as count 
            FROM explanations 
            GROUP BY action
        """)
        by_action = {row['action']: row['count'] for row in cursor.fetchall()}
        
        # Com misericórdia
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM explanations 
            WHERE mercy_applied = 1
        """)
        mercy_count = cursor.fetchone()['count']
        
        # Tamanho do banco
        db_size_mb = self.db_path.stat().st_size / (1024 * 1024)
        
        return {
            'total_explanations': total,
            'by_action': by_action,
            'mercy_applied_count': mercy_count,
            'mercy_rate': mercy_count / total if total > 0 else 0.0,
            'db_size_mb': round(db_size_mb, 2),
        }