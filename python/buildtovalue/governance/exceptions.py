# python/buildtovalue/governance/exceptions.py
"""
Exceções customizadas para o módulo de Governança.
"""

class GovernanceError(Exception):
    """Erro base para problemas de governança."""
    pass

class SecurityViolation(GovernanceError):
    """
    Levantada quando uma verificação de segurança falha.
    Ex: Modelo abliterado detectado, padrão de ataque encontrado.
    """
    def __init__(self, message: str, model_id: str = "unknown", severity: str = "critical"):
        self.model_id = model_id
        self.severity = severity
        super().__init__(f"SECURITY VIOLATION [{severity.upper()}]: {message} (Model: {model_id})")

class IntegrityCheckFailed(GovernanceError):
    """
    Levantada quando a integridade de um artefato (modelo, skill) não pode ser verificada
    ou falhou de forma não-crítica (ex: modelo desconhecido sem teste comportamental).
    """
    def __init__(self, message: str, model_id: str):
        self.model_id = model_id
        super().__init__(f"INTEGRITY CHECK FAILED: {message} (Model: {model_id})")