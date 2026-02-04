
#[derive(Debug)]
pub enum ResponseType {
    /// Genérico: Não revela o que foi detectado
    Generic,
    
    /// Específico: Apenas para logs internos (nunca exposto ao usuário)
    Specific(String),
}

impl ValidationResult {
    /// Converte resultado em mensagem para usuário (uniform)
    pub fn to_user_message(&self) -> String {
        match self {
            ValidationResult::Clean => {
                "Requisição processada com sucesso.".to_string()
            }
            ValidationResult::Violation(_) => {
                // SEMPRE a mesma mensagem (não revela tipo de violação)
                "Sua requisição contém conteúdo que viola nossas políticas. \
                 Para mais detalhes, consulte o ID da requisição.".to_string()
            }
        }
    }
    
    /// Mensagem detalhada (apenas para logs/auditoria)
    pub fn to_audit_message(&self) -> String {
        match self {
            ValidationResult::Clean => "No violations detected.".to_string(),
            ValidationResult::Violation(finding) => {
                format!(
                    "Violation detected: {} (confidence: {}, position: {}-{})",
                    finding.title,
                    finding.confidence,
                    finding.position_start,
                    finding.position_end
                )
            }
        }
    }
}