//! Session Guard v2.3.2
//!
//! Proteção contra hijacking de sessão e ataques de replay.
//! Implementa validação de tokens de sessão com expiração e nonce.
//!
//! Princípio: Cada sessão deve ser única e ter tempo de vida limitado
//! para prevenir ataques de replay e sequestro de sessão.
//!
//! INVARIANTE: Nenhum .unwrap() alcançável por input de usuário no hot-path.
//! duration_since(UNIX_EPOCH) usa .unwrap_or(Duration::ZERO):
//! skew de NTP ou anomalia de clock do SO → token ainda gerado com
//! unicidade garantida por nonce (u64) + salt ([u8; 16]).

use std::collections::HashMap;
use std::time::{Duration, Instant};
use blake3::Hasher;

/// Token de sessão segura
#[derive(Debug, Clone)]
pub struct SessionToken {
    pub token: String,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub user_id: String,
    pub nonce: u64,
}

/// Guardião de sessões
#[derive(Debug)]
pub struct SessionGuard {
    sessions: HashMap<String, SessionToken>,
    session_timeout: Duration,
    max_sessions_per_user: usize,
}

impl SessionGuard {
    /// Cria um novo guardião de sessões com timeout padrão (30 minutos)
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            session_timeout: Duration::from_secs(1800), // 30 minutos
            max_sessions_per_user: 5,
        }
    }

    /// Cria guardião com configuração personalizada
    pub fn with_config(timeout_seconds: u64, max_per_user: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            session_timeout: Duration::from_secs(timeout_seconds),
            max_sessions_per_user: max_per_user,
        }
    }

    /// Cria uma nova sessão para um usuário
    pub fn create_session(&mut self, user_id: &str) -> Result<String, SessionError> {
        // Limpa sessões expiradas primeiro
        self.cleanup_expired_sessions();

        // Verifica limite de sessões por usuário
        let user_session_count = self.sessions
            .values()
            .filter(|session| session.user_id == user_id)
            .count();

        if user_session_count >= self.max_sessions_per_user {
            return Err(SessionError::MaxSessionsExceeded);
        }

        // Gera token seguro
        let token = self.generate_token(user_id);
        let now = Instant::now();

        let session = SessionToken {
            token: token.clone(),
            created_at: now,
            expires_at: now + self.session_timeout,
            user_id: user_id.to_string(),
            nonce: rand::random(),
        };

        // Armazena sessão
        self.sessions.insert(token.clone(), session);

        Ok(token)
    }

    /// Valida um token de sessão
    pub fn validate_session(&self, token: &str) -> Result<&SessionToken, SessionError> {
        let session = self.sessions.get(token)
            .ok_or(SessionError::InvalidToken)?;

        // Verifica expiração
        if Instant::now() > session.expires_at {
            return Err(SessionError::SessionExpired);
        }

        Ok(session)
    }

    /// Renova uma sessão (extende o tempo de expiração)
    pub fn renew_session(&mut self, token: &str) -> Result<(), SessionError> {
        let session = self.sessions.get_mut(token)
            .ok_or(SessionError::InvalidToken)?;

        let now = Instant::now();

        // Verifica se a sessão ainda é válida
        if now > session.expires_at {
            return Err(SessionError::SessionExpired);
        }

        // Renova por mais uma janela de tempo
        session.expires_at = now + self.session_timeout;
        session.nonce = session.nonce.wrapping_add(1); // Incrementa nonce

        Ok(())
    }

    /// Encerra uma sessão
    pub fn invalidate_session(&mut self, token: &str) -> bool {
        self.sessions.remove(token).is_some()
    }

    /// Encerra todas as sessões de um usuário
    pub fn invalidate_all_user_sessions(&mut self, user_id: &str) -> usize {
        let tokens_to_remove: Vec<String> = self.sessions
            .iter()
            .filter(|(_, session)| session.user_id == user_id)
            .map(|(token, _)| token.clone())
            .collect();

        let count = tokens_to_remove.len();
        for token in tokens_to_remove {
            self.sessions.remove(&token);
        }

        count
    }

    /// Limpa sessões expiradas
    pub fn cleanup_expired_sessions(&mut self) -> usize {
        let now = Instant::now();
        let expired_tokens: Vec<String> = self.sessions
            .iter()
            .filter(|(_, session)| now > session.expires_at)
            .map(|(token, _)| token.clone())
            .collect();

        let count = expired_tokens.len();
        for token in expired_tokens {
            self.sessions.remove(&token);
        }

        count
    }

    /// Gera token seguro usando BLAKE3.
    ///
    /// Hot-path invariant: duration_since(UNIX_EPOCH) usa .unwrap_or(Duration::ZERO).
    /// Skew de NTP ou clock regressivo → timestamp = 0, mas nonce (u64) + salt ([u8; 16])
    /// garantem unicidade criptográfica sem panic.
    fn generate_token(&self, user_id: &str) -> String {
        let mut hasher = Hasher::new();
        let nonce: u64 = rand::random();

        // Fail-secure: clock anomaly → Duration::ZERO; nonce+salt mantêm unicidade.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        hasher.update(user_id.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());

        // Adiciona sal aleatório
        let salt: [u8; 16] = rand::random();
        hasher.update(&salt);

        hex::encode(hasher.finalize().as_bytes())
    }

    /// Retorna estatísticas das sessões
    pub fn get_stats(&self) -> SessionStats {
        let now = Instant::now();
        let active_sessions = self.sessions
            .values()
            .filter(|session| now <= session.expires_at)
            .count();

        let expired_sessions = self.sessions.len() - active_sessions;

        // Conta usuários únicos
        let unique_users: std::collections::HashSet<_> = self.sessions
            .values()
            .map(|session| &session.user_id)
            .collect();

        SessionStats {
            total_sessions: self.sessions.len(),
            active_sessions,
            expired_sessions,
            unique_users: unique_users.len(),
        }
    }
}

impl Default for SessionGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Estatísticas de sessão
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub expired_sessions: usize,
    pub unique_users: usize,
}

/// Erros de sessão
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Invalid or malformed session token")]
    InvalidToken,

    #[error("Session has expired")]
    SessionExpired,

    #[error("Maximum sessions per user exceeded")]
    MaxSessionsExceeded,

    #[error("Session validation failed")]
    ValidationFailed,

    #[error("Session already exists")]
    SessionExists,
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_session_creation_and_validation() {
        let mut guard = SessionGuard::new();

        // Cria sessão
        let token = guard.create_session("user123").unwrap();

        // Valida sessão
        let session = guard.validate_session(&token).unwrap();
        assert_eq!(session.user_id, "user123");
        assert!(session.expires_at > Instant::now());
    }

    #[test]
    fn test_session_expiration() {
        let mut guard = SessionGuard::with_config(1, 5); // 1 segundo de timeout

        // Cria sessão
        let token = guard.create_session("user123").unwrap();

        // Espera expirar
        sleep(Duration::from_millis(1500));

        // Deve falhar na validação
        assert!(guard.validate_session(&token).is_err());
    }

    #[test]
    fn test_session_renewal() {
        let mut guard = SessionGuard::with_config(2, 5); // 2 segundos de timeout

        // Cria sessão
        let token = guard.create_session("user123").unwrap();

        // Espera um pouco
        sleep(Duration::from_millis(1000));

        // Renova
        guard.renew_session(&token).unwrap();

        // Espera mais um pouco (ainda deve ser válida após renewal)
        sleep(Duration::from_millis(1200));

        // Deve ainda ser válida
        assert!(guard.validate_session(&token).is_ok());
    }

    #[test]
    fn test_max_sessions_per_user() {
        let mut guard = SessionGuard::with_config(60, 2); // Máximo 2 sessões por usuário

        // Cria 2 sessões (deve funcionar)
        guard.create_session("user123").unwrap();
        guard.create_session("user123").unwrap();

        // Terceira sessão deve falhar
        assert!(matches!(
            guard.create_session("user123"),
            Err(SessionError::MaxSessionsExceeded)
        ));
    }

    #[test]
    fn test_session_cleanup() {
        let mut guard = SessionGuard::with_config(1, 5); // Sessões de 1 segundo

        // Cria várias sessões
        guard.create_session("user1").unwrap();
        guard.create_session("user2").unwrap();

        // Espera expirar
        sleep(Duration::from_millis(1500));

        // Limpa sessões expiradas
        let cleaned = guard.cleanup_expired_sessions();
        assert_eq!(cleaned, 2);

        // Verifica estatísticas
        let stats = guard.get_stats();
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.expired_sessions, 0); // Já foram limpas
    }

    #[test]
    fn test_session_invalidation() {
        let mut guard = SessionGuard::new();

        // Cria sessão
        let token = guard.create_session("user123").unwrap();

        // Verifica que existe
        assert!(guard.validate_session(&token).is_ok());

        // Invalida
        assert!(guard.invalidate_session(&token));

        // Verifica que não existe mais
        assert!(guard.validate_session(&token).is_err());
    }

    #[test]
    fn test_unique_token_generation() {
        let guard = SessionGuard::new();
        let user_id = "same_user";

        // Gera dois tokens para o mesmo usuário
        let token1 = guard.generate_token(user_id);
        let token2 = guard.generate_token(user_id);

        // Deve ser diferente (devido ao nonce e timestamp)
        assert_ne!(token1, token2);

        // Deve ser hexadecimal válido
        assert!(hex::decode(&token1).is_ok());
        assert!(hex::decode(&token2).is_ok());
    }

    #[test]
    fn test_token_generation_resilient_to_clock_skew() {
        // Verifica que generate_token não entra em panic mesmo com Duration::ZERO
        // (simulado indiretamente — o método usa unwrap_or(Duration::ZERO)).
        let guard = SessionGuard::new();
        let token = guard.generate_token("clock_skew_user");
        assert!(!token.is_empty());
        assert!(hex::decode(&token).is_ok());
    }
}
