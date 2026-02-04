
/// Módulos que podem gerar findings
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorModule {
    Unknown = 0,
    CPF = 1,
    CNPJ = 2,
    Email = 3,
    CreditCard = 4,
    Phone = 5,
    Entropy = 10,
    ZScore = 11,
    Deobfuscator = 20,
    Network = 30,
    SessionGuard = 40,
    Policies = 50,
    Interceptor = 60,
}

/// Severidade técnica (objetiva, sem julgamento ético)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TechnicalSeverity {
    /// Informacional (ex: padrão detectado mas não sensível)
    Info = 0,
    
    /// Baixa (ex: entropia ligeiramente alta)
    Low = 64,
    
    /// Média (ex: padrão de email genérico)
    Medium = 128,
    
    /// Alta (ex: CPF válido detectado)
    PolicyViolation = 192,
    
    /// Crítica (ex: múltiplos CPFs + CNPJ + cartão de crédito)
    Critical = 255,
}

impl TechnicalSeverity {
    /// Retorna score numérico (0-255)
    pub fn to_score(&self) -> u8 {
        *self as u8
    }
    
    /// Verifica se é crítico
    pub fn is_critical(&self) -> bool {
        *self >= TechnicalSeverity::Critical
    }
}

/// Estatísticas do input
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct InputStatistics {
    /// Entropia de Shannon (bits/caractere)
    pub entropy: f32,
    
    /// Z-Score da distribuição de caracteres
    pub z_score: f32,
    
    /// Número de caracteres únicos
    pub unique_chars: u16,
    
    /// Tamanho total
    pub total_chars: u32,
    
    /// Proporção de dígitos (0.0-1.0)
    pub digit_ratio: f32,
    
    /// Proporção de letras (0.0-1.0)
    pub letter_ratio: f32,
    
    /// Proporção de símbolos (0.0-1.0)
    pub symbol_ratio: f32,
    
    /// Reserved
    pub _reserved: [u8; 228],
}

static_assertions::const_assert_eq!(
    std::mem::size_of::<InputStatistics>(),
    256
);

impl Default for InputStatistics {
    fn default() -> Self {
        Self {
            entropy: 0.0,
            z_score: 0.0,
            unique_chars: 0,
            total_chars: 0,
            digit_ratio: 0.0,
            letter_ratio: 0.0,
            symbol_ratio: 0.0,
            _reserved: [0; 228],
        }
    }
}

impl InputStatistics {
    pub fn to_bytes(&self) -> [u8; 256] {
        unsafe {
            std::mem::transmute(*self)
        }
    }
}

/// Declaração de viés (transparência)
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct BiasDeclaration {
    /// Taxa de falso positivo (0.0-1.0)
    pub false_positive_rate: f32,
    
    /// Data da última calibração (timestamp)
    pub calibration_date: u64,
    
    /// Limitações conhecidas (texto livre)
    pub limitations: [u8; 256],
    
    /// Grupos conhecidamente afetados
    pub affected_groups: [u8; 128],
    
    /// Reserved
    pub _reserved: [u8; 112],
}

static_assertions::const_assert_eq!(
    std::mem::size_of::<BiasDeclaration>(),
    512
);

impl Default for BiasDeclaration {
    fn default() -> Self {
        let mut decl = Self {
            false_positive_rate: 0.15,  // 15% (conservador)
            calibration_date: Self::now_timestamp(),
            limitations: [0; 256],
            affected_groups: [0; 128],
            _reserved: [0; 112],
        };
        
        // Preenche limitações padrão
        let default_limitations = 
            "Não suporta CPFs históricos (pré-1965). \
             Pode ter falsos positivos em discussões acadêmicas. \
             Requer calibração trimestral.";
        decl.set_limitations(default_limitations);
        
        decl
    }
}

impl BiasDeclaration {
    pub fn set_limitations(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let len = bytes.len().min(256);
        self.limitations[0..len].copy_from_slice(&bytes[0..len]);
    }
    
    pub fn get_limitations(&self) -> &str {
        std::str::from_utf8(&self.limitations)
            .unwrap_or("INVALID_UTF8")
            .trim_end_matches('\0')
    }
    
    pub fn get_fpr(&self) -> f32 {
        self.false_positive_rate
    }
    
    pub fn to_bytes(&self) -> [u8; 512] {
        unsafe {
            std::mem::transmute(*self)
        }
    }
    
    fn now_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}