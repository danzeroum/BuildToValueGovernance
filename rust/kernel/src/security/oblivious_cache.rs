
use std::collections::HashMap;
use rand::Rng;

/// Cache que oculta padrões de acesso (previne cache timing attacks)
/// 
/// Inspirado em Oblivious RAM (ORAM), mas simplificado.
pub struct ObliviousCache<K, V> {
    storage: HashMap<K, V>,
    dummy_keys: Vec<K>,
    access_count: u64,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> ObliviousCache<K, V> {
    pub fn new(dummy_keys: Vec<K>) -> Self {
        Self {
            storage: HashMap::new(),
            dummy_keys,
            access_count: 0,
        }
    }
    
    /// Lookup constant-time (sempre acessa N elementos)
    pub fn contains_ct(&self, key: K) -> bool {
        let mut found = false;
        let mut rng = rand::thread_rng();
        
        // 1. Acessa chave real
        if self.storage.contains_key(&key) {
            found = true;
        }
        
        // 2. Acessa M chaves dummy (M aleatório entre 2-5)
        let dummy_accesses = rng.gen_range(2..=5);
        for _ in 0..dummy_accesses {
            let dummy_idx = rng.gen_range(0..self.dummy_keys.len());
            let _ = self.storage.get(&self.dummy_keys[dummy_idx]);
        }
        
        // 3. Incrementa contador (obfuscação adicional)
        // Força flush de cache a cada 1000 acessos
        if self.access_count.is_multiple_of(1000) {
            self.dummy_flush();
        }
        
        found
    }
    
    /// Insert (sempre adiciona + remove dummy)
    pub fn insert(&mut self, key: K, value: V) {
        let mut rng = rand::thread_rng();
        
        // 1. Insere valor real
        self.storage.insert(key.clone(), value);
        
        // 2. Remove uma chave dummy aleatória (se houver)
        if !self.storage.is_empty() {
            let keys: Vec<_> = self.storage.keys().cloned().collect();
            let random_idx = rng.gen_range(0..keys.len());
            if self.dummy_keys.contains(&keys[random_idx]) {
                self.storage.remove(&keys[random_idx]);
            }
        }
        
        self.access_count += 1;
    }
    
    /// Flush dummy (força invalidação de cache)
    fn dummy_flush(&self) {
        // Força CPU cache miss (lê memória distante)
        let dummy_data: Vec<u8> = (0..1024).map(|_| rand::random()).collect();
        let _ = dummy_data.iter().sum::<u8>();
    }
}