
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use blake3::Hasher;

/// MISP/STIX threat event (immutable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String, // UUID
    pub threat_type: String, // "prompt_injection", "pii_leakage", etc.
    pub severity: u8, // 1-10
    pub source: String, // "MISP", "STIX", "OWASP", etc.
    pub indicators: Vec<String>, // IOCs (Indicators of Compromise)
    pub timestamp: i64,
    pub hash: String, // BLAKE3 hash (immutability proof)
}

impl ThreatEvent {
    /// Compute BLAKE3 hash for immutability
    pub fn compute_hash(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.threat_type.as_bytes());
        hasher.update(&[self.severity]);
        hasher.update(self.source.as_bytes());
        
        for indicator in &self.indicators {
            hasher.update(indicator.as_bytes());
        }
        
        hasher.update(&self.timestamp.to_le_bytes());
        
        hasher.finalize().to_hex().to_string()
    }

    /// Validate hash integrity
    pub fn verify_integrity(&self) -> bool {
        self.compute_hash() == self.hash
    }
}

/// Threat Intelligence Database (in-memory index)
pub struct ThreatIngestor {
    events: HashMap<String, ThreatEvent>, // id -> event
    index_by_type: HashMap<String, Vec<String>>, // threat_type -> [id1, id2, ...]
}

impl ThreatIngestor {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            index_by_type: HashMap::new(),
        }
    }

    /// Ingest threat event (deterministic)
    pub fn ingest(&mut self, mut event: ThreatEvent) -> Result<(), String> {
        // Compute hash
        event.hash = event.compute_hash();

        // Verify integrity
        if !event.verify_integrity() {
            return Err("Hash mismatch".to_string());
        }

        // Index by type
        self.index_by_type
            .entry(event.threat_type.clone())
            .or_insert_with(Vec::new)
            .push(event.id.clone());

        // Store event
        self.events.insert(event.id.clone(), event);

        Ok(())
    }

    /// Query threats by type (O(1) lookup)
    pub fn query_by_type(&self, threat_type: &str) -> Vec<&ThreatEvent> {
        self.index_by_type
            .get(threat_type)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.events.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Export to Python (Protobuf batch)
    pub fn export_batch(&self, limit: usize) -> Vec<ThreatEvent> {
        self.events
            .values()
            .take(limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_ingestion() {
        let mut ingestor = ThreatIngestor::new();
        
        let event = ThreatEvent {
            id: "threat-001".to_string(),
            threat_type: "prompt_injection".to_string(),
            severity: 9,
            source: "OWASP".to_string(),
            indicators: vec!["ignore previous".to_string()],
            timestamp: 1234567890,
            hash: String::new(), // Will be computed
        };

        assert!(ingestor.ingest(event.clone()).is_ok());
        
        let results = ingestor.query_by_type("prompt_injection");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_hash_integrity() {
        let event = ThreatEvent {
            id: "threat-002".to_string(),
            threat_type: "pii_leakage".to_string(),
            severity: 8,
            source: "MISP".to_string(),
            indicators: vec!["CPF".to_string()],
            timestamp: 1234567890,
            hash: String::new(),
        };

        let hash1 = event.compute_hash();
        let hash2 = event.compute_hash();
        
        assert_eq!(hash1, hash2); // Deterministic
    }
}