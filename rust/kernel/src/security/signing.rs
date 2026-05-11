
use ring::hmac;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

/// Signing key manager (HMAC-SHA256)
pub struct SigningKeyManager {
    key: hmac::Key,
}

impl SigningKeyManager {
    /// Load signing key from file (secure storage)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        // Read key file — Zeroizing ensures memory is zeroed on drop
        let key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            fs::read(path.as_ref())
                .map_err(|e| CryptoError::KeyLoadFailed(e.to_string()))?
        );

        // Validate key length (must be 32 bytes for HMAC-SHA256)
        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        // Validate key entropy (must not be all zeros, etc)
        if key_bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::WeakKey("Key is all zeros".to_string()));
        }

        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        // key_bytes is zeroed automatically when dropped here
        Ok(Self { key })
    }
    
    /// Generate new signing key (for initial setup)
    pub fn generate() -> Result<Vec<u8>, CryptoError> {
        use ring::rand::{SystemRandom, SecureRandom};
        
        let rng = SystemRandom::new();
        let mut key_bytes = vec![0u8; 32];
        
        rng.fill(&mut key_bytes)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        
        Ok(key_bytes)
    }
    
    /// Sign message (HMAC-SHA256)
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = hmac::sign(&self.key, message);
        signature.as_ref().to_vec()
    }
    
    /// Verify signature (constant-time comparison)
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        hmac::verify(&self.key, message, signature).is_ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Failed to load key: {0}")]
    KeyLoadFailed(String),
    
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Weak key detected: {0}")]
    WeakKey(String),
    
    #[error("Key generation failed")]
    KeyGenerationFailed,
}

// ═══════════════════════════════════════════════════════════════
// Key Rotation Support
// ═══════════════════════════════════════════════════════════════

pub struct SigningKeyRotator {
    current_key: SigningKeyManager,
    previous_keys: Vec<SigningKeyManager>,
}

impl SigningKeyRotator {
    /// Load current key + previous keys (for rotation)
    pub fn new(
        current_key_path: &Path,
        previous_key_paths: Vec<&Path>,
    ) -> Result<Self, CryptoError> {
        let current_key = SigningKeyManager::from_file(current_key_path)?;
        
        let mut previous_keys = Vec::new();
        for path in previous_key_paths {
            previous_keys.push(SigningKeyManager::from_file(path)?);
        }
        
        Ok(Self {
            current_key,
            previous_keys,
        })
    }
    
    /// Sign with current key
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.current_key.sign(message)
    }
    
    /// Verify with current key OR previous keys (during rotation)
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        // Try current key first
        if self.current_key.verify(message, signature) {
            return true;
        }
        
        // Try previous keys (rotation period)
        for key in &self.previous_keys {
            if key.verify(message, signature) {
                return true;
            }
        }
        
        false
    }
}

// ═══════════════════════════════════════════════════════════════
// Asymmetric Signing (Ed25519) — ADR-C2
// Zero heap on hot path (sign returns [u8;64] on stack).
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum SigningError {
    KeyGenerationFailed,
    InvalidKey,
}

pub struct AsymmetricSigner {
    key_pair: Ed25519KeyPair,
}

impl AsymmetricSigner {
    /// Generate a new Ed25519 key pair. Cold path — allocation acceptable.
    /// Returns (signer, public_key_bytes[32]).
    pub fn generate() -> Result<(Self, [u8; 32]), SigningError> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| SigningError::KeyGenerationFailed)?;
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| SigningError::InvalidKey)?;
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(kp.public_key().as_ref());
        Ok((Self { key_pair: kp }, pub_key))
    }

    /// Hot path: sign returns [u8; 64] on the stack — zero heap allocation.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig = self.key_pair.sign(message);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    /// Verify an Ed25519 signature.
    pub fn verify(pub_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let peer = UnparsedPublicKey::new(&ED25519, pub_key as &[u8]);
        peer.verify(msg, sig).is_ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_sign_and_verify() {
        // Generate key
        let key_bytes = SigningKeyManager::generate().unwrap();
        
        // Write to temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&key_bytes).unwrap();
        
        // Load key
        let manager = SigningKeyManager::from_file(temp_file.path()).unwrap();
        
        // Sign message
        let message = b"Hello, World!";
        let signature = manager.sign(message);
        
        // Verify
        assert!(manager.verify(message, &signature));
        
        // Verify with wrong message
        assert!(!manager.verify(b"Wrong message", &signature));
    }
    
    #[test]
    fn test_key_rotation() {
        // Generate keys
        let key1 = SigningKeyManager::generate().unwrap();
        let key2 = SigningKeyManager::generate().unwrap();
        
        // Write to temp files
        let mut file1 = NamedTempFile::new().unwrap();
        let mut file2 = NamedTempFile::new().unwrap();
        file1.write_all(&key1).unwrap();
        file2.write_all(&key2).unwrap();
        
        // Create rotator (key2 = current, key1 = previous)
        let rotator = SigningKeyRotator::new(
            file2.path(),
            vec![file1.path()],
        ).unwrap();
        
        // Sign with current key
        let message = b"Test message";
        let signature_current = rotator.sign(message);
        
        // Should verify (current key)
        assert!(rotator.verify(message, &signature_current));
        
        // Sign with previous key manually
        let manager_previous = SigningKeyManager::from_file(file1.path()).unwrap();
        let signature_previous = manager_previous.sign(message);
        
        // Should also verify (previous key)
        assert!(rotator.verify(message, &signature_previous));
    }

    #[test]
    fn test_asymmetric_sign_verify_roundtrip() {
        let (signer, pub_key) = AsymmetricSigner::generate().unwrap();
        let message = b"BTV agent attestation test";
        let sig = signer.sign(message);
        assert!(AsymmetricSigner::verify(&pub_key, message, &sig));
        // Wrong message must fail
        assert!(!AsymmetricSigner::verify(&pub_key, b"tampered", &sig));
        // Wrong key must fail
        let (_, other_pub) = AsymmetricSigner::generate().unwrap();
        assert!(!AsymmetricSigner::verify(&other_pub, message, &sig));
    }

    #[test]
    fn test_asymmetric_sign_is_stack_only() {
        // sign() must return [u8; 64] — compile-time size verified here
        let (signer, _) = AsymmetricSigner::generate().unwrap();
        let sig: [u8; 64] = signer.sign(b"stack-only");
        assert_eq!(sig.len(), 64);
    }
}
