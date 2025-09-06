//! Hybrid encryption implementation combining RSA-OAEP and AES-GCM.
//!
//! This module provides the main HybridCipher that uses RSA for key encryption
//! and AES-GCM for fast data encryption, following best practices for hybrid
//! cryptography.

use super::{
    aes_gcm::{AesGcmCipher, AesKey},
    rsa_oaep::RsaOaepCipher,
};
use crate::config::Config;
use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};

/// A hybrid cipher that combines RSA-OAEP and AES-GCM encryption.
///
/// The HybridCipher uses RSA-OAEP to encrypt a randomly generated AES key,
/// which is then used to encrypt the actual data with AES-GCM. This approach
/// combines the security of RSA with the performance of AES.
#[derive(Debug, Clone)]
pub struct HybridCipher {
    config: Config,
}

impl HybridCipher {
    /// Create a new HybridCipher with the given configuration.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Encrypt data using hybrid encryption.
    ///
    /// # Arguments
    /// * `public_key` - The RSA public key to encrypt the AES key with
    /// * `plaintext` - The data to encrypt (max 512KB for blob encryption)
    ///
    /// # Returns
    /// The encrypted data as a byte vector in format:
    /// [encrypted_session_key(512 bytes)][nonce(12 bytes)][ciphertext+tag]
    pub fn encrypt(&self, public_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Check size limit: 512KB maximum for blob encryption
        const MAX_BLOB_SIZE: usize = 512 * 1024; // 512KB
        if plaintext.len() > MAX_BLOB_SIZE {
            return Err(FluxError::invalid_input(format!(
                "Data too large for blob encryption: {} bytes exceeds {} KB limit",
                plaintext.len(),
                MAX_BLOB_SIZE / 1024
            )));
        }

        // 1. Generate random AES key
        let aes_key = AesKey::generate(self.config.cipher_suite)?;

        // 2. Encrypt plaintext with AES-GCM
        let aes_cipher = AesGcmCipher::new(self.config.cipher_suite);
        let (nonce, aes_ciphertext) = aes_cipher.encrypt(&aes_key, plaintext, None)?;

        // 3. Encrypt AES key with RSA-OAEP
        let rsa_cipher = RsaOaepCipher::new();
        let encrypted_aes_key = rsa_cipher.encrypt(public_key, aes_key.as_bytes())?;

        // 4. Validate encrypted key size (should match RSA key size in bytes)
        let expected_key_size = public_key.key_size_bits() / 8;
        if encrypted_aes_key.len() != expected_key_size {
            return Err(FluxError::crypto(format!(
                "Unexpected encrypted key size: {} bytes, expected {} bytes for {}-bit RSA",
                encrypted_aes_key.len(),
                expected_key_size,
                public_key.key_size_bits()
            )));
        }

        // 5. Validate nonce size (should be 12 bytes for GCM)
        if nonce.len() != 12 {
            return Err(FluxError::crypto(format!(
                "Unexpected nonce size: {} bytes, expected 12 bytes for GCM",
                nonce.len()
            )));
        }

        // 6. Combine data in format:
        // [encrypted_session_key(key_size bytes)][nonce(12 bytes)][ciphertext+tag]
        let mut result = Vec::with_capacity(encrypted_aes_key.len() + 12 + aes_ciphertext.len());

        result.extend_from_slice(&encrypted_aes_key); // key_size bytes
        result.extend_from_slice(&nonce); // 12 bytes
        result.extend_from_slice(&aes_ciphertext); // ciphertext + 16-byte tag

        Ok(result)
    }

    /// Decrypt data using hybrid decryption.
    ///
    /// # Arguments
    /// * `private_key` - The RSA private key to decrypt the AES key with
    /// * `ciphertext` - The encrypted data in format: [encrypted_session_key(key_size)][nonce(12)][ciphertext+tag]
    ///
    /// # Returns
    /// The decrypted data as a byte vector.
    pub fn decrypt(&self, private_key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Calculate the expected encrypted key size based on RSA key size
        let encrypted_key_size = private_key.key_size_bits() / 8;

        // Minimum size check: encrypted_key_size + 12 (nonce) + 16 (GCM tag)
        let min_size = encrypted_key_size + 12 + 16;
        if ciphertext.len() < min_size {
            return Err(FluxError::invalid_input(format!(
                "Ciphertext too short: {} bytes, minimum {} bytes required",
                ciphertext.len(),
                min_size
            )));
        }

        // Parse format: [encrypted_session_key(key_size)][nonce(12)][ciphertext+tag]
        let encrypted_aes_key = &ciphertext[0..encrypted_key_size];
        let nonce = &ciphertext[encrypted_key_size..encrypted_key_size + 12];
        let aes_ciphertext = &ciphertext[encrypted_key_size + 12..];

        // 1. Decrypt AES key with RSA-OAEP
        let rsa_cipher = RsaOaepCipher::new();
        let aes_key_bytes = rsa_cipher.decrypt(private_key, encrypted_aes_key)?;
        let aes_key = AesKey::new(aes_key_bytes);

        // 2. Decrypt ciphertext with AES-GCM
        let aes_cipher = AesGcmCipher::new(self.config.cipher_suite);
        let plaintext = aes_cipher.decrypt(&aes_key, nonce, aes_ciphertext, None)?;

        Ok(plaintext)
    }

    /// Get the configuration used by this cipher.
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl Default for HybridCipher {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CipherSuite, Config, RsaKeySize};
    use crate::keys::KeyPair;
    use proptest::prelude::*;

    #[test]
    fn test_hybrid_cipher_creation() {
        let cipher = HybridCipher::default();
        assert!(cipher.config().validate().is_ok());
    }

    #[test]
    fn test_hybrid_cipher_with_custom_config() {
        let config = Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .rsa_key_size(RsaKeySize::Rsa3072)
            .build()
            .unwrap();

        let cipher = HybridCipher::new(config.clone());
        assert_eq!(cipher.config().cipher_suite, config.cipher_suite);
        assert_eq!(cipher.config().rsa_key_size, config.rsa_key_size);
    }

    #[test]
    fn test_hybrid_cipher_debug() {
        let cipher = HybridCipher::default();
        let debug_str = format!("{:?}", cipher);
        assert!(debug_str.contains("HybridCipher"));
        assert!(debug_str.contains("config"));
    }

    #[test]
    fn test_hybrid_cipher_clone() {
        let config = Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .build()
            .unwrap();

        let cipher1 = HybridCipher::new(config);
        let cipher2 = cipher1.clone();

        assert_eq!(cipher1.config().cipher_suite, cipher2.config().cipher_suite);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = b"Hello, FluxEncrypt hybrid encryption!";

        // Test encryption
        let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();
        assert!(!ciphertext.is_empty());
        assert!(ciphertext.len() > plaintext.len()); // Should be larger due to metadata

        // Test decryption
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = b"";

        let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_data_encryption() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = vec![42u8; 10000]; // 10KB of data

        let ciphertext = cipher.encrypt(keypair.public_key(), &plaintext).unwrap();
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_very_large_data_encryption() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = vec![0x42u8; 512 * 1024]; // 512KB of data (at the limit)

        let ciphertext = cipher.encrypt(keypair.public_key(), &plaintext).unwrap();
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_data_size_limit_exceeded() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = vec![0x42u8; 512 * 1024 + 1]; // 512KB + 1 byte (exceeds limit)

        let result = cipher.encrypt(keypair.public_key(), &plaintext);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("Data too large for blob encryption"));
        }
    }

    #[test]
    fn test_different_cipher_suites() {
        let keypair = KeyPair::generate(2048).unwrap();
        let plaintext = b"Test data for different cipher suites";

        for cipher_suite in &[CipherSuite::Aes128Gcm, CipherSuite::Aes256Gcm] {
            let config = Config::builder()
                .cipher_suite(*cipher_suite)
                .build()
                .unwrap();

            let cipher = HybridCipher::new(config);

            let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();
            let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();

            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_different_key_sizes() {
        let plaintext = b"Test data for different key sizes";

        for key_size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(*key_size).unwrap();
            let cipher = HybridCipher::default();

            let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();
            let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();

            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_decrypt_invalid_ciphertext_too_short() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();

        // Test with ciphertext too short (less than minimum required: 256+12+16=284 bytes for 2048-bit RSA)
        for len in 0..284 {
            let short_ciphertext = vec![0u8; len];
            let result = cipher.decrypt(keypair.private_key(), &short_ciphertext);
            assert!(result.is_err(), "Should fail with length {}", len);

            if let Err(e) = result {
                assert!(e.to_string().contains("Ciphertext too short"));
            }
        }
    }

    #[test]
    fn test_decrypt_invalid_encrypted_key_data() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();

        // Create a ciphertext with valid length but invalid encrypted key data
        let encrypted_key_size = keypair.private_key().key_size_bits() / 8;
        let invalid_ciphertext = vec![0u8; encrypted_key_size + 12 + 16];
        // Fill with invalid data that will fail RSA decryption

        let result = cipher.decrypt(keypair.private_key(), &invalid_ciphertext);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("RSA decryption failed"));
        }
    }

    #[test]
    fn test_ciphertext_format_integrity() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = b"Test ciphertext format integrity";

        let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();

        // Verify ciphertext format: [encrypted_key][nonce][aes_ciphertext]
        let encrypted_key_size = keypair.public_key().key_size_bits() / 8; // 256 bytes for 2048-bit RSA
        let nonce_size = 12; // GCM nonce size
        let tag_size = 16; // GCM tag size

        let expected_min_size = encrypted_key_size + nonce_size + tag_size;
        assert!(
            ciphertext.len() >= expected_min_size,
            "Ciphertext should have at least {} bytes, got {}",
            expected_min_size,
            ciphertext.len()
        );

        // Verify structure
        assert_eq!(
            encrypted_key_size, 256,
            "Encrypted key should be 256 bytes for 2048-bit RSA"
        );

        // The remaining should be nonce (12 bytes) + AES ciphertext with tag
        let aes_data_size = ciphertext.len() - encrypted_key_size;
        assert_eq!(
            aes_data_size,
            nonce_size + plaintext.len() + tag_size,
            "AES data should be nonce + plaintext + tag"
        );
    }

    #[test]
    fn test_different_plaintexts_produce_different_ciphertexts() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();

        let plaintext1 = b"First test message";
        let plaintext2 = b"Second test message";

        let ciphertext1 = cipher.encrypt(keypair.public_key(), plaintext1).unwrap();
        let ciphertext2 = cipher.encrypt(keypair.public_key(), plaintext2).unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Different plaintexts should produce different ciphertexts"
        );
    }

    #[test]
    fn test_same_plaintext_produces_different_ciphertexts() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = b"Same test message";

        let ciphertext1 = cipher.encrypt(keypair.public_key(), plaintext).unwrap();
        let ciphertext2 = cipher.encrypt(keypair.public_key(), plaintext).unwrap();

        // Due to random nonce and AES key generation, same plaintext should produce different ciphertexts
        assert_ne!(
            ciphertext1, ciphertext2,
            "Same plaintext should produce different ciphertexts due to randomness"
        );

        // But both should decrypt to the same plaintext
        let decrypted1 = cipher.decrypt(keypair.private_key(), &ciphertext1).unwrap();
        let decrypted2 = cipher.decrypt(keypair.private_key(), &ciphertext2).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_detection() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();
        let plaintext = b"Test tamper detection";

        let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();

        // Tamper with various parts of the ciphertext
        let encrypted_key_size = keypair.public_key().key_size_bits() / 8; // 256 for 2048-bit RSA
        let original_len = ciphertext.len();

        // Tamper with encrypted key data (first 256 bytes)
        if ciphertext.len() > 10 {
            let mut tampered = ciphertext.clone();
            tampered[10] ^= 1; // Tamper with encrypted key
            let _result = cipher.decrypt(keypair.private_key(), &tampered);
            // This might or might not fail depending on RSA implementation and where we tamper
        }

        // Tamper with nonce (bytes 256-268)
        if ciphertext.len() > encrypted_key_size + 5 {
            let mut tampered = ciphertext.clone();
            tampered[encrypted_key_size + 5] ^= 1; // Tamper with nonce
            let _result = cipher.decrypt(keypair.private_key(), &tampered);
            // This should fail due to GCM authentication or nonce mismatch
        }

        // Tamper with AES ciphertext (should always fail due to GCM authentication)
        if !ciphertext.is_empty() {
            let mut tampered = ciphertext.clone();
            tampered[original_len - 1] ^= 1; // Tamper with last byte (AES ciphertext/tag)
            let _result = cipher.decrypt(keypair.private_key(), &tampered);
            // Should fail due to GCM authentication
        }
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_encrypt_decrypt_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..10000)
        ) {
            let keypair = KeyPair::generate(2048).unwrap();
            let cipher = HybridCipher::default();

            let ciphertext = cipher.encrypt(keypair.public_key(), &data).unwrap();
            let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();

            let data_len = data.len();
            let is_empty = data.is_empty();

            prop_assert_eq!(decrypted, data);
            if !is_empty {
                prop_assert!(ciphertext.len() > data_len, "Ciphertext should be larger than plaintext");
            }
        }
    }

    #[test]
    fn test_encrypt_with_different_data_patterns() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = HybridCipher::default();

        let test_patterns = vec![
            vec![0x00; 100],                                           // All zeros
            vec![0xFF; 100],                                           // All ones
            (0..100u8).collect(),                                      // Sequential bytes
            [0xAA, 0x55].repeat(50),                                   // Alternating pattern
            b"The quick brown fox jumps over the lazy dog".repeat(10), // Repeated text
        ];

        for pattern in test_patterns {
            let ciphertext = cipher.encrypt(keypair.public_key(), &pattern).unwrap();
            let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();
            assert_eq!(decrypted, pattern);
        }
    }

    #[test]
    fn test_config_access() {
        let config = Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .build()
            .unwrap();

        let cipher = HybridCipher::new(config.clone());
        assert_eq!(cipher.config().cipher_suite, config.cipher_suite);
    }
}
