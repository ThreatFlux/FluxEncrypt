//! AES-GCM symmetric encryption implementation.
//!
//! This module provides AES-GCM encryption and decryption functionality
//! using the Ring cryptography library for high performance and security.

use crate::config::CipherSuite;
use crate::error::{FluxError, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::ZeroizeOnDrop;

/// AES-GCM cipher for symmetric encryption/decryption operations
#[derive(Debug)]
pub struct AesGcmCipher {
    cipher_suite: CipherSuite,
    rng: SystemRandom,
}

/// A secure AES key that is automatically zeroized when dropped
#[derive(Clone, ZeroizeOnDrop)]
pub struct AesKey {
    key: Vec<u8>,
}

impl AesKey {
    /// Create a new AES key from raw bytes
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Generate a new random AES key
    pub fn generate(cipher_suite: CipherSuite) -> Result<Self> {
        let key_len = match cipher_suite {
            CipherSuite::Aes128Gcm => 16,
            CipherSuite::Aes256Gcm => 32,
        };

        let rng = SystemRandom::new();
        let mut key = vec![0u8; key_len];
        rng.fill(&mut key)
            .map_err(|_| FluxError::crypto("Failed to generate AES key"))?;

        Ok(Self::new(key))
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesKey")
            .field("len", &self.key.len())
            .finish()
    }
}

impl AesGcmCipher {
    /// Create a new AES-GCM cipher
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            cipher_suite,
            rng: SystemRandom::new(),
        }
    }

    /// Encrypt data with AES-GCM
    ///
    /// # Arguments
    /// * `key` - The AES encryption key
    /// * `plaintext` - The data to encrypt
    /// * `associated_data` - Optional associated data for authenticated encryption
    ///
    /// # Returns
    /// A tuple containing (nonce, ciphertext) where the ciphertext includes the auth tag
    pub fn encrypt(
        &self,
        key: &AesKey,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate random nonce
        let mut nonce_bytes = vec![0u8; 12]; // GCM nonce is always 12 bytes
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| FluxError::crypto("Failed to generate nonce"))?;

        let nonce = Nonce::assume_unique_for_key(
            nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| FluxError::crypto("Invalid nonce length"))?,
        );

        // Create the cipher
        let algorithm = match self.cipher_suite {
            CipherSuite::Aes128Gcm => &AES_128_GCM,
            CipherSuite::Aes256Gcm => &AES_256_GCM,
        };

        let unbound_key = UnboundKey::new(algorithm, key.as_bytes())
            .map_err(|_| FluxError::crypto("Invalid AES key"))?;
        let sealing_key = LessSafeKey::new(unbound_key);

        // Prepare data to encrypt
        let mut in_out = plaintext.to_vec();

        // Encrypt in place
        let aad = Aad::from(associated_data.unwrap_or(&[]));

        sealing_key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| FluxError::crypto("AES-GCM encryption failed"))?;

        Ok((nonce_bytes, in_out))
    }

    /// Decrypt data with AES-GCM
    ///
    /// # Arguments
    /// * `key` - The AES decryption key
    /// * `nonce` - The nonce used for encryption
    /// * `ciphertext` - The encrypted data (including auth tag)
    /// * `associated_data` - Optional associated data for authenticated encryption
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(
        &self,
        key: &AesKey,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(FluxError::invalid_input("Invalid nonce length for GCM"));
        }

        let nonce = Nonce::assume_unique_for_key(
            nonce
                .try_into()
                .map_err(|_| FluxError::crypto("Invalid nonce"))?,
        );

        // Create the cipher
        let algorithm = match self.cipher_suite {
            CipherSuite::Aes128Gcm => &AES_128_GCM,
            CipherSuite::Aes256Gcm => &AES_256_GCM,
        };

        let unbound_key = UnboundKey::new(algorithm, key.as_bytes())
            .map_err(|_| FluxError::crypto("Invalid AES key"))?;
        let opening_key = LessSafeKey::new(unbound_key);

        // Prepare data to decrypt
        let mut in_out = ciphertext.to_vec();

        // Decrypt in place
        let aad = Aad::from(associated_data.unwrap_or(&[]));

        let plaintext = opening_key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| FluxError::crypto("AES-GCM decryption failed"))?;

        Ok(plaintext.to_vec())
    }

    /// Get the key length for the configured cipher suite
    pub fn key_length(&self) -> usize {
        match self.cipher_suite {
            CipherSuite::Aes128Gcm => 16,
            CipherSuite::Aes256Gcm => 32,
        }
    }

    /// Get the nonce length (always 12 bytes for GCM)
    pub fn nonce_length(&self) -> usize {
        12
    }

    /// Get the authentication tag length (always 16 bytes for GCM)
    pub fn tag_length(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_aes_key_generation() {
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 32);

        let key = AesKey::generate(CipherSuite::Aes128Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 16);
    }

    #[test]
    fn test_aes_key_from_bytes() {
        let key_bytes = vec![0x42u8; 32];
        let key = AesKey::new(key_bytes.clone());
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_aes_key_zeroization() {
        let key_bytes = vec![0x42u8; 32];
        let key = AesKey::new(key_bytes.clone());
        drop(key);
        // Note: We can't test actual zeroization without unsafe code,
        // but the ZeroizeOnDrop derive ensures it happens
    }

    #[test]
    fn test_aes_key_debug_format() {
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("AesKey"));
        assert!(debug_str.contains("len"));
        // Should not contain actual key bytes
        assert!(!debug_str.contains("42"));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = b"Hello, FluxEncrypt!";

        let (nonce, ciphertext) = cipher.encrypt(&key, plaintext, None).unwrap();
        assert_eq!(nonce.len(), 12);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // plaintext + tag

        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = b"Hello, FluxEncrypt!";
        let aad = b"associated data";

        let (nonce, ciphertext) = cipher.encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted = cipher
            .decrypt(&key, &nonce, &ciphertext, Some(aad))
            .unwrap();
        assert_eq!(decrypted, plaintext);

        // Should fail with wrong AAD
        let wrong_aad = b"wrong data";
        let result = cipher.decrypt(&key, &nonce, &ciphertext, Some(wrong_aad));
        assert!(result.is_err());
    }

    #[test]
    fn test_both_cipher_suites() {
        for cipher_suite in &[CipherSuite::Aes128Gcm, CipherSuite::Aes256Gcm] {
            let cipher = AesGcmCipher::new(*cipher_suite);
            let key = AesKey::generate(*cipher_suite).unwrap();
            let plaintext = b"Test data for both cipher suites";

            let (nonce, ciphertext) = cipher.encrypt(&key, plaintext, None).unwrap();
            let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();

            assert_eq!(decrypted, plaintext);
            assert_eq!(nonce.len(), cipher.nonce_length());
            assert_eq!(ciphertext.len(), plaintext.len() + cipher.tag_length());
        }
    }

    #[test]
    fn test_empty_plaintext() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = b"";

        let (nonce, ciphertext) = cipher.encrypt(&key, plaintext, None).unwrap();
        assert_eq!(ciphertext.len(), 16); // Only the auth tag

        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = vec![0x42u8; 65536]; // 64KB

        let (nonce, ciphertext) = cipher.encrypt(&key, &plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_nonce_length() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let ciphertext = vec![0u8; 16]; // Just a tag

        // Test with wrong nonce lengths
        for wrong_len in &[0, 1, 11, 13, 16] {
            let wrong_nonce = vec![0u8; *wrong_len];
            let result = cipher.decrypt(&key, &wrong_nonce, &ciphertext, None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_invalid_ciphertext() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let nonce = vec![0u8; 12];

        // Test with ciphertext too short (less than tag length)
        for len in 0..16 {
            let short_ciphertext = vec![0u8; len];
            let result = cipher.decrypt(&key, &nonce, &short_ciphertext, None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_tampered_ciphertext() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = b"Test data for tampering detection";

        let (nonce, mut ciphertext) = cipher.encrypt(&key, plaintext, None).unwrap();

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 1;
        }

        let result = cipher.decrypt(&key, &nonce, &ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key1 = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let key2 = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = b"Test data for wrong key";

        let (nonce, ciphertext) = cipher.encrypt(&key1, plaintext, None).unwrap();

        // Try to decrypt with wrong key
        let result = cipher.decrypt(&key2, &nonce, &ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_properties() {
        let aes128_cipher = AesGcmCipher::new(CipherSuite::Aes128Gcm);
        let aes256_cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);

        assert_eq!(aes128_cipher.key_length(), 16);
        assert_eq!(aes256_cipher.key_length(), 32);

        assert_eq!(aes128_cipher.nonce_length(), 12);
        assert_eq!(aes256_cipher.nonce_length(), 12);

        assert_eq!(aes128_cipher.tag_length(), 16);
        assert_eq!(aes256_cipher.tag_length(), 16);
    }

    #[test]
    fn test_different_aad_values() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = b"Test data for different AAD values";

        let large_aad = vec![0u8; 1000];
        let test_aads = vec![
            Some(&b""[..]),
            Some(&b"short"[..]),
            Some(&b"a much longer associated data value that tests edge cases"[..]),
            Some(&large_aad[..]), // Large AAD
            None,
        ];

        for aad in test_aads {
            let (nonce, ciphertext) = cipher.encrypt(&key, plaintext, aad).unwrap();
            let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, aad).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_nonce_uniqueness() {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let plaintext = b"Test nonce uniqueness";

        let mut nonces = std::collections::HashSet::new();

        // Generate multiple encryptions and check nonce uniqueness
        for _ in 0..100 {
            let (nonce, _) = cipher.encrypt(&key, plaintext, None).unwrap();
            assert!(nonces.insert(nonce), "Duplicate nonce detected");
        }
    }

    // Property-based tests using proptest
    proptest! {
        #[test]
        fn test_encrypt_decrypt_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..10000)
        ) {
            let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
            let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();

            let (nonce, ciphertext) = cipher.encrypt(&key, &data, None).unwrap();
            let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn test_encrypt_decrypt_with_aad_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..1000),
            aad in prop::collection::vec(any::<u8>(), 0..1000)
        ) {
            let cipher = AesGcmCipher::new(CipherSuite::Aes128Gcm);
            let key = AesKey::generate(CipherSuite::Aes128Gcm).unwrap();

            let (nonce, ciphertext) = cipher.encrypt(&key, &data, Some(&aad)).unwrap();
            let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, Some(&aad)).unwrap();

            prop_assert_eq!(decrypted, data);
        }
    }
}
