//! Simple symmetric encryption for secret storage.
//!
//! This module provides a straightforward AES-256-GCM encryption interface
//! designed for encrypting secrets like API tokens, MFA secrets, and other
//! sensitive data stored in databases.
//!
//! # Example
//!
//! ```rust
//! use fluxencrypt::symmetric::SymmetricCipher;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create cipher from hex-encoded 32-byte key
//! let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
//! let cipher = SymmetricCipher::new(key)?;
//!
//! // Encrypt a secret
//! let secret = "my-secret-api-token";
//! let encrypted = cipher.encrypt(secret)?;
//!
//! // Decrypt it back
//! let decrypted = cipher.decrypt(&encrypted)?;
//! assert_eq!(decrypted, secret);
//! # Ok(())
//! # }
//! ```
//!
//! # Security Notes
//!
//! - Uses AES-256-GCM with 12-byte random nonces
//! - Each encryption produces different ciphertext (due to random nonce)
//! - Authentication tag prevents tampering
//! - Output format: `base64(nonce || ciphertext || tag)`

use crate::config::CipherSuite;
use crate::encryption::aes_gcm::{AesGcmCipher, AesKey};
use crate::error::{FluxError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// A simple symmetric encryption cipher for secret storage.
///
/// Uses AES-256-GCM with random nonces and base64-encoded output.
/// Designed for encrypting secrets in databases.
#[derive(Debug)]
pub struct SymmetricCipher {
    cipher: AesGcmCipher,
    key: AesKey,
}

impl SymmetricCipher {
    /// Create a new symmetric cipher from a hex-encoded 32-byte key.
    ///
    /// # Arguments
    /// * `hex_key` - A 64-character hex string representing a 32-byte key
    ///
    /// # Errors
    /// Returns an error if the key is not valid hex or not 32 bytes.
    ///
    /// # Example
    /// ```rust
    /// use fluxencrypt::symmetric::SymmetricCipher;
    ///
    /// let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// let cipher = SymmetricCipher::new(key).unwrap();
    /// ```
    pub fn new(hex_key: &str) -> Result<Self> {
        let key_bytes = hex::decode(hex_key)
            .map_err(|_| FluxError::key("Invalid hex encoding for encryption key"))?;

        if key_bytes.len() != 32 {
            return Err(FluxError::key(format!(
                "Encryption key must be 32 bytes (64 hex characters), got {} bytes",
                key_bytes.len()
            )));
        }

        let key = AesKey::new(key_bytes);
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);

        Ok(Self { cipher, key })
    }

    /// Create a new symmetric cipher from raw 32-byte key.
    ///
    /// # Arguments
    /// * `key_bytes` - A 32-byte encryption key
    ///
    /// # Errors
    /// Returns an error if the key is not exactly 32 bytes.
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(FluxError::key(format!(
                "Encryption key must be 32 bytes, got {} bytes",
                key_bytes.len()
            )));
        }

        let key = AesKey::new(key_bytes.to_vec());
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);

        Ok(Self { cipher, key })
    }

    /// Encrypt plaintext and return base64-encoded ciphertext.
    ///
    /// The output format is `base64(nonce || ciphertext || tag)` where:
    /// - `nonce` is 12 random bytes
    /// - `ciphertext` is the encrypted data
    /// - `tag` is the 16-byte authentication tag
    ///
    /// # Arguments
    /// * `plaintext` - The string to encrypt
    ///
    /// # Returns
    /// Base64-encoded ciphertext suitable for database storage.
    ///
    /// # Example
    /// ```rust
    /// use fluxencrypt::symmetric::SymmetricCipher;
    ///
    /// let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// let cipher = SymmetricCipher::new(key).unwrap();
    ///
    /// let encrypted = cipher.encrypt("secret-token").unwrap();
    /// assert!(!encrypted.is_empty());
    /// ```
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        self.encrypt_bytes(plaintext.as_bytes())
    }

    /// Encrypt raw bytes and return base64-encoded ciphertext.
    ///
    /// Same as `encrypt()` but accepts raw bytes instead of a string.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<String> {
        let (nonce, ciphertext) = self.cipher.encrypt(&self.key, plaintext, None)?;

        // Combine nonce and ciphertext
        let mut combined = nonce;
        combined.extend(ciphertext);

        // Base64 encode
        Ok(BASE64.encode(combined))
    }

    /// Decrypt base64-encoded ciphertext and return plaintext string.
    ///
    /// # Arguments
    /// * `encrypted` - Base64-encoded ciphertext from `encrypt()`
    ///
    /// # Returns
    /// The original plaintext string.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The input is not valid base64
    /// - The ciphertext is too short (less than nonce + tag)
    /// - The authentication tag is invalid (tampered data)
    /// - The decrypted data is not valid UTF-8
    ///
    /// # Example
    /// ```rust
    /// use fluxencrypt::symmetric::SymmetricCipher;
    ///
    /// let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// let cipher = SymmetricCipher::new(key).unwrap();
    ///
    /// let encrypted = cipher.encrypt("secret-token").unwrap();
    /// let decrypted = cipher.decrypt(&encrypted).unwrap();
    /// assert_eq!(decrypted, "secret-token");
    /// ```
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        let decrypted_bytes = self.decrypt_bytes(encrypted)?;

        String::from_utf8(decrypted_bytes)
            .map_err(|_| FluxError::crypto("Decrypted data is not valid UTF-8"))
    }

    /// Decrypt base64-encoded ciphertext and return raw bytes.
    ///
    /// Same as `decrypt()` but returns raw bytes instead of a string.
    pub fn decrypt_bytes(&self, encrypted: &str) -> Result<Vec<u8>> {
        // Base64 decode
        let combined = BASE64
            .decode(encrypted)
            .map_err(|_| FluxError::invalid_input("Invalid base64 encoding in ciphertext"))?;

        // Minimum length: 12 (nonce) + 16 (tag)
        if combined.len() < 28 {
            return Err(FluxError::invalid_input(
                "Ciphertext too short (must be at least 28 bytes after base64 decoding)",
            ));
        }

        // Split nonce and ciphertext
        let (nonce, ciphertext) = combined.split_at(12);

        self.cipher.decrypt(&self.key, nonce, ciphertext, None)
    }

    /// Generate a new random encryption key and return it as hex-encoded string.
    ///
    /// Use this to generate keys for new deployments.
    ///
    /// # Example
    /// ```rust
    /// use fluxencrypt::symmetric::SymmetricCipher;
    ///
    /// let key = SymmetricCipher::generate_key().unwrap();
    /// assert_eq!(key.len(), 64); // 32 bytes = 64 hex chars
    ///
    /// // Use the generated key
    /// let cipher = SymmetricCipher::new(&key).unwrap();
    /// ```
    pub fn generate_key() -> Result<String> {
        let key = AesKey::generate(CipherSuite::Aes256Gcm)?;
        Ok(hex::encode(key.as_bytes()))
    }
}

impl Clone for SymmetricCipher {
    fn clone(&self) -> Self {
        // We need to clone the key bytes since AesKey doesn't implement Clone publicly
        Self {
            cipher: AesGcmCipher::new(CipherSuite::Aes256Gcm),
            key: AesKey::new(self.key.as_bytes().to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_key() -> String {
        SymmetricCipher::generate_key().unwrap()
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let plaintext = "access-sandbox-abc123-secret-token";
        let encrypted = cipher.encrypt(plaintext).unwrap();

        assert_ne!(encrypted, plaintext);

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let plaintext = b"binary\x00data\xff\xfe";
        let encrypted = cipher.encrypt_bytes(plaintext).unwrap();

        let decrypted = cipher.decrypt_bytes(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_not_hex() {
        let result =
            SymmetricCipher::new("not-hex-gggggggggggggggggggggggggggggggggggggggggggggggggggggg");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_too_short() {
        let result = SymmetricCipher::new("tooshort");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_too_long() {
        let result = SymmetricCipher::new(&"a".repeat(66));
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_key_exact_length() {
        let result = SymmetricCipher::new(&"a".repeat(64));
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_string() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let encrypted = cipher.encrypt("").unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_unicode_content() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let unicode_text = "Hello 世界! 🔐 Привет мир! café résumé";
        let encrypted = cipher.encrypt(unicode_text).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, unicode_text);
    }

    #[test]
    fn test_very_long_data() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let long_text: String = (0..10000)
            .map(|i| ((i % 26) as u8 + b'a') as char)
            .collect();
        let encrypted = cipher.encrypt(&long_text).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, long_text);
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        assert!(cipher.decrypt("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        // "abc" in base64 - way too short
        assert!(cipher.decrypt("YWJj").is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = generate_test_key();
        let key2 = generate_test_key();

        let cipher1 = SymmetricCipher::new(&key1).unwrap();
        let cipher2 = SymmetricCipher::new(&key2).unwrap();

        let encrypted = cipher1.encrypt("secret data").unwrap();

        // Decrypting with a different key should fail
        assert!(cipher2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertext() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let plaintext = "same input";
        let encrypted1 = cipher.encrypt(plaintext).unwrap();
        let encrypted2 = cipher.encrypt(plaintext).unwrap();

        // Due to random nonce, same plaintext produces different ciphertext
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same value
        assert_eq!(cipher.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(cipher.decrypt(&encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn test_special_characters() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?\n\t\r\\";
        let encrypted = cipher.encrypt(special_chars).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, special_chars);
    }

    #[test]
    fn test_json_content() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let json = r#"{"access_token":"secret","refresh_token":"also_secret","expires_in":3600}"#;
        let encrypted = cipher.encrypt(json).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, json);
    }

    #[test]
    fn test_generate_key() {
        let key = SymmetricCipher::generate_key().unwrap();
        assert_eq!(key.len(), 64); // 32 bytes = 64 hex chars

        // Key should be valid hex
        assert!(hex::decode(&key).is_ok());

        // Should be able to create a cipher with it
        let cipher = SymmetricCipher::new(&key).unwrap();
        let encrypted = cipher.encrypt("test").unwrap();
        assert_eq!(cipher.decrypt(&encrypted).unwrap(), "test");
    }

    #[test]
    fn test_from_bytes() {
        let key_bytes = [0x42u8; 32];
        let cipher = SymmetricCipher::from_bytes(&key_bytes).unwrap();

        let encrypted = cipher.encrypt("test").unwrap();
        assert_eq!(cipher.decrypt(&encrypted).unwrap(), "test");
    }

    #[test]
    fn test_from_bytes_wrong_length() {
        let short = [0u8; 16];
        assert!(SymmetricCipher::from_bytes(&short).is_err());

        let long = [0u8; 64];
        assert!(SymmetricCipher::from_bytes(&long).is_err());
    }

    #[test]
    fn test_clone() {
        let key = generate_test_key();
        let cipher1 = SymmetricCipher::new(&key).unwrap();
        let cipher2 = cipher1.clone();

        let encrypted = cipher1.encrypt("test").unwrap();
        assert_eq!(cipher2.decrypt(&encrypted).unwrap(), "test");
    }

    #[test]
    fn test_tampered_ciphertext() {
        let key = generate_test_key();
        let cipher = SymmetricCipher::new(&key).unwrap();

        let encrypted = cipher.encrypt("secret").unwrap();

        // Decode, tamper, re-encode
        let mut bytes = BASE64.decode(&encrypted).unwrap();
        if bytes.len() > 12 {
            bytes[12] ^= 1; // Flip a bit in the ciphertext portion
        }
        let tampered = BASE64.encode(&bytes);

        // Should fail authentication
        assert!(cipher.decrypt(&tampered).is_err());
    }
}
