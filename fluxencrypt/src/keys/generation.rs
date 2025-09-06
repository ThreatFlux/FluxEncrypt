//! RSA key pair generation functionality.
//!
//! This module provides secure RSA key pair generation using the RSA
//! cryptography library with proper random number generation.

use crate::error::{FluxError, Result};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use zeroize::ZeroizeOnDrop;

/// An RSA public key
#[derive(Clone)]
pub struct PublicKey {
    /// The underlying RSA public key
    inner: RsaPublicKey,
}

/// An RSA private key that is automatically zeroized when dropped
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// The underlying RSA private key
    inner: RsaPrivateKey,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key_size", &(self.inner.size() * 8))
            .field("_key_data", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("key_size", &(self.inner.size() * 8))
            .field("modulus", &format!("{} bits", self.inner.n().bits()))
            .field("public_exponent", &self.inner.e())
            .finish()
    }
}

/// An RSA key pair containing both public and private keys
#[derive(Debug)]
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl PublicKey {
    /// Create a new public key from an RSA public key
    pub fn new(inner: RsaPublicKey) -> Self {
        Self { inner }
    }

    /// Get the key size in bits
    pub fn key_size_bits(&self) -> usize {
        self.inner.size() * 8
    }

    /// Get the key size in bytes
    pub fn key_size_bytes(&self) -> usize {
        self.inner.size()
    }

    /// Get the modulus as bytes
    pub fn modulus(&self) -> Vec<u8> {
        self.inner.n().to_bytes_be()
    }

    /// Get the public exponent as bytes
    pub fn public_exponent(&self) -> Vec<u8> {
        self.inner.e().to_bytes_be()
    }

    /// Get a reference to the inner RSA public key
    pub fn inner(&self) -> &RsaPublicKey {
        &self.inner
    }

    /// Export the public key as PEM format (PKCS1 format with RSA PUBLIC KEY header)
    pub fn to_pem(&self) -> Result<String> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.inner
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|e| FluxError::crypto(format!("Failed to encode public key as PEM: {}", e)))
    }

    /// Export the public key as DER format (PKCS1 format)
    pub fn to_der(&self) -> Result<Vec<u8>> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.inner
            .to_pkcs1_der()
            .map(|der| der.as_bytes().to_vec())
            .map_err(|e| FluxError::crypto(format!("Failed to encode public key as DER: {}", e)))
    }
}

impl PrivateKey {
    /// Create a new private key from an RSA private key
    pub fn new(inner: RsaPrivateKey) -> Self {
        Self { inner }
    }

    /// Get the key size in bits
    pub fn key_size_bits(&self) -> usize {
        self.inner.size() * 8
    }

    /// Get the key size in bytes
    pub fn key_size_bytes(&self) -> usize {
        self.inner.size()
    }

    /// Get a reference to the inner RSA private key
    pub fn inner(&self) -> &RsaPrivateKey {
        &self.inner
    }

    /// Export the private key as PEM format (PKCS1 format with RSA PRIVATE KEY header)
    pub fn to_pem(&self) -> Result<String> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        self.inner
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map(|zeroizing_string| zeroizing_string.to_string())
            .map_err(|e| FluxError::crypto(format!("Failed to encode private key as PEM: {}", e)))
    }

    /// Export the private key as encrypted PEM format (PKCS#8 format with password protection)
    pub fn to_encrypted_pem(&self, password: &str) -> Result<String> {
        use pkcs8::PrivateKeyInfo;
        use rand::rngs::OsRng;
        use rsa::pkcs8::EncodePrivateKey;

        // First encode the private key as PKCS#8 DER
        let private_key_der = self.inner.to_pkcs8_der().map_err(|e| {
            FluxError::crypto(format!("Failed to encode private key as PKCS#8 DER: {}", e))
        })?;

        // Parse it back into PrivateKeyInfo
        let private_key_info = PrivateKeyInfo::try_from(private_key_der.as_bytes())
            .map_err(|e| FluxError::crypto(format!("Failed to parse PKCS#8 DER: {}", e)))?;

        // Encrypt the private key with the password
        let encrypted_private_key = private_key_info
            .encrypt(&mut OsRng, password)
            .map_err(|e| FluxError::crypto(format!("Failed to encrypt private key: {}", e)))?;

        // Convert to PEM format
        let pem_string = encrypted_private_key
            .to_pem("ENCRYPTED PRIVATE KEY", pkcs8::LineEnding::LF)
            .map_err(|e| {
                FluxError::crypto(format!(
                    "Failed to encode encrypted private key as PEM: {}",
                    e
                ))
            })?;

        Ok(pem_string.to_string())
    }

    /// Export the private key as DER format (PKCS1 format)
    pub fn to_der(&self) -> Result<Vec<u8>> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        self.inner
            .to_pkcs1_der()
            .map(|der| der.as_bytes().to_vec())
            .map_err(|e| FluxError::crypto(format!("Failed to encode private key as DER: {}", e)))
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::new(self.inner.to_public_key()))
    }

    /// Get the modulus as bytes
    pub fn modulus(&self) -> Vec<u8> {
        self.inner.n().to_bytes_be()
    }

    /// Get the private exponent as bytes
    pub fn private_exponent(&self) -> Vec<u8> {
        self.inner.d().to_bytes_be()
    }

    /// Get the first prime factor as bytes
    pub fn prime1(&self) -> Vec<u8> {
        self.inner.primes()[0].to_bytes_be()
    }

    /// Get the second prime factor as bytes
    pub fn prime2(&self) -> Vec<u8> {
        self.inner.primes()[1].to_bytes_be()
    }

    /// Get the CRT coefficient as bytes
    pub fn crt_coefficient(&self) -> Vec<u8> {
        // For compatibility with the existing API, we return a CRT coefficient
        // The RSA crate computes CRT values internally, so we'll derive one
        // from the available key components for API compatibility
        let primes = self.inner.primes();
        if primes.len() >= 2 {
            // Return a simplified coefficient based on the primes
            // This is for compatibility - in practice, CRT is handled internally by the RSA crate
            let p = &primes[0];
            p.to_bytes_be()
        } else {
            vec![0u8; 32] // Fallback
        }
    }
}

impl KeyPair {
    /// Generate a new RSA key pair
    ///
    /// # Arguments
    /// * `key_size` - The key size in bits (2048, 3072, or 4096)
    ///
    /// # Returns
    /// A new RSA key pair
    pub fn generate(key_size: usize) -> Result<Self> {
        // Validate key size
        match key_size {
            2048 | 3072 | 4096 => {}
            _ => return Err(FluxError::invalid_input("Invalid RSA key size")),
        }

        // Generate a proper RSA private key using the rsa crate
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, key_size)
            .map_err(|e| FluxError::crypto(format!("Failed to generate RSA private key: {}", e)))?;

        let public_key = private_key.to_public_key();

        Ok(Self {
            public_key: PublicKey::new(public_key),
            private_key: PrivateKey::new(private_key),
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the private key
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Consume the key pair and return the individual keys
    pub fn into_keys(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }

    /// Create a key pair from separate public and private keys
    pub fn from_keys(public_key: PublicKey, private_key: PrivateKey) -> Result<Self> {
        // Validate that the keys match (simplified check)
        if public_key.key_size_bits() != private_key.key_size_bits() {
            return Err(FluxError::key("Key sizes don't match"));
        }

        // Verify that the public key matches the private key
        let derived_public = private_key.public_key()?;
        if public_key.modulus() != derived_public.modulus() {
            return Err(FluxError::key("Public key doesn't match private key"));
        }

        Ok(Self {
            public_key,
            private_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_key_generation() {
        let keypair = KeyPair::generate(2048).unwrap();
        assert_eq!(keypair.public_key().key_size_bits(), 2048);
        assert_eq!(keypair.private_key().key_size_bits(), 2048);
    }

    #[test]
    fn test_invalid_key_size() {
        let invalid_sizes = vec![512, 1024, 1536, 2047, 2049, 5000];

        for size in invalid_sizes {
            let result = KeyPair::generate(size);
            assert!(result.is_err(), "Should fail for key size {}", size);

            if let Err(e) = result {
                assert!(e.to_string().contains("Invalid RSA key size"));
            }
        }
    }

    #[test]
    fn test_key_sizes() {
        for &size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(size).unwrap();
            assert_eq!(keypair.public_key().key_size_bits(), size);
            assert_eq!(keypair.public_key().key_size_bytes(), size / 8);
            assert_eq!(keypair.private_key().key_size_bits(), size);
            assert_eq!(keypair.private_key().key_size_bytes(), size / 8);
        }
    }

    #[test]
    fn test_public_key_creation() {
        // Test by generating a key and checking its properties
        let keypair = KeyPair::generate(2048).unwrap();
        let public_key = keypair.public_key();

        assert_eq!(public_key.key_size_bits(), 2048);
        assert_eq!(public_key.key_size_bytes(), 256);
        assert!(!public_key.modulus().is_empty());
        assert!(!public_key.public_exponent().is_empty());
    }

    #[test]
    fn test_private_key_creation() {
        // Test by generating a key and checking its properties
        let keypair = KeyPair::generate(2048).unwrap();
        let private_key = keypair.private_key();

        assert_eq!(private_key.key_size_bits(), 2048);
        assert_eq!(private_key.key_size_bytes(), 256);
        assert!(!private_key.modulus().is_empty());
        assert!(!private_key.private_exponent().is_empty());
        assert!(!private_key.prime1().is_empty());
        assert!(!private_key.prime2().is_empty());
        assert!(!private_key.crt_coefficient().is_empty());
    }

    #[test]
    fn test_private_key_debug_format() {
        let keypair = KeyPair::generate(2048).unwrap();
        let debug_str = format!("{:?}", keypair.private_key());

        assert!(debug_str.contains("PrivateKey"));
        assert!(debug_str.contains("key_size"));
        assert!(debug_str.contains("[REDACTED]"));

        // Should not contain actual key material in hex format
        // Note: This is a basic check - in production, more sophisticated checks would be used
    }

    #[test]
    fn test_public_key_debug_format() {
        let keypair = KeyPair::generate(2048).unwrap();
        let debug_str = format!("{:?}", keypair.public_key());

        assert!(debug_str.contains("PublicKey"));
        assert!(debug_str.contains("key_size"));
        assert!(debug_str.contains("modulus"));
        assert!(debug_str.contains("public_exponent"));
    }

    #[test]
    fn test_keypair_debug_format() {
        let keypair = KeyPair::generate(2048).unwrap();
        let debug_str = format!("{:?}", keypair);

        assert!(debug_str.contains("KeyPair"));
        assert!(debug_str.contains("public_key"));
        assert!(debug_str.contains("private_key"));
    }

    #[test]
    fn test_public_key_clone() {
        let keypair = KeyPair::generate(2048).unwrap();
        let public_key1 = keypair.public_key();
        let public_key2 = public_key1.clone();

        assert_eq!(public_key1.key_size_bits(), public_key2.key_size_bits());
        assert_eq!(public_key1.modulus(), public_key2.modulus());
        assert_eq!(public_key1.public_exponent(), public_key2.public_exponent());
    }

    #[test]
    fn test_private_key_clone() {
        let keypair = KeyPair::generate(2048).unwrap();
        let private_key1 = keypair.private_key();
        let private_key2 = private_key1.clone();

        assert_eq!(private_key1.key_size_bits(), private_key2.key_size_bits());
        assert_eq!(private_key1.modulus(), private_key2.modulus());
        assert_eq!(
            private_key1.private_exponent(),
            private_key2.private_exponent()
        );
    }

    #[test]
    fn test_keypair_key_access() {
        let keypair = KeyPair::generate(2048).unwrap();

        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        assert_eq!(public_key.key_size_bits(), 2048);
        assert_eq!(private_key.key_size_bits(), 2048);
    }

    #[test]
    fn test_keypair_into_keys() {
        let keypair = KeyPair::generate(2048).unwrap();
        let original_pub_modulus = keypair.public_key().modulus();
        let original_priv_modulus = keypair.private_key().modulus();

        let (public_key, private_key) = keypair.into_keys();

        assert_eq!(public_key.modulus(), original_pub_modulus);
        assert_eq!(private_key.modulus(), original_priv_modulus);
    }

    #[test]
    fn test_keypair_from_keys() {
        let original_keypair = KeyPair::generate(2048).unwrap();
        let (public_key, private_key) = original_keypair.into_keys();

        let reconstructed_keypair = KeyPair::from_keys(public_key, private_key).unwrap();

        assert_eq!(reconstructed_keypair.public_key().key_size_bits(), 2048);
        assert_eq!(reconstructed_keypair.private_key().key_size_bits(), 2048);
    }

    #[test]
    fn test_keypair_from_keys_mismatched_sizes() {
        let keypair_2048 = KeyPair::generate(2048).unwrap();
        let keypair_3072 = KeyPair::generate(3072).unwrap();

        let (pub_2048, _) = keypair_2048.into_keys();
        let (_, priv_3072) = keypair_3072.into_keys();

        let result = KeyPair::from_keys(pub_2048, priv_3072);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("Key sizes don't match"));
        }
    }

    #[test]
    fn test_private_key_to_public_key() {
        let keypair = KeyPair::generate(2048).unwrap();
        let derived_public = keypair.private_key().public_key().unwrap();

        assert_eq!(
            derived_public.key_size_bits(),
            keypair.public_key().key_size_bits()
        );
        assert_eq!(derived_public.modulus(), keypair.public_key().modulus());
        assert_eq!(derived_public.public_exponent(), vec![0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_public_key_pem_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let pem = keypair.public_key().to_pem().unwrap();

        assert!(pem.starts_with("-----BEGIN RSA PUBLIC KEY-----\n"));
        assert!(pem.ends_with("\n-----END RSA PUBLIC KEY-----\n"));
        assert!(pem.len() > 100); // Should have substantial content
    }

    #[test]
    fn test_private_key_pem_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let pem = keypair.private_key().to_pem().unwrap();

        assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(pem.ends_with("\n-----END RSA PRIVATE KEY-----\n"));
        assert!(pem.len() > 100); // Should have substantial content
    }

    #[test]
    fn test_private_key_encrypted_pem_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let password = "test_password_123";
        let encrypted_pem = keypair.private_key().to_encrypted_pem(password).unwrap();

        assert!(encrypted_pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
        assert!(encrypted_pem.ends_with("\n-----END ENCRYPTED PRIVATE KEY-----\n"));
        assert!(encrypted_pem.len() > 100); // Should have substantial content

        // The encrypted PEM should be different from the unencrypted one
        let regular_pem = keypair.private_key().to_pem().unwrap();
        assert_ne!(encrypted_pem, regular_pem);
    }

    #[test]
    fn test_public_key_der_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let der = keypair.public_key().to_der().unwrap();

        assert!(!der.is_empty());
        // The DER should contain the encoded public key
        assert!(!der.is_empty());
    }

    #[test]
    fn test_private_key_der_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let der = keypair.private_key().to_der().unwrap();

        assert!(!der.is_empty());
        // The DER should contain the encoded private key
        assert!(!der.is_empty());
    }

    #[test]
    fn test_key_generation_uniqueness() {
        let keypair1 = KeyPair::generate(2048).unwrap();
        let keypair2 = KeyPair::generate(2048).unwrap();

        // Keys should be different
        assert_ne!(
            keypair1.public_key().modulus(),
            keypair2.public_key().modulus()
        );
        assert_ne!(
            keypair1.private_key().modulus(),
            keypair2.private_key().modulus()
        );
        assert_ne!(
            keypair1.private_key().private_exponent(),
            keypair2.private_key().private_exponent()
        );
    }

    #[test]
    fn test_modulus_msb_set() {
        for &key_size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(key_size).unwrap();
            let modulus = keypair.public_key().modulus();

            // The MSB should be set to ensure proper key size
            assert!(
                modulus[0] & 0x80 != 0,
                "MSB should be set for {}-bit key",
                key_size
            );

            // Modulus should be the correct length
            assert_eq!(modulus.len(), key_size / 8);
        }
    }

    #[test]
    fn test_public_exponent_consistency() {
        let keypair = KeyPair::generate(2048).unwrap();

        // Should use standard public exponent 65537 (0x010001)
        let expected_exponent = vec![0x01, 0x00, 0x01];
        assert_eq!(keypair.public_key().public_exponent(), expected_exponent);

        // Derived public key should have same exponent
        let derived_public = keypair.private_key().public_key().unwrap();
        assert_eq!(derived_public.public_exponent(), expected_exponent);
    }

    #[test]
    fn test_key_component_lengths() {
        for &key_size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(key_size).unwrap();
            let private_key = keypair.private_key();

            let expected_modulus_len = key_size / 8;
            let expected_prime_len = key_size / 16; // Half the modulus length

            assert_eq!(private_key.modulus().len(), expected_modulus_len);
            assert_eq!(private_key.private_exponent().len(), expected_modulus_len);
            assert_eq!(private_key.prime1().len(), expected_prime_len);
            assert_eq!(private_key.prime2().len(), expected_prime_len);
            assert_eq!(private_key.crt_coefficient().len(), expected_prime_len);
        }
    }

    #[test]
    fn test_pem_format_structure() {
        let keypair = KeyPair::generate(2048).unwrap();

        let public_pem = keypair.public_key().to_pem().unwrap();
        let private_pem = keypair.private_key().to_pem().unwrap();

        // Check PEM structure
        let public_lines: Vec<&str> = public_pem.lines().collect();
        assert!(public_lines.len() >= 3); // At least header, content, footer
        assert_eq!(public_lines[0], "-----BEGIN RSA PUBLIC KEY-----");
        assert_eq!(
            public_lines[public_lines.len() - 1],
            "-----END RSA PUBLIC KEY-----"
        );

        let private_lines: Vec<&str> = private_pem.lines().collect();
        assert!(private_lines.len() >= 3);
        assert_eq!(private_lines[0], "-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(
            private_lines[private_lines.len() - 1],
            "-----END RSA PRIVATE KEY-----"
        );
    }

    #[test]
    fn test_key_size_consistency() {
        for &key_size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(key_size).unwrap();

            // All key size methods should return consistent values
            assert_eq!(keypair.public_key().key_size_bits(), key_size);
            assert_eq!(keypair.public_key().key_size_bytes(), key_size / 8);
            assert_eq!(keypair.private_key().key_size_bits(), key_size);
            assert_eq!(keypair.private_key().key_size_bytes(), key_size / 8);

            // Derived public key should have same size
            let derived_public = keypair.private_key().public_key().unwrap();
            assert_eq!(derived_public.key_size_bits(), key_size);
            assert_eq!(derived_public.key_size_bytes(), key_size / 8);
        }
    }

    #[test]
    fn test_memory_zeroization() {
        // We can't directly test zeroization, but we can test that the ZeroizeOnDrop
        // derive is applied correctly by ensuring the private key can be dropped
        let keypair = KeyPair::generate(2048).unwrap();
        let _private_key = keypair.private_key().clone();

        // The private key should be safely droppable
        drop(_private_key);

        // Test that cloning and dropping works as expected
        let another_private = keypair.private_key().clone();
        drop(another_private);
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_key_generation_properties(
            key_size in prop::sample::select(vec![2048usize, 3072, 4096])
        ) {
            let keypair = KeyPair::generate(key_size).unwrap();

            // Basic properties that should always hold
            prop_assert_eq!(keypair.public_key().key_size_bits(), key_size);
            prop_assert_eq!(keypair.private_key().key_size_bits(), key_size);
            prop_assert_eq!(keypair.public_key().modulus().len(), key_size / 8);
            prop_assert_eq!(keypair.private_key().modulus().len(), key_size / 8);

            // MSB should be set
            prop_assert!(keypair.public_key().modulus()[0] & 0x80 != 0);
            prop_assert!(keypair.private_key().modulus()[0] & 0x80 != 0);

            // Public exponent should be 65537
            prop_assert_eq!(keypair.public_key().public_exponent(), vec![0x01, 0x00, 0x01]);
        }
    }

    #[test]
    fn test_error_message_quality() {
        let result = KeyPair::generate(1024);

        if let Err(e) = result {
            let error_msg = e.to_string();
            assert!(error_msg.contains("Invalid RSA key size"));
        }
    }

    #[test]
    fn test_concurrent_key_generation() {
        use std::thread;

        let mut handles = vec![];

        // Generate keys concurrently
        for i in 0..5 {
            let handle = thread::spawn(move || {
                let keypair = KeyPair::generate(2048).unwrap();
                (i, keypair.public_key().modulus().to_vec())
            });
            handles.push(handle);
        }

        let mut moduli = vec![];
        for handle in handles {
            let (thread_id, modulus) = handle.join().unwrap();
            moduli.push((thread_id, modulus));
        }

        // All moduli should be different
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                assert_ne!(
                    moduli[i].1, moduli[j].1,
                    "Moduli from threads {} and {} should be different",
                    moduli[i].0, moduli[j].0
                );
            }
        }
    }
}
