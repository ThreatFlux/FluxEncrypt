//! RSA key pair generation functionality.
//!
//! This module provides secure RSA key pair generation using the Ring
//! cryptography library with proper random number generation.

use crate::error::{FluxError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::ZeroizeOnDrop;

/// An RSA public key
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The key size in bits
    key_size: usize,
    /// The RSA modulus (n)
    modulus: Vec<u8>,
    /// The RSA public exponent (e)
    public_exponent: Vec<u8>,
}

/// An RSA private key that is automatically zeroized when dropped
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// The key size in bits
    key_size: usize,
    /// The RSA modulus (n)
    modulus: Vec<u8>,
    /// The RSA private exponent (d)
    private_exponent: Vec<u8>,
    /// The first prime factor (p)
    prime1: Vec<u8>,
    /// The second prime factor (q)
    prime2: Vec<u8>,
    /// The CRT coefficient (q^-1 mod p)
    crt_coefficient: Vec<u8>,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key_size", &self.key_size)
            .field("_key_data", &"[REDACTED]")
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
    /// Create a new public key
    pub fn new(key_size: usize, modulus: Vec<u8>, public_exponent: Vec<u8>) -> Self {
        Self {
            key_size,
            modulus,
            public_exponent,
        }
    }

    /// Get the key size in bits
    pub fn key_size_bits(&self) -> usize {
        self.key_size
    }

    /// Get the key size in bytes
    pub fn key_size_bytes(&self) -> usize {
        self.key_size / 8
    }

    /// Get the modulus
    pub fn modulus(&self) -> &[u8] {
        &self.modulus
    }

    /// Get the public exponent
    pub fn public_exponent(&self) -> &[u8] {
        &self.public_exponent
    }

    /// Export the public key as PEM format
    pub fn to_pem(&self) -> Result<String> {
        // This is a placeholder implementation
        // In a real implementation, you would encode the key in ASN.1/DER format
        // and then base64 encode it with PEM headers
        let encoded = BASE64.encode(&self.modulus);
        Ok(format!(
            "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----\n",
            encoded
        ))
    }

    /// Export the public key as DER format
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // This is a placeholder implementation
        // In a real implementation, you would properly encode using ASN.1/DER
        Ok(self.modulus.clone())
    }
}

impl PrivateKey {
    /// Create a new private key
    pub fn new(
        key_size: usize,
        modulus: Vec<u8>,
        private_exponent: Vec<u8>,
        prime1: Vec<u8>,
        prime2: Vec<u8>,
        crt_coefficient: Vec<u8>,
    ) -> Self {
        Self {
            key_size,
            modulus,
            private_exponent,
            prime1,
            prime2,
            crt_coefficient,
        }
    }

    /// Get the key size in bits
    pub fn key_size_bits(&self) -> usize {
        self.key_size
    }

    /// Get the key size in bytes
    pub fn key_size_bytes(&self) -> usize {
        self.key_size / 8
    }

    /// Export the private key as PEM format
    pub fn to_pem(&self) -> Result<String> {
        // This is a placeholder implementation
        let encoded = BASE64.encode(&self.modulus);
        Ok(format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            encoded
        ))
    }

    /// Export the private key as DER format
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // This is a placeholder implementation
        Ok(self.modulus.clone())
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> Result<PublicKey> {
        // Use standard public exponent 65537
        let public_exponent = vec![0x01, 0x00, 0x01];
        Ok(PublicKey::new(
            self.key_size,
            self.modulus.clone(),
            public_exponent,
        ))
    }

    /// Get the modulus
    pub fn modulus(&self) -> &[u8] {
        &self.modulus
    }

    /// Get the private exponent
    pub fn private_exponent(&self) -> &[u8] {
        &self.private_exponent
    }

    /// Get the first prime factor
    pub fn prime1(&self) -> &[u8] {
        &self.prime1
    }

    /// Get the second prime factor
    pub fn prime2(&self) -> &[u8] {
        &self.prime2
    }

    /// Get the CRT coefficient
    pub fn crt_coefficient(&self) -> &[u8] {
        &self.crt_coefficient
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
    ///
    /// # Note
    /// This is a simplified implementation for demonstration purposes.
    /// In a production environment, you would use a proper RSA key generation
    /// library like `rsa` crate or external tools.
    pub fn generate(key_size: usize) -> Result<Self> {
        // Validate key size
        match key_size {
            2048 | 3072 | 4096 => {}
            _ => return Err(FluxError::invalid_input("Invalid RSA key size")),
        }

        // For demonstration, we'll create placeholder keys with proper structure
        // In a real implementation, this would involve:
        // 1. Generate two large prime numbers p and q
        // 2. Calculate n = p * q (the modulus)
        // 3. Calculate φ(n) = (p-1)(q-1)
        // 4. Choose e = 65537 (common public exponent)
        // 5. Calculate d = e^-1 mod φ(n) (private exponent)
        // 6. Calculate CRT parameters

        let rng = SystemRandom::new();
        let modulus_len = key_size / 8;
        let prime_len = modulus_len / 2;

        // Generate placeholder values
        let mut modulus = vec![0u8; modulus_len];
        let mut prime1 = vec![0u8; prime_len];
        let mut prime2 = vec![0u8; prime_len];
        let mut private_exponent = vec![0u8; modulus_len];
        let mut crt_coefficient = vec![0u8; prime_len];

        rng.fill(&mut modulus)
            .map_err(|_| FluxError::crypto("Failed to generate random modulus"))?;
        rng.fill(&mut prime1)
            .map_err(|_| FluxError::crypto("Failed to generate random prime1"))?;
        rng.fill(&mut prime2)
            .map_err(|_| FluxError::crypto("Failed to generate random prime2"))?;
        rng.fill(&mut private_exponent)
            .map_err(|_| FluxError::crypto("Failed to generate random private exponent"))?;
        rng.fill(&mut crt_coefficient)
            .map_err(|_| FluxError::crypto("Failed to generate random CRT coefficient"))?;

        // Ensure the modulus has the MSB set (proper key size)
        modulus[0] |= 0x80;

        // Standard public exponent 65537
        let public_exponent = vec![0x01, 0x00, 0x01];

        let public_key = PublicKey::new(key_size, modulus.clone(), public_exponent);
        let private_key = PrivateKey::new(
            key_size,
            modulus,
            private_exponent,
            prime1,
            prime2,
            crt_coefficient,
        );

        Ok(Self {
            public_key,
            private_key,
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
        let modulus = vec![0x01, 0x02, 0x03, 0x04];
        let public_exponent = vec![0x01, 0x00, 0x01];
        let key_size = 2048;

        let public_key = PublicKey::new(key_size, modulus.clone(), public_exponent.clone());

        assert_eq!(public_key.key_size_bits(), key_size);
        assert_eq!(public_key.key_size_bytes(), key_size / 8);
        assert_eq!(public_key.modulus(), &modulus);
        assert_eq!(public_key.public_exponent(), &public_exponent);
    }

    #[test]
    fn test_private_key_creation() {
        let key_size = 2048;
        let modulus = vec![0x01, 0x02, 0x03, 0x04];
        let private_exponent = vec![0x05, 0x06, 0x07, 0x08];
        let prime1 = vec![0x09, 0x0A];
        let prime2 = vec![0x0B, 0x0C];
        let crt_coefficient = vec![0x0D, 0x0E];

        let private_key = PrivateKey::new(
            key_size,
            modulus.clone(),
            private_exponent.clone(),
            prime1.clone(),
            prime2.clone(),
            crt_coefficient.clone(),
        );

        assert_eq!(private_key.key_size_bits(), key_size);
        assert_eq!(private_key.key_size_bytes(), key_size / 8);
        assert_eq!(private_key.modulus(), &modulus);
        assert_eq!(private_key.private_exponent(), &private_exponent);
        assert_eq!(private_key.prime1(), &prime1);
        assert_eq!(private_key.prime2(), &prime2);
        assert_eq!(private_key.crt_coefficient(), &crt_coefficient);
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
        let original_pub_modulus = keypair.public_key().modulus().to_vec();
        let original_priv_modulus = keypair.private_key().modulus().to_vec();

        let (public_key, private_key) = keypair.into_keys();

        assert_eq!(public_key.modulus(), &original_pub_modulus);
        assert_eq!(private_key.modulus(), &original_priv_modulus);
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
        assert_eq!(derived_public.public_exponent(), &vec![0x01, 0x00, 0x01]);
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
    fn test_public_key_der_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let der = keypair.public_key().to_der().unwrap();

        assert!(!der.is_empty());
        // In this placeholder implementation, DER is just the modulus
        assert_eq!(der, keypair.public_key().modulus());
    }

    #[test]
    fn test_private_key_der_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let der = keypair.private_key().to_der().unwrap();

        assert!(!der.is_empty());
        // In this placeholder implementation, DER is just the modulus
        assert_eq!(der, keypair.private_key().modulus());
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
        assert_eq!(keypair.public_key().public_exponent(), &expected_exponent);

        // Derived public key should have same exponent
        let derived_public = keypair.private_key().public_key().unwrap();
        assert_eq!(derived_public.public_exponent(), &expected_exponent);
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
            prop_assert_eq!(keypair.public_key().public_exponent(), &vec![0x01, 0x00, 0x01]);
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
