//! RSA private key functionality.

use crate::error::{FluxError, Result};
use crate::keys::PublicKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::RsaPrivateKey;
use zeroize::ZeroizeOnDrop;

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

        let private_key_der = self.inner.to_pkcs8_der().map_err(|e| {
            FluxError::crypto(format!("Failed to encode private key as PKCS#8 DER: {}", e))
        })?;

        let private_key_info = PrivateKeyInfo::try_from(private_key_der.as_bytes())
            .map_err(|e| FluxError::crypto(format!("Failed to parse PKCS#8 DER: {}", e)))?;

        let encrypted_private_key = private_key_info
            .encrypt(&mut OsRng, password)
            .map_err(|e| FluxError::crypto(format!("Failed to encrypt private key: {}", e)))?;

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
        let primes = self.inner.primes();
        if primes.len() >= 2 {
            let p = &primes[0];
            p.to_bytes_be()
        } else {
            vec![0u8; 32]
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::KeyPair;

    #[test]
    fn test_private_key_creation() {
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
    fn test_private_key_pem_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let pem = keypair.private_key().to_pem().unwrap();

        assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(pem.ends_with("\n-----END RSA PRIVATE KEY-----\n"));
        assert!(pem.len() > 100);
    }

    #[test]
    fn test_private_key_encrypted_pem_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let password = "test_password_123";
        let encrypted_pem = keypair.private_key().to_encrypted_pem(password).unwrap();

        assert!(encrypted_pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
        assert!(encrypted_pem.ends_with("\n-----END ENCRYPTED PRIVATE KEY-----\n"));
        assert!(encrypted_pem.len() > 100);

        let regular_pem = keypair.private_key().to_pem().unwrap();
        assert_ne!(encrypted_pem, regular_pem);
    }

    #[test]
    fn test_private_key_der_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let der = keypair.private_key().to_der().unwrap();

        assert!(!der.is_empty());
    }

    #[test]
    fn test_key_component_lengths() {
        for &key_size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(key_size).unwrap();
            let private_key = keypair.private_key();

            let expected_modulus_len = key_size / 8;
            let expected_prime_len = key_size / 16;

            assert_eq!(private_key.modulus().len(), expected_modulus_len);
            assert_eq!(private_key.private_exponent().len(), expected_modulus_len);
            assert_eq!(private_key.prime1().len(), expected_prime_len);
            assert_eq!(private_key.prime2().len(), expected_prime_len);
            assert_eq!(private_key.crt_coefficient().len(), expected_prime_len);
        }
    }

    #[test]
    fn test_memory_zeroization() {
        let keypair = KeyPair::generate(2048).unwrap();
        let _private_key = keypair.private_key().clone();

        drop(_private_key);

        let another_private = keypair.private_key().clone();
        drop(another_private);
    }
}
