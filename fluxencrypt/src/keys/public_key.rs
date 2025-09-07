//! RSA public key functionality.

use crate::error::{FluxError, Result};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;

/// An RSA public key
#[derive(Clone)]
pub struct PublicKey {
    /// The underlying RSA public key
    inner: RsaPublicKey,
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

#[cfg(test)]
mod tests {
    use crate::keys::KeyPair;

    #[test]
    fn test_public_key_creation() {
        let keypair = KeyPair::generate(2048).unwrap();
        let public_key = keypair.public_key();

        assert_eq!(public_key.key_size_bits(), 2048);
        assert_eq!(public_key.key_size_bytes(), 256);
        assert!(!public_key.modulus().is_empty());
        assert!(!public_key.public_exponent().is_empty());
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
    fn test_public_key_clone() {
        let keypair = KeyPair::generate(2048).unwrap();
        let public_key1 = keypair.public_key();
        let public_key2 = public_key1.clone();

        assert_eq!(public_key1.key_size_bits(), public_key2.key_size_bits());
        assert_eq!(public_key1.modulus(), public_key2.modulus());
        assert_eq!(public_key1.public_exponent(), public_key2.public_exponent());
    }

    #[test]
    fn test_public_key_pem_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let pem = keypair.public_key().to_pem().unwrap();

        assert!(pem.starts_with("-----BEGIN RSA PUBLIC KEY-----\n"));
        assert!(pem.ends_with("\n-----END RSA PUBLIC KEY-----\n"));
        assert!(pem.len() > 100);
    }

    #[test]
    fn test_public_key_der_export() {
        let keypair = KeyPair::generate(2048).unwrap();
        let der = keypair.public_key().to_der().unwrap();

        assert!(!der.is_empty());
    }

    #[test]
    fn test_public_exponent_consistency() {
        let keypair = KeyPair::generate(2048).unwrap();

        // Should use standard public exponent 65537 (0x010001)
        let expected_exponent = vec![0x01, 0x00, 0x01];
        assert_eq!(keypair.public_key().public_exponent(), expected_exponent);
    }

    #[test]
    fn test_key_size_consistency() {
        for &key_size in &[2048, 3072, 4096] {
            let keypair = KeyPair::generate(key_size).unwrap();

            assert_eq!(keypair.public_key().key_size_bits(), key_size);
            assert_eq!(keypair.public_key().key_size_bytes(), key_size / 8);
        }
    }

    #[test]
    fn test_pem_format_structure() {
        let keypair = KeyPair::generate(2048).unwrap();
        let public_pem = keypair.public_key().to_pem().unwrap();

        let public_lines: Vec<&str> = public_pem.lines().collect();
        assert!(public_lines.len() >= 3);
        assert_eq!(public_lines[0], "-----BEGIN RSA PUBLIC KEY-----");
        assert_eq!(
            public_lines[public_lines.len() - 1],
            "-----END RSA PUBLIC KEY-----"
        );
    }
}
