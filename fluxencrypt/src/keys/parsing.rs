//! Key parsing functionality for various formats.
//!
//! This module provides functionality to parse RSA keys from different
//! formats including PEM, DER, and PKCS#8.

use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Key format enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// PEM format (Base64 encoded with headers)
    Pem,
    /// DER format (Binary ASN.1)
    Der,
    /// PKCS#8 format
    Pkcs8,
    /// SSH public key format
    Ssh,
}

/// Key parser for various formats
#[derive(Debug)]
pub struct KeyParser;

impl KeyParser {
    /// Create a new key parser
    pub fn new() -> Self {
        Self
    }

    /// Parse a public key from bytes
    ///
    /// # Arguments
    /// * `data` - The key data
    /// * `format` - The format of the key data
    ///
    /// # Returns
    /// The parsed public key
    pub fn parse_public_key(&self, data: &[u8], format: KeyFormat) -> Result<PublicKey> {
        match format {
            KeyFormat::Pem => self.parse_public_key_pem(data),
            KeyFormat::Der => self.parse_public_key_der(data),
            KeyFormat::Pkcs8 => self.parse_public_key_pkcs8(data),
            KeyFormat::Ssh => Err(FluxError::invalid_input("SSH format not yet supported")),
        }
    }

    /// Parse a private key from bytes
    ///
    /// # Arguments
    /// * `data` - The key data
    /// * `format` - The format of the key data
    ///
    /// # Returns
    /// The parsed private key
    pub fn parse_private_key(&self, data: &[u8], format: KeyFormat) -> Result<PrivateKey> {
        match format {
            KeyFormat::Pem => self.parse_private_key_pem(data),
            KeyFormat::Der => self.parse_private_key_der(data),
            KeyFormat::Pkcs8 => self.parse_private_key_pkcs8(data),
            KeyFormat::Ssh => Err(FluxError::invalid_input(
                "SSH format not supported for private keys",
            )),
        }
    }

    /// Auto-detect the key format from data
    pub fn detect_format(&self, data: &[u8]) -> Option<KeyFormat> {
        // Check for PEM format (starts with "-----BEGIN")
        if data.starts_with(b"-----BEGIN") {
            return Some(KeyFormat::Pem);
        }

        // For binary data, assume DER/PKCS8
        // More sophisticated detection would examine the ASN.1 structure
        Some(KeyFormat::Der)
    }

    /// Parse a public key from PEM format (try PKCS1 first, then PKCS8)
    fn parse_public_key_pem(&self, data: &[u8]) -> Result<PublicKey> {
        let pem_str = std::str::from_utf8(data)
            .map_err(|_| FluxError::invalid_input("Invalid UTF-8 in PEM data"))?;

        // Try PKCS1 format first (RSA PUBLIC KEY header)
        use rsa::pkcs1::DecodeRsaPublicKey;
        let rsa_public_key = RsaPublicKey::from_pkcs1_pem(pem_str)
            .or_else(|_| {
                // Fallback to PKCS8 format (PUBLIC KEY header)
                use rsa::pkcs8::DecodePublicKey;
                RsaPublicKey::from_public_key_pem(pem_str)
            })
            .map_err(|e| FluxError::crypto(format!("Failed to parse PEM public key: {}", e)))?;

        Ok(PublicKey::new(rsa_public_key))
    }

    /// Parse a public key from DER format (try PKCS1 first, then PKCS8)
    fn parse_public_key_der(&self, data: &[u8]) -> Result<PublicKey> {
        // Try PKCS1 format first
        use rsa::pkcs1::DecodeRsaPublicKey;
        let rsa_public_key = RsaPublicKey::from_pkcs1_der(data)
            .or_else(|_| {
                // Fallback to PKCS8 format
                use rsa::pkcs8::DecodePublicKey;
                RsaPublicKey::from_public_key_der(data)
            })
            .map_err(|e| FluxError::crypto(format!("Failed to parse DER public key: {}", e)))?;

        Ok(PublicKey::new(rsa_public_key))
    }

    /// Parse a public key from PKCS#8 format
    fn parse_public_key_pkcs8(&self, data: &[u8]) -> Result<PublicKey> {
        // Try DER first, then PEM if that fails
        match RsaPublicKey::from_public_key_der(data) {
            Ok(key) => Ok(PublicKey::new(key)),
            Err(_) => {
                let pem_str = std::str::from_utf8(data)
                    .map_err(|_| FluxError::invalid_input("Invalid UTF-8 in PKCS#8 data"))?;

                let rsa_public_key = RsaPublicKey::from_public_key_pem(pem_str).map_err(|e| {
                    FluxError::crypto(format!("Failed to parse PKCS#8 public key: {}", e))
                })?;

                Ok(PublicKey::new(rsa_public_key))
            }
        }
    }

    /// Parse a private key from PEM format
    fn parse_private_key_pem(&self, data: &[u8]) -> Result<PrivateKey> {
        let pem_str = std::str::from_utf8(data)
            .map_err(|_| FluxError::invalid_input("Invalid UTF-8 in PEM data"))?;

        let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(pem_str)
            .or_else(|_| {
                // Try PKCS#1 format as fallback
                use rsa::pkcs1::DecodeRsaPrivateKey;
                RsaPrivateKey::from_pkcs1_pem(pem_str)
            })
            .map_err(|e| FluxError::crypto(format!("Failed to parse PEM private key: {}", e)))?;

        Ok(PrivateKey::new(rsa_private_key))
    }

    /// Parse a private key from DER format
    fn parse_private_key_der(&self, data: &[u8]) -> Result<PrivateKey> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(data)
            .or_else(|_| {
                // Try PKCS#1 format as fallback
                use rsa::pkcs1::DecodeRsaPrivateKey;
                RsaPrivateKey::from_pkcs1_der(data)
            })
            .map_err(|e| FluxError::crypto(format!("Failed to parse DER private key: {}", e)))?;

        Ok(PrivateKey::new(rsa_private_key))
    }

    /// Parse a private key from PKCS#8 format
    fn parse_private_key_pkcs8(&self, data: &[u8]) -> Result<PrivateKey> {
        // Try DER first, then PEM if that fails
        match RsaPrivateKey::from_pkcs8_der(data) {
            Ok(key) => Ok(PrivateKey::new(key)),
            Err(_) => {
                let pem_str = std::str::from_utf8(data)
                    .map_err(|_| FluxError::invalid_input("Invalid UTF-8 in PKCS#8 data"))?;

                let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(pem_str).map_err(|e| {
                    FluxError::crypto(format!("Failed to parse PKCS#8 private key: {}", e))
                })?;

                Ok(PrivateKey::new(rsa_private_key))
            }
        }
    }
}

impl Default for KeyParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to parse a public key from a PEM string
pub fn parse_public_key_from_str(pem_str: &str) -> Result<PublicKey> {
    let parser = KeyParser::new();
    parser.parse_public_key(pem_str.as_bytes(), KeyFormat::Pem)
}

/// Convenience function to parse a private key from a PEM string
pub fn parse_private_key_from_str(pem_str: &str) -> Result<PrivateKey> {
    let parser = KeyParser::new();
    parser.parse_private_key(pem_str.as_bytes(), KeyFormat::Pem)
}

/// Convenience function to parse an encrypted private key from a PEM string
pub fn parse_encrypted_private_key_from_str(pem_str: &str, password: &str) -> Result<PrivateKey> {
    use pkcs8::DecodePrivateKey;

    // Parse the encrypted private key PEM and decrypt it
    let rsa_private_key = RsaPrivateKey::from_pkcs8_encrypted_pem(pem_str, password)
        .map_err(|e| FluxError::crypto(format!("Failed to parse encrypted private key: {}", e)))?;

    Ok(PrivateKey::new(rsa_private_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_format_detection() {
        let parser = KeyParser::new();

        // Test PEM detection
        let pem_data = b"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----";
        assert_eq!(parser.detect_format(pem_data), Some(KeyFormat::Pem));

        // Test DER detection (binary data)
        let der_data = b"\x30\x82\x01\x22";
        assert_eq!(parser.detect_format(der_data), Some(KeyFormat::Der));
    }

    #[test]
    fn test_roundtrip_with_generated_keys() {
        let keypair = KeyPair::generate(2048).unwrap();
        let parser = KeyParser::new();

        // Test public key PEM roundtrip
        let public_pem = keypair.public_key().to_pem().unwrap();
        let parsed_public = parser
            .parse_public_key(public_pem.as_bytes(), KeyFormat::Pem)
            .unwrap();
        assert_eq!(parsed_public.modulus(), keypair.public_key().modulus());

        // Test private key PEM roundtrip
        let private_pem = keypair.private_key().to_pem().unwrap();
        let parsed_private = parser
            .parse_private_key(private_pem.as_bytes(), KeyFormat::Pem)
            .unwrap();
        assert_eq!(parsed_private.modulus(), keypair.private_key().modulus());

        // Test public key DER roundtrip
        let public_der = keypair.public_key().to_der().unwrap();
        let parsed_public_der = parser
            .parse_public_key(&public_der, KeyFormat::Der)
            .unwrap();
        assert_eq!(parsed_public_der.modulus(), keypair.public_key().modulus());

        // Test private key DER roundtrip
        let private_der = keypair.private_key().to_der().unwrap();
        let parsed_private_der = parser
            .parse_private_key(&private_der, KeyFormat::Der)
            .unwrap();
        assert_eq!(
            parsed_private_der.modulus(),
            keypair.private_key().modulus()
        );
    }

    #[test]
    fn test_invalid_data() {
        let parser = KeyParser::new();

        // Test invalid PEM
        let invalid_pem = b"not a pem key";
        assert!(parser
            .parse_public_key(invalid_pem, KeyFormat::Pem)
            .is_err());

        // Test invalid DER
        let invalid_der = b"not der data";
        assert!(parser
            .parse_public_key(invalid_der, KeyFormat::Der)
            .is_err());
    }

    #[test]
    fn test_ssh_format_not_supported() {
        let parser = KeyParser::new();
        let dummy_data = b"ssh-rsa ...";

        assert!(parser.parse_public_key(dummy_data, KeyFormat::Ssh).is_err());
        assert!(parser
            .parse_private_key(dummy_data, KeyFormat::Ssh)
            .is_err());
    }

    #[test]
    fn test_parser_creation() {
        let parser1 = KeyParser::new();
        let parser2 = KeyParser;

        assert!(format!("{:?}", parser1).contains("KeyParser"));
        assert!(format!("{:?}", parser2).contains("KeyParser"));
    }
}
