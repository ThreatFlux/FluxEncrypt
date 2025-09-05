//! Key parsing functionality for various formats.
//!
//! This module provides functionality to parse RSA keys from different
//! formats including PEM, DER, and PKCS#8.

use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

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
            KeyFormat::Ssh => self.parse_public_key_ssh(data),
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

        // Check for SSH format (starts with ssh-rsa, ssh-ed25519, etc.)
        if let Ok(data_str) = std::str::from_utf8(data) {
            if data_str.starts_with("ssh-rsa") || data_str.starts_with("ssh-ed25519") {
                return Some(KeyFormat::Ssh);
            }
        }

        // Assume DER for binary data
        Some(KeyFormat::Der)
    }

    /// Parse a public key from PEM format
    fn parse_public_key_pem(&self, data: &[u8]) -> Result<PublicKey> {
        let pem_str = std::str::from_utf8(data)
            .map_err(|_| FluxError::invalid_input("Invalid UTF-8 in PEM data"))?;

        // Extract base64 content between PEM headers
        let lines: Vec<&str> = pem_str.lines().collect();
        let mut base64_lines = Vec::new();
        let mut in_key = false;

        for line in lines {
            if line.starts_with("-----BEGIN") {
                in_key = true;
            } else if line.starts_with("-----END") {
                break;
            } else if in_key && !line.trim().is_empty() {
                base64_lines.push(line.trim());
            }
        }

        if base64_lines.is_empty() {
            return Err(FluxError::invalid_input("No valid PEM content found"));
        }

        let base64_content = base64_lines.join("");
        let der_data = BASE64
            .decode(&base64_content)
            .map_err(|_| FluxError::invalid_input("Invalid base64 in PEM"))?;

        // For demonstration, create a key with the decoded data as modulus
        // In a real implementation, you would parse the ASN.1 structure
        let key_size = der_data.len() * 8; // Approximate
        let public_exponent = vec![0x01, 0x00, 0x01]; // Standard e = 65537

        Ok(PublicKey::new(key_size, der_data, public_exponent))
    }

    /// Parse a public key from DER format
    fn parse_public_key_der(&self, data: &[u8]) -> Result<PublicKey> {
        // For demonstration, treat the data as the modulus
        // In a real implementation, you would parse the ASN.1 DER structure
        let key_size = data.len() * 8;
        let public_exponent = vec![0x01, 0x00, 0x01]; // Standard e = 65537

        Ok(PublicKey::new(key_size, data.to_vec(), public_exponent))
    }

    /// Parse a public key from PKCS#8 format
    fn parse_public_key_pkcs8(&self, data: &[u8]) -> Result<PublicKey> {
        // For demonstration, delegate to DER parsing
        // In a real implementation, you would handle the PKCS#8 wrapper
        self.parse_public_key_der(data)
    }

    /// Parse a public key from SSH format
    fn parse_public_key_ssh(&self, data: &[u8]) -> Result<PublicKey> {
        let ssh_str = std::str::from_utf8(data)
            .map_err(|_| FluxError::invalid_input("Invalid UTF-8 in SSH key data"))?;

        // SSH key format: "ssh-rsa AAAAB3NzaC1yc2E... comment"
        let parts: Vec<&str> = ssh_str.split_whitespace().collect();

        if parts.len() < 2 {
            return Err(FluxError::invalid_input("Invalid SSH key format"));
        }

        if parts[0] != "ssh-rsa" {
            return Err(FluxError::invalid_input("Only ssh-rsa keys are supported"));
        }

        let key_data = BASE64
            .decode(parts[1])
            .map_err(|_| FluxError::invalid_input("Invalid base64 in SSH key"))?;

        // For demonstration, use the decoded data as modulus
        // In a real implementation, you would parse the SSH wire format
        let key_size = key_data.len() * 8;
        let public_exponent = vec![0x01, 0x00, 0x01];

        Ok(PublicKey::new(key_size, key_data, public_exponent))
    }

    /// Parse a private key from PEM format
    fn parse_private_key_pem(&self, data: &[u8]) -> Result<PrivateKey> {
        let pem_str = std::str::from_utf8(data)
            .map_err(|_| FluxError::invalid_input("Invalid UTF-8 in PEM data"))?;

        // Extract base64 content between PEM headers
        let lines: Vec<&str> = pem_str.lines().collect();
        let mut base64_lines = Vec::new();
        let mut in_key = false;

        for line in lines {
            if line.starts_with("-----BEGIN") {
                in_key = true;
            } else if line.starts_with("-----END") {
                break;
            } else if in_key && !line.trim().is_empty() {
                base64_lines.push(line.trim());
            }
        }

        if base64_lines.is_empty() {
            return Err(FluxError::invalid_input("No valid PEM content found"));
        }

        let base64_content = base64_lines.join("");
        let der_data = BASE64
            .decode(&base64_content)
            .map_err(|_| FluxError::invalid_input("Invalid base64 in PEM"))?;

        // For demonstration, create placeholder key components
        // In a real implementation, you would parse the ASN.1 structure
        let key_size = der_data.len() * 8; // Approximate
        let modulus = der_data.clone();
        let private_exponent = der_data.clone();
        let prime_len = der_data.len() / 2;
        let prime1 = der_data[..prime_len].to_vec();
        let prime2 = der_data[prime_len..].to_vec();
        let crt_coefficient = vec![1u8; prime_len];

        Ok(PrivateKey::new(
            key_size,
            modulus,
            private_exponent,
            prime1,
            prime2,
            crt_coefficient,
        ))
    }

    /// Parse a private key from DER format
    fn parse_private_key_der(&self, data: &[u8]) -> Result<PrivateKey> {
        // For demonstration, create placeholder key components
        // In a real implementation, you would parse the ASN.1 DER structure
        let key_size = data.len() * 8;
        let modulus = data.to_vec();
        let private_exponent = data.to_vec();
        let prime_len = data.len() / 2;
        let prime1 = data[..prime_len].to_vec();
        let prime2 = data[prime_len..].to_vec();
        let crt_coefficient = vec![1u8; prime_len];

        Ok(PrivateKey::new(
            key_size,
            modulus,
            private_exponent,
            prime1,
            prime2,
            crt_coefficient,
        ))
    }

    /// Parse a private key from PKCS#8 format
    fn parse_private_key_pkcs8(&self, data: &[u8]) -> Result<PrivateKey> {
        // For demonstration, delegate to DER parsing
        // In a real implementation, you would handle the PKCS#8 wrapper
        self.parse_private_key_der(data)
    }
}

impl Default for KeyParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to parse a public key from a string
pub fn parse_public_key_from_str(key_str: &str) -> Result<PublicKey> {
    let parser = KeyParser::new();
    let data = key_str.as_bytes();

    let format = parser
        .detect_format(data)
        .ok_or_else(|| FluxError::invalid_input("Unable to detect key format"))?;

    parser.parse_public_key(data, format)
}

/// Convenience function to parse a private key from a string
pub fn parse_private_key_from_str(key_str: &str) -> Result<PrivateKey> {
    let parser = KeyParser::new();
    let data = key_str.as_bytes();

    let format = parser
        .detect_format(data)
        .ok_or_else(|| FluxError::invalid_input("Unable to detect key format"))?;

    parser.parse_private_key(data, format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        let parser = KeyParser::new();

        // Test PEM detection
        let pem_data = b"-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END RSA PUBLIC KEY-----";
        assert_eq!(parser.detect_format(pem_data), Some(KeyFormat::Pem));

        // Test SSH detection
        let ssh_data = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@host";
        assert_eq!(parser.detect_format(ssh_data), Some(KeyFormat::Ssh));

        // Test binary data (assumes DER) - use actual binary data that can't be UTF-8
        let binary_data = b"\x30\x82\x01\x22\x30\x0d\x06\x09\xff\x86";
        assert_eq!(parser.detect_format(binary_data), Some(KeyFormat::Der));
    }

    #[test]
    fn test_pem_parsing_basic() {
        let parser = KeyParser::new();
        // Simple PEM with base64 encoded data "test" -> "dGVzdA=="
        let pem_data = b"-----BEGIN RSA PUBLIC KEY-----\ndGVzdA==\n-----END RSA PUBLIC KEY-----";
        let result = parser.parse_public_key(pem_data, KeyFormat::Pem);
        assert!(result.is_ok());
    }

    #[test]
    fn test_der_parsing_basic() {
        let parser = KeyParser::new();
        let der_data = b"\x30\x82\x01\x22\x30\x0d";
        let result = parser.parse_public_key(der_data, KeyFormat::Der);
        assert!(result.is_ok());
    }
}
