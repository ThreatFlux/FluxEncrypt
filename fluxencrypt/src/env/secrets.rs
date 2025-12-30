//! Secret handling and format detection for environment variables.
//!
//! This module provides types and functions for working with secrets loaded
//! from environment variables, including automatic format detection and
//! conversion to cryptographic keys.

use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use zeroize::ZeroizeOnDrop;

/// Supported secret formats in environment variables
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFormat {
    /// Raw string value
    Raw,
    /// Base64 encoded value
    Base64,
    /// PEM format (with headers)
    Pem,
    /// Hexadecimal encoded value
    Hex,
    /// File path pointing to the secret
    FilePath,
}

/// A secret loaded from an environment variable
#[derive(ZeroizeOnDrop)]
#[allow(unused_assignments)] // False positive: fields are used via getter methods
pub struct EnvSecret {
    /// The raw secret data
    data: Vec<u8>,
    /// The detected or specified format
    #[zeroize(skip)]
    format: SecretFormat,
    /// The original string value (for debugging)
    #[zeroize(skip)]
    original: String,
}

impl std::fmt::Debug for EnvSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvSecret")
            .field("format", &self.format)
            .field("data_len", &self.data.len())
            .field("original_len", &self.original.len())
            .finish()
    }
}

impl EnvSecret {
    /// Create a new secret from raw data
    pub fn new(data: Vec<u8>, format: SecretFormat, original: String) -> Self {
        Self {
            data,
            format,
            original,
        }
    }

    /// Create a secret from a string with automatic format detection
    pub fn from_string(value: String) -> Result<Self> {
        let format = Self::detect_format(&value);
        Self::from_string_with_format(value, format)
    }

    /// Create a secret from a string with a specified format
    pub fn from_string_with_format(value: String, format: SecretFormat) -> Result<Self> {
        let data = match format {
            SecretFormat::Raw => Self::decode_raw(&value),
            SecretFormat::Base64 => Self::decode_base64(&value)?,
            SecretFormat::Hex => Self::decode_hex(&value)?,
            SecretFormat::Pem => Self::decode_pem(&value),
            SecretFormat::FilePath => Self::read_from_file(&value)?,
        };

        Ok(Self::new(data, format, value))
    }

    /// Decode raw string data
    fn decode_raw(value: &str) -> Vec<u8> {
        value.as_bytes().to_vec()
    }

    /// Decode base64 string data
    fn decode_base64(value: &str) -> Result<Vec<u8>> {
        BASE64
            .decode(value)
            .map_err(|e| FluxError::invalid_input(format!("Invalid base64: {}", e)))
    }

    /// Decode hexadecimal string data
    fn decode_hex(value: &str) -> Result<Vec<u8>> {
        let clean_value = value.trim();
        if !clean_value.len().is_multiple_of(2) {
            return Err(FluxError::invalid_input("Hex string must have even length"));
        }

        let mut result = Vec::with_capacity(clean_value.len() / 2);
        for chunk in clean_value.as_bytes().chunks(2) {
            let hex_str = std::str::from_utf8(chunk)
                .map_err(|_| FluxError::invalid_input("Invalid hex characters"))?;
            let byte = u8::from_str_radix(hex_str, 16)
                .map_err(|_| FluxError::invalid_input("Invalid hex characters"))?;
            result.push(byte);
        }
        Ok(result)
    }

    /// Decode PEM format data
    fn decode_pem(value: &str) -> Vec<u8> {
        value.as_bytes().to_vec() // PEM is text-based
    }

    /// Read secret data from file
    fn read_from_file(value: &str) -> Result<Vec<u8>> {
        std::fs::read(value).map_err(|e| {
            FluxError::invalid_input(format!("Cannot read secret file {}: {}", value, e))
        })
    }

    /// Detect the format of a secret string
    pub fn detect_format(value: &str) -> SecretFormat {
        // Check for PEM format
        if value.starts_with("-----BEGIN") && value.contains("-----END") {
            return SecretFormat::Pem;
        }

        // Check for file path (contains / or \)
        if value.contains('/') || value.contains('\\') {
            return SecretFormat::FilePath;
        }

        // Check for hex (all characters are hex digits)
        if value.len() > 10 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            return SecretFormat::Hex;
        }

        // Check for base64 (ends with = padding and contains base64 chars)
        if value.len() > 10
            && (value.ends_with('=') || value.ends_with("=="))
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            return SecretFormat::Base64;
        }

        // Default to raw
        SecretFormat::Raw
    }

    /// Get the secret data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the secret format
    pub fn format(&self) -> SecretFormat {
        self.format
    }

    /// Get the original string value (for debugging)
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Convert the secret to a string (if it contains valid UTF-8)
    pub fn as_string(&self) -> Result<String> {
        String::from_utf8(self.data.clone())
            .map_err(|e| FluxError::invalid_input(format!("Secret contains invalid UTF-8: {}", e)))
    }

    /// Convert the secret to a public key
    pub fn as_public_key(&self) -> Result<PublicKey> {
        match self.format {
            SecretFormat::Pem => {
                // Parse PEM format
                let pem_str = self.as_string()?;
                crate::keys::parsing::parse_public_key_from_str(&pem_str)
            }
            _ => {
                // Try to parse as PEM first, then other formats
                if let Ok(pem_str) = self.as_string() {
                    if let Ok(key) = crate::keys::parsing::parse_public_key_from_str(&pem_str) {
                        return Ok(key);
                    }
                }

                // TODO: Try other formats (DER, etc.)
                Err(FluxError::invalid_input(
                    "Cannot parse secret as public key",
                ))
            }
        }
    }

    /// Convert the secret to a private key
    pub fn as_private_key(&self) -> Result<PrivateKey> {
        match self.format {
            SecretFormat::Pem => {
                // Parse PEM format
                let pem_str = self.as_string()?;
                crate::keys::parsing::parse_private_key_from_str(&pem_str)
            }
            _ => {
                // Try to parse as PEM first, then other formats
                if let Ok(pem_str) = self.as_string() {
                    if let Ok(key) = crate::keys::parsing::parse_private_key_from_str(&pem_str) {
                        return Ok(key);
                    }
                }

                // TODO: Try other formats (DER, PKCS#8, etc.)
                Err(FluxError::invalid_input(
                    "Cannot parse secret as private key",
                ))
            }
        }
    }

    /// Convert the secret to base64
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.data)
    }

    /// Convert the secret to hex
    pub fn to_hex(&self) -> String {
        self.data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the length of the secret data
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// Utility function to load a secret from an environment variable
pub fn load_env_secret(var_name: &str) -> Result<EnvSecret> {
    let value = std::env::var(var_name)
        .map_err(|_| FluxError::env(format!("Environment variable not found: {}", var_name)))?;

    EnvSecret::from_string(value)
}

/// Utility function to load a secret with a specific format
pub fn load_env_secret_with_format(var_name: &str, format: SecretFormat) -> Result<EnvSecret> {
    let value = std::env::var(var_name)
        .map_err(|_| FluxError::env(format!("Environment variable not found: {}", var_name)))?;

    EnvSecret::from_string_with_format(value, format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        // Test PEM detection
        let pem_value = "-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END RSA PUBLIC KEY-----";
        assert_eq!(EnvSecret::detect_format(pem_value), SecretFormat::Pem);

        // Test file path detection
        assert_eq!(
            EnvSecret::detect_format("/path/to/file"),
            SecretFormat::FilePath
        );
        assert_eq!(
            EnvSecret::detect_format("C:\\path\\to\\file"),
            SecretFormat::FilePath
        );

        // Test hex detection
        let hex_value = "abcdef1234567890abcdef1234567890";
        assert_eq!(EnvSecret::detect_format(hex_value), SecretFormat::Hex);

        // Test base64 detection
        let b64_value = "SGVsbG8gV29ybGQ=";
        assert_eq!(EnvSecret::detect_format(b64_value), SecretFormat::Base64);

        // Test raw detection
        assert_eq!(EnvSecret::detect_format("hello world"), SecretFormat::Raw);
    }

    #[test]
    fn test_raw_secret() {
        let secret =
            EnvSecret::from_string_with_format("hello world".to_string(), SecretFormat::Raw)
                .unwrap();

        assert_eq!(secret.as_bytes(), b"hello world");
        assert_eq!(secret.format(), SecretFormat::Raw);
        assert_eq!(secret.as_string().unwrap(), "hello world");
    }

    #[test]
    fn test_base64_secret() {
        let secret = EnvSecret::from_string_with_format(
            "SGVsbG8gV29ybGQ=".to_string(),
            SecretFormat::Base64,
        )
        .unwrap();

        assert_eq!(secret.as_bytes(), b"Hello World");
        assert_eq!(secret.format(), SecretFormat::Base64);
    }

    #[test]
    fn test_hex_secret() {
        let secret = EnvSecret::from_string_with_format(
            "48656c6c6f20576f726c64".to_string(),
            SecretFormat::Hex,
        )
        .unwrap();

        assert_eq!(secret.as_bytes(), b"Hello World");
        assert_eq!(secret.format(), SecretFormat::Hex);
    }

    #[test]
    fn test_secret_conversions() {
        let secret = EnvSecret::from_string("Hello World".to_string()).unwrap();

        assert_eq!(secret.to_base64(), "SGVsbG8gV29ybGQ=");
        assert_eq!(secret.to_hex(), "48656c6c6f20576f726c64");
        assert!(!secret.is_empty());
        assert_eq!(secret.len(), 11);
    }
}
