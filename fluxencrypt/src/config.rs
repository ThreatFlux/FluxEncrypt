//! Configuration options and builders for FluxEncrypt operations.

use crate::error::{FluxError, Result};

/// Supported cipher suites for symmetric encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM (recommended)
    Aes256Gcm,
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

/// Key derivation algorithms and parameters
#[derive(Debug, Clone)]
pub enum KeyDerivation {
    /// PBKDF2 with SHA-256
    Pbkdf2 {
        /// Number of iterations (recommended: 100,000+)
        iterations: u32,
        /// Salt length in bytes (recommended: 32)
        salt_len: usize,
    },
    /// Argon2id (future implementation)
    #[allow(dead_code)]
    Argon2 {
        /// Memory cost in KB
        memory_cost: u32,
        /// Time cost (iterations)
        time_cost: u32,
        /// Parallelism degree
        parallelism: u32,
    },
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::Pbkdf2 {
            iterations: 100_000,
            salt_len: 32,
        }
    }
}

/// RSA key size options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeySize {
    /// 2048-bit keys (minimum recommended)
    Rsa2048,
    /// 3072-bit keys
    Rsa3072,
    /// 4096-bit keys (maximum security)
    Rsa4096,
}

impl Default for RsaKeySize {
    fn default() -> Self {
        Self::Rsa2048
    }
}

impl From<RsaKeySize> for usize {
    fn from(size: RsaKeySize) -> Self {
        match size {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
        }
    }
}

/// Compression algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression
    None,
    /// Zlib compression (future implementation)
    #[allow(dead_code)]
    Zlib,
    /// LZ4 compression (future implementation)
    #[allow(dead_code)]
    Lz4,
}

impl Default for Compression {
    fn default() -> Self {
        Self::None
    }
}

/// Configuration for FluxEncrypt operations
#[derive(Debug, Clone)]
pub struct Config {
    /// Cipher suite for symmetric encryption
    pub cipher_suite: CipherSuite,
    /// Key derivation algorithm and parameters
    pub key_derivation: KeyDerivation,
    /// RSA key size for asymmetric operations
    pub rsa_key_size: RsaKeySize,
    /// Compression algorithm
    pub compression: Compression,
    /// Memory limit for operations in MB
    pub memory_limit_mb: usize,
    /// Enable hardware acceleration if available
    pub hardware_acceleration: bool,
    /// Maximum chunk size for streaming operations
    pub stream_chunk_size: usize,
    /// Enable secure memory wiping
    pub secure_memory: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuite::default(),
            key_derivation: KeyDerivation::default(),
            rsa_key_size: RsaKeySize::default(),
            compression: Compression::default(),
            memory_limit_mb: 256,
            hardware_acceleration: true,
            stream_chunk_size: 64 * 1024, // 64KB
            secure_memory: true,
        }
    }
}

/// Builder for creating Config instances
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl Config {
    /// Create a new ConfigBuilder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Get the key length in bytes for the configured cipher suite
    pub fn key_length(&self) -> usize {
        match self.cipher_suite {
            CipherSuite::Aes128Gcm => 16,
            CipherSuite::Aes256Gcm => 32,
        }
    }

    /// Get the nonce/IV length in bytes for the configured cipher suite
    pub fn nonce_length(&self) -> usize {
        match self.cipher_suite {
            CipherSuite::Aes128Gcm | CipherSuite::Aes256Gcm => 12,
        }
    }

    /// Get the authentication tag length in bytes
    pub fn tag_length(&self) -> usize {
        match self.cipher_suite {
            CipherSuite::Aes128Gcm | CipherSuite::Aes256Gcm => 16,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.memory_limit_mb == 0 {
            return Err(FluxError::config("Memory limit cannot be zero"));
        }

        if self.stream_chunk_size == 0 {
            return Err(FluxError::config("Stream chunk size cannot be zero"));
        }

        if self.stream_chunk_size > self.memory_limit_mb * 1024 * 1024 {
            return Err(FluxError::config(
                "Stream chunk size cannot exceed memory limit",
            ));
        }

        match &self.key_derivation {
            KeyDerivation::Pbkdf2 {
                iterations,
                salt_len,
            } => {
                if *iterations < 1000 {
                    return Err(FluxError::config(
                        "PBKDF2 iterations should be at least 1000",
                    ));
                }
                if *salt_len < 16 {
                    return Err(FluxError::config("Salt length should be at least 16 bytes"));
                }
            }
            KeyDerivation::Argon2 { .. } => {
                // Future validation for Argon2
            }
        }

        Ok(())
    }
}

impl ConfigBuilder {
    /// Set the cipher suite
    pub fn cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.config.cipher_suite = cipher_suite;
        self
    }

    /// Set the key derivation algorithm
    pub fn key_derivation(mut self, key_derivation: KeyDerivation) -> Self {
        self.config.key_derivation = key_derivation;
        self
    }

    /// Set the RSA key size
    pub fn rsa_key_size(mut self, rsa_key_size: RsaKeySize) -> Self {
        self.config.rsa_key_size = rsa_key_size;
        self
    }

    /// Set the compression algorithm
    pub fn compression(mut self, compression: Compression) -> Self {
        self.config.compression = compression;
        self
    }

    /// Set the memory limit in MB
    pub fn memory_limit_mb(mut self, memory_limit_mb: usize) -> Self {
        self.config.memory_limit_mb = memory_limit_mb;
        self
    }

    /// Enable or disable hardware acceleration
    pub fn hardware_acceleration(mut self, hardware_acceleration: bool) -> Self {
        self.config.hardware_acceleration = hardware_acceleration;
        self
    }

    /// Set the stream chunk size
    pub fn stream_chunk_size(mut self, stream_chunk_size: usize) -> Self {
        self.config.stream_chunk_size = stream_chunk_size;
        self
    }

    /// Enable or disable secure memory wiping
    pub fn secure_memory(mut self, secure_memory: bool) -> Self {
        self.config.secure_memory = secure_memory;
        self
    }

    /// Build the configuration, validating it first
    pub fn build(self) -> Result<Config> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.cipher_suite, CipherSuite::Aes256Gcm);
        assert_eq!(config.rsa_key_size, RsaKeySize::Rsa2048);
        assert_eq!(config.memory_limit_mb, 256);
    }

    #[test]
    fn test_config_builder() {
        let config = Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .memory_limit_mb(512)
            .hardware_acceleration(false)
            .build()
            .unwrap();

        assert_eq!(config.cipher_suite, CipherSuite::Aes128Gcm);
        assert_eq!(config.memory_limit_mb, 512);
        assert!(!config.hardware_acceleration);
    }

    #[test]
    fn test_invalid_config() {
        let result = Config::builder().memory_limit_mb(0).build();
        assert!(result.is_err());
    }
}
