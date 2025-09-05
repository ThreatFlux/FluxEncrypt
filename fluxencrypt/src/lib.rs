//! # FluxEncrypt
//!
//! A high-performance, secure encryption SDK for Rust applications, providing both
//! hybrid encryption capabilities and streaming data protection with enterprise-grade
//! security features.
//!
//! ## Features
//!
//! - **Hybrid Encryption**: Combines RSA-OAEP and AES-GCM for optimal security and performance
//! - **Stream Processing**: Handle large files and data streams efficiently  
//! - **Memory Safety**: Automatic secret zeroization and secure memory handling
//! - **Performance**: Hardware-accelerated cryptographic operations
//! - **Flexibility**: Configurable security parameters and multiple key formats
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use fluxencrypt::{Config, HybridCipher};
//! use fluxencrypt::keys::KeyPair;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new key pair
//! let keypair = KeyPair::generate(2048)?;
//!
//! // Create cipher with default configuration
//! let cipher = HybridCipher::new(Config::default());
//!
//! // Encrypt data
//! let plaintext = b"Hello, FluxEncrypt!";
//! let ciphertext = cipher.encrypt(keypair.public_key(), plaintext)?;
//!
//! // Decrypt data
//! let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)?;
//! assert_eq!(plaintext, &decrypted[..]);
//! # Ok(())
//! # }
//! ```
//!
//! ## Module Organization
//!
//! - [`encryption`] - Core encryption and decryption functionality
//! - [`keys`] - Key generation, parsing, and management
//! - [`mod@env`] - Environment-based secret management
//! - [`stream`] - Streaming encryption for large datasets
//! - [`config`] - Configuration options and builders
//! - [`error`] - Error types and handling

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

pub mod config;
pub mod encryption;
pub mod env;
pub mod error;
pub mod keys;
pub mod stream;

// Re-export commonly used types
pub use config::Config;
pub use encryption::HybridCipher;
pub use error::{FluxError, Result};

use encryption::hybrid::HybridCipher as InternalHybridCipher;
use keys::{KeyPair, PrivateKey, PublicKey};
use std::path::Path;
use stream::{FileStreamCipher, StreamCipher};

/// Current version of the FluxEncrypt library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Main FluxEncrypt cryptographic engine providing unified access to all encryption functionality
#[derive(Debug)]
pub struct Cryptum {
    config: Config,
    hybrid_cipher: InternalHybridCipher,
    stream_cipher: StreamCipher,
    file_cipher: FileStreamCipher,
}

impl Cryptum {
    /// Create a new Cryptum instance with custom configuration
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            hybrid_cipher: InternalHybridCipher::new(config.clone()),
            stream_cipher: StreamCipher::new(config.clone()),
            file_cipher: FileStreamCipher::new(config.clone()),
            config,
        })
    }

    /// Create a new Cryptum instance with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::new(Config::default())
    }

    /// Create a Cryptum instance with a configuration builder
    pub fn builder() -> CryptumBuilder {
        CryptumBuilder::new()
    }

    /// Get the current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Generate a new RSA key pair
    pub fn generate_keypair(&self, key_size: usize) -> Result<KeyPair> {
        KeyPair::generate(key_size)
    }

    /// Encrypt data using hybrid encryption
    pub fn encrypt(&self, public_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.hybrid_cipher.encrypt(public_key, plaintext)
    }

    /// Decrypt data using hybrid encryption
    pub fn decrypt(&self, private_key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.hybrid_cipher.decrypt(private_key, ciphertext)
    }

    /// Encrypt a file using streaming encryption
    pub fn encrypt_file<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        public_key: &PublicKey,
    ) -> Result<u64> {
        self.file_cipher
            .encrypt_file(input_path, output_path, public_key, None)
    }

    /// Decrypt a file using streaming decryption
    pub fn decrypt_file<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        private_key: &PrivateKey,
    ) -> Result<u64> {
        self.file_cipher
            .decrypt_file(input_path, output_path, private_key, None)
    }

    /// Encrypt a file with progress callback
    pub fn encrypt_file_with_progress<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        public_key: &PublicKey,
        progress: stream::ProgressCallback,
    ) -> Result<u64> {
        self.file_cipher
            .encrypt_file(input_path, output_path, public_key, Some(progress))
    }

    /// Decrypt a file with progress callback
    pub fn decrypt_file_with_progress<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        private_key: &PrivateKey,
        progress: stream::ProgressCallback,
    ) -> Result<u64> {
        self.file_cipher
            .decrypt_file(input_path, output_path, private_key, Some(progress))
    }

    /// Access the hybrid cipher for advanced operations
    pub fn hybrid_cipher(&self) -> &InternalHybridCipher {
        &self.hybrid_cipher
    }

    /// Access the stream cipher for advanced operations
    pub fn stream_cipher(&self) -> &StreamCipher {
        &self.stream_cipher
    }

    /// Access the file cipher for advanced operations
    pub fn file_cipher(&self) -> &FileStreamCipher {
        &self.file_cipher
    }

    /// Get batch processor for multiple file operations
    pub fn batch_processor(&self) -> stream::BatchProcessor {
        stream::BatchProcessor::new(self.config.clone())
    }
}

/// Builder for configuring and creating Cryptum instances
#[derive(Debug, Default)]
pub struct CryptumBuilder {
    config_builder: config::ConfigBuilder,
}

impl CryptumBuilder {
    /// Create a new Cryptum builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the cipher suite
    pub fn cipher_suite(mut self, cipher_suite: config::CipherSuite) -> Self {
        self.config_builder = self.config_builder.cipher_suite(cipher_suite);
        self
    }

    /// Set the RSA key size
    pub fn rsa_key_size(mut self, key_size: config::RsaKeySize) -> Self {
        self.config_builder = self.config_builder.rsa_key_size(key_size);
        self
    }

    /// Set the memory limit
    pub fn memory_limit_mb(mut self, limit: usize) -> Self {
        self.config_builder = self.config_builder.memory_limit_mb(limit);
        self
    }

    /// Enable or disable hardware acceleration
    pub fn hardware_acceleration(mut self, enable: bool) -> Self {
        self.config_builder = self.config_builder.hardware_acceleration(enable);
        self
    }

    /// Set the stream chunk size
    pub fn stream_chunk_size(mut self, size: usize) -> Self {
        self.config_builder = self.config_builder.stream_chunk_size(size);
        self
    }

    /// Enable or disable secure memory
    pub fn secure_memory(mut self, enable: bool) -> Self {
        self.config_builder = self.config_builder.secure_memory(enable);
        self
    }

    /// Build the Cryptum instance
    pub fn build(self) -> Result<Cryptum> {
        let config = self.config_builder.build()?;
        Cryptum::new(config)
    }
}

/// Convenience function to create a Cryptum instance with default settings
pub fn cryptum() -> Result<Cryptum> {
    Cryptum::with_defaults()
}
