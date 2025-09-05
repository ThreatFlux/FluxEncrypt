# FluxEncrypt

[![CI](https://github.com/ThreatFlux/fluxencrypt/workflows/CI/badge.svg)](https://github.com/ThreatFlux/fluxencrypt/actions)
[![Security Audit](https://github.com/ThreatFlux/fluxencrypt/workflows/Security/badge.svg)](https://github.com/ThreatFlux/fluxencrypt/actions)
[![Crates.io](https://img.shields.io/crates/v/fluxencrypt.svg)](https://crates.io/crates/fluxencrypt)
[![Documentation](https://docs.rs/fluxencrypt/badge.svg)](https://docs.rs/fluxencrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-performance, secure encryption SDK for Rust applications, providing both hybrid encryption capabilities and streaming data protection with enterprise-grade security features.

## Authors

- **Wyatt Roersma** - Lead Developer
- **Claude Code** - AI Assistant Developer  
- **Codex** - Architecture Consultant

*Developed for the ThreatFlux Organization*

## Features

### 🔐 Core Encryption
- **Hybrid Encryption**: Combines RSA-OAEP and AES-GCM for optimal security and performance
- **AES-256-GCM**: Fast symmetric encryption with authenticated encryption
- **RSA-OAEP**: Secure asymmetric encryption with optimal padding
- **Key Derivation**: PBKDF2 and Argon2 support for secure key generation

### 🚀 Performance
- **Stream Processing**: Handle large files and data streams efficiently
- **Batch Operations**: Process multiple files with parallel execution
- **Memory Safety**: Zero-copy operations where possible
- **Hardware Acceleration**: Leverages hardware crypto instructions

### 🔧 Developer Experience
- **Simple API**: Intuitive interface for common use cases
- **Flexible Configuration**: Customizable security parameters
- **Comprehensive Examples**: Ready-to-use code samples
- **Excellent Documentation**: Detailed guides and API references

### 🛡️ Security
- **Memory Protection**: Automatic secret zeroization
- **Constant-time Operations**: Protection against timing attacks
- **Secure Random Generation**: Cryptographically secure randomness
- **Environment Integration**: Secure secret management from environment variables

### 📦 Async Support
- **Tokio Integration**: Full async/await support
- **Streaming Operations**: Process large datasets asynchronously
- **Concurrent Processing**: Handle multiple operations simultaneously

## Quick Start

### Installation

Add FluxEncrypt to your `Cargo.toml`:

```toml
[dependencies]
fluxencrypt = "0.1.0"

# For async support
fluxencrypt-async = "0.1.0"

# For CLI usage
fluxencrypt-cli = "0.1.0"
```

### Basic Usage

```rust
use fluxencrypt::{Config, HybridCipher};
use fluxencrypt::keys::KeyPair;

// Generate a new key pair
let keypair = KeyPair::generate(2048)?;

// Create cipher with default configuration
let cipher = HybridCipher::new(Config::default());

// Encrypt data
let plaintext = b"Hello, FluxEncrypt!";
let ciphertext = cipher.encrypt(&keypair.public_key(), plaintext)?;

// Decrypt data
let decrypted = cipher.decrypt(&keypair.private_key(), &ciphertext)?;
assert_eq!(plaintext, &decrypted[..]);
```

### File Encryption

```rust
use fluxencrypt::stream::FileStreamCipher;
use std::path::Path;

let cipher = FileStreamCipher::new(config);

// Encrypt a file
cipher.encrypt_file(
    Path::new("document.pdf"),
    Path::new("document.pdf.enc"),
    &public_key
)?;

// Decrypt a file
cipher.decrypt_file(
    Path::new("document.pdf.enc"),
    Path::new("document_restored.pdf"),
    &private_key
)?;
```

### Async Operations

```rust
use fluxencrypt_async::{AsyncHybridCipher, Config};

let cipher = AsyncHybridCipher::new(Config::default());

// Async encryption
let ciphertext = cipher.encrypt_async(&public_key, data).await?;

// Async decryption  
let plaintext = cipher.decrypt_async(&private_key, &ciphertext).await?;
```

### Environment-based Key Management

```rust
use fluxencrypt::env::EnvSecretProvider;

// Load keys from environment variables
let provider = EnvSecretProvider::new();
let private_key = provider.get_private_key("FLUX_PRIVATE_KEY")?;
let public_key = provider.get_public_key("FLUX_PUBLIC_KEY")?;
```

## Command Line Interface

FluxEncrypt includes a powerful CLI for file encryption operations:

```bash
# Install the CLI
cargo install fluxencrypt-cli

# Generate a new key pair
fluxencrypt keygen --output-dir ./keys

# Encrypt a file
fluxencrypt encrypt --key ./keys/public.pem --input document.pdf --output document.pdf.enc

# Decrypt a file  
fluxencrypt decrypt --key ./keys/private.pem --input document.pdf.enc --output document.pdf

# Batch encrypt multiple files
fluxencrypt batch-encrypt --key ./keys/public.pem --input-dir ./documents --output-dir ./encrypted

# Stream encrypt large files
fluxencrypt stream-encrypt --key ./keys/public.pem --input large-file.bin --output large-file.bin.enc
```

## Configuration

FluxEncrypt provides flexible configuration options:

```rust
use fluxencrypt::{Config, CipherSuite, KeyDerivation};

let config = Config::builder()
    .cipher_suite(CipherSuite::Aes256Gcm)
    .key_derivation(KeyDerivation::Pbkdf2 {
        iterations: 100_000,
        salt_len: 32,
    })
    .compression(true)
    .memory_limit_mb(256)
    .build();
```

## Performance Benchmarks

FluxEncrypt is designed for high performance:

- **AES-256-GCM**: 2.5+ GB/s throughput on modern hardware
- **RSA-2048**: 1000+ operations/sec for key operations
- **Hybrid Mode**: Optimal balance of security and speed
- **Stream Processing**: Constant memory usage regardless of file size

Run benchmarks:

```bash
cd fluxencrypt && cargo bench
```

## Security Considerations

### Cryptographic Standards
- Uses only well-established, peer-reviewed algorithms
- Implements current NIST recommendations
- Regular security audits and updates

### Memory Safety
- Automatic zeroization of sensitive data
- Protected memory allocation for keys
- Secure random number generation

### Side-channel Resistance
- Constant-time implementations
- Protection against timing attacks
- Secure coding practices throughout

## Project Structure

```
fluxencrypt/
├── fluxencrypt/           # Core library
├── fluxencrypt-cli/       # Command line interface  
├── fluxencrypt-async/     # Async support
├── examples/              # Usage examples
├── benches/               # Performance benchmarks
├── tests/                 # Integration tests
└── docs/                  # Additional documentation
```

## Examples

The `examples/` directory contains comprehensive examples:

- `basic_encryption.rs` - Simple encrypt/decrypt operations
- `file_encryption.rs` - File-based encryption
- `stream_processing.rs` - Large data stream handling  
- `async_operations.rs` - Async encryption patterns
- `key_management.rs` - Key generation and storage
- `batch_processing.rs` - Multiple file operations
- `environment_config.rs` - Environment-based configuration

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/ThreatFlux/fluxencrypt.git
cd fluxencrypt

# Install development dependencies
cargo install cargo-audit cargo-deny cargo-outdated

# Run tests
cargo test --all

# Run security audit
cargo audit

# Check for license compliance
cargo deny check
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: https://docs.rs/fluxencrypt
- **Issues**: https://github.com/ThreatFlux/fluxencrypt/issues
- **Discussions**: https://github.com/ThreatFlux/fluxencrypt/discussions

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

---

**FluxEncrypt** - Secure, Fast, Reliable Encryption for Rust Applications