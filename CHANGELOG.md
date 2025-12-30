# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2025-12-30

### Added
- **SymmetricCipher**: New simple AES-256-GCM encryption for secret storage (API tokens, MFA secrets, database credentials)
- **Cryptum**: Unified API providing single interface for all encryption operations
- **CryptumBuilder**: Fluent builder pattern for configuring Cryptum instances
- Python-compatible CLI features for easier integration
- String data encryption/decryption via `--data` flag
- Base64 encoded output by default for text-friendly handling
- Raw binary output option via `--raw` flag
- Base64 encoded keys support via `--base64` flag in keygen
- 4096-bit RSA keys as new secure default (upgraded from 2048-bit)
- Major code refactoring for reduced complexity
- Split large modules into focused, maintainable files
- Enhanced CLI user experience with better output formatting
- Improved error handling and validation
- `generate_key()` method for SymmetricCipher to create random encryption keys

### Changed
- **BREAKING**: Default RSA key size increased from 2048 to 4096 bits
- **BREAKING**: CLI output format changed to base64 by default
- **BREAKING**: Minimum supported Rust version (MSRV) is now 1.89.0
- Refactored codebase structure for better maintainability
- Enhanced security with pinned GitHub Actions versions
- Improved temporary file handling with secure permissions
- Updated documentation to reflect current functionality
- Version bump to 0.5.0 (major feature release)

### Security
- Upgraded to 4096-bit RSA keys by default for enhanced security
- Pinned GitHub Actions to specific versions to prevent supply chain attacks
- Secure temporary file creation with proper permissions
- Memory-safe cryptographic operations
- Automatic secret zeroization
- Constant-time implementations for critical operations

### Fixed
- Documentation build issues resolved
- Test failures addressed
- CLI help text now matches actual functionality
- Corrected examples to use current API
- Fixed clippy warnings for Rust 1.92.0 compatibility
- Integration tests now run without `#[ignore]` attributes

### Performance
- Optimized key generation for 4096-bit keys
- Improved streaming encryption performance
- Better memory management in large file operations

## [0.1.3] - 2024-09-06

### Added
- Complete CLI implementation with all major commands
- String data encryption support via `--data` flag
- Base64 output format as default
- Raw binary output option via `--raw` flag
- Base64 key storage option via `--base64` flag
- 4096-bit RSA key generation by default
- Enhanced user experience with progress indicators
- Comprehensive test coverage
- Security audit compliance

### Changed
- Default RSA key size upgraded to 4096 bits
- CLI output format defaults to base64 encoding
- Improved error messages and user feedback
- Enhanced key management capabilities

### Security  
- Upgraded cryptographic defaults for better security
- Secure random number generation
- Protected memory operations

## [0.1.0] - 2024-12-XX

### Added
- Initial release of FluxEncrypt
- Hybrid encryption support (RSA-OAEP + AES-GCM)
- Stream processing capabilities
- Environment-based secret management
- Command line interface
- Async/await support
- Comprehensive test suite
- Performance benchmarks
- Security audit compliance

### Features
- AES-256-GCM symmetric encryption
- RSA-OAEP asymmetric encryption
- PBKDF2 key derivation
- Batch file processing
- Memory protection with zeroization
- Hardware acceleration support
- Cross-platform compatibility

### Documentation
- Complete API documentation
- Usage examples and tutorials
- Security best practices guide
- Performance optimization tips
- CLI usage guide

### Infrastructure
- Continuous integration with GitHub Actions
- Automated security scanning
- Code quality checks with Clippy
- Dependency vulnerability scanning
- Automated release process