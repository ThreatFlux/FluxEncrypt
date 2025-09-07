//! RSA key pair generation functionality.
//!
//! This module provides secure RSA key pair generation using the RSA
//! cryptography library with proper random number generation.
//!
//! **Note**: This module is kept for backward compatibility. New code should
//! use the modular structure in `key_pair`, `public_key`, and `private_key` modules.

// Re-export from the new modular structure
pub use crate::keys::key_pair::KeyPair;
pub use crate::keys::private_key::PrivateKey;
pub use crate::keys::public_key::PublicKey;
