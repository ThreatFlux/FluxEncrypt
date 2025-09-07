//! Key generation, parsing, and management functionality.
//!
//! This module provides comprehensive key management capabilities including
//! RSA key pair generation, key parsing from various formats, and secure
//! key storage operations.

pub mod generation;
pub mod key_pair;
pub mod parsing;
pub mod private_key;
pub mod public_key;
pub mod storage;

// Re-export main types for backward compatibility
pub use generation::{KeyPair, PrivateKey, PublicKey};
// Re-export new modular types
pub use key_pair::KeyPair as KeyPairNew;
pub use private_key::PrivateKey as PrivateKeyNew;
pub use public_key::PublicKey as PublicKeyNew;
