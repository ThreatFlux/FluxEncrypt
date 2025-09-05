//! Environment-based secret management functionality.
//!
//! This module provides secure ways to load cryptographic keys and other
//! secrets from environment variables, supporting various formats and
//! automatic detection.

pub mod provider;
pub mod secrets;

// Re-export main types
pub use provider::EnvSecretProvider;
pub use secrets::{EnvSecret, SecretFormat};
