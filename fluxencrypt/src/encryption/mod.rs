//! Core encryption and decryption functionality.
//!
//! This module provides the main encryption interfaces for FluxEncrypt, including
//! hybrid encryption that combines RSA-OAEP for key encryption with AES-GCM for
//! data encryption.

pub mod aes_gcm;
pub mod hybrid;
pub mod rsa_oaep;

// Re-export main types
pub use hybrid::HybridCipher;
