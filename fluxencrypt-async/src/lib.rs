//! # FluxEncrypt Async
//!
//! Async/await support for the FluxEncrypt encryption SDK, providing non-blocking
//! encryption and decryption operations suitable for high-concurrency applications.
//!
//! ## Features
//!
//! - **Async Encryption/Decryption**: Non-blocking hybrid encryption operations
//! - **Streaming Support**: Process large files asynchronously without blocking
//! - **Concurrent Processing**: Handle multiple operations simultaneously
//! - **Tokio Integration**: Full compatibility with the Tokio async runtime
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use fluxencrypt_async::{AsyncHybridCipher, Config};
//! use fluxencrypt::keys::KeyPair;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate a new key pair
//!     let keypair = KeyPair::generate(2048)?;
//!
//!     // Create async cipher
//!     let cipher = AsyncHybridCipher::new(Config::default());
//!
//!     // Encrypt data asynchronously
//!     let plaintext = b"Hello, async FluxEncrypt!";
//!     let ciphertext = cipher.encrypt_async(&keypair.public_key(), plaintext).await?;
//!
//!     // Decrypt data asynchronously
//!     let decrypted = cipher.decrypt_async(&keypair.private_key(), &ciphertext).await?;
//!     assert_eq!(plaintext, &decrypted[..]);
//!
//!     Ok(())
//! }
//! ```

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

pub mod futures;
pub mod tokio;

// Re-export commonly used types
pub use crate::tokio::AsyncHybridCipher;
pub use fluxencrypt::Config;

/// Current version of the FluxEncrypt Async library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
