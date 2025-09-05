//! Streaming encryption and decryption functionality.
//!
//! This module provides efficient streaming encryption capabilities for
//! processing large files and data streams without loading everything
//! into memory at once.

pub mod batch;
pub mod cipher;

// Re-export main types
pub use batch::BatchProcessor;
pub use cipher::{FileStreamCipher, ProgressCallback, StreamCipher};
