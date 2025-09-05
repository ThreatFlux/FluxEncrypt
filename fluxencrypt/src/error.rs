//! Error types and handling for FluxEncrypt operations.

use thiserror::Error;

/// Result type alias for FluxEncrypt operations.
pub type Result<T> = std::result::Result<T, FluxError>;

/// Main error type for FluxEncrypt operations.
#[derive(Error, Debug)]
pub enum FluxError {
    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {message}")]
    CryptoError {
        /// Error message describing the failure
        message: String,
    },

    /// Key-related error
    #[error("Key error: {message}")]
    KeyError {
        /// Error message describing the key issue
        message: String,
    },

    /// Invalid input data
    #[error("Invalid input: {message}")]
    InvalidInput {
        /// Error message describing the invalid input
        message: String,
    },

    /// Configuration error
    #[error("Configuration error: {message}")]
    ConfigError {
        /// Error message describing the configuration issue
        message: String,
    },

    /// I/O operation failed
    #[error("I/O error: {source}")]
    IoError {
        /// The underlying I/O error
        #[from]
        source: std::io::Error,
    },

    /// Serialization/deserialization error
    #[cfg(feature = "serde")]
    #[error("Serialization error: {source}")]
    SerializationError {
        /// The underlying serialization error
        #[from]
        source: serde_json::Error,
    },

    /// Environment variable error
    #[error("Environment error: {message}")]
    EnvError {
        /// Error message describing the environment issue
        message: String,
    },

    /// Ring cryptographic library error
    #[error("Ring crypto error: {message}")]
    RingError {
        /// Error message from ring
        message: String,
    },

    /// Base64 decoding error
    #[error("Base64 decode error: {source}")]
    Base64Error {
        /// The underlying base64 error
        #[from]
        source: base64::DecodeError,
    },

    /// Stream processing error
    #[error("Stream error: {message}")]
    StreamError {
        /// Error message describing the stream issue
        message: String,
    },

    /// Memory allocation error
    #[error("Memory error: {message}")]
    MemoryError {
        /// Error message describing the memory issue
        message: String,
    },

    /// Other/generic error
    #[error("Other error: {source}")]
    Other {
        /// The underlying error
        #[from]
        source: anyhow::Error,
    },
}

impl FluxError {
    /// Create a new crypto error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::CryptoError {
            message: message.into(),
        }
    }

    /// Create a new key error
    pub fn key(message: impl Into<String>) -> Self {
        Self::KeyError {
            message: message.into(),
        }
    }

    /// Create a new invalid input error
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    /// Create a new configuration error
    pub fn config(message: impl Into<String>) -> Self {
        Self::ConfigError {
            message: message.into(),
        }
    }

    /// Create a new environment error
    pub fn env(message: impl Into<String>) -> Self {
        Self::EnvError {
            message: message.into(),
        }
    }

    /// Create a new stream error
    pub fn stream(message: impl Into<String>) -> Self {
        Self::StreamError {
            message: message.into(),
        }
    }

    /// Create a new memory error
    pub fn memory(message: impl Into<String>) -> Self {
        Self::MemoryError {
            message: message.into(),
        }
    }

    /// Create an other error from an anyhow error
    pub fn other(source: anyhow::Error) -> Self {
        Self::Other { source }
    }
}

impl From<ring::error::Unspecified> for FluxError {
    fn from(err: ring::error::Unspecified) -> Self {
        Self::RingError {
            message: format!("Ring unspecified error: {:?}", err),
        }
    }
}

impl From<ring::error::KeyRejected> for FluxError {
    fn from(err: ring::error::KeyRejected) -> Self {
        Self::KeyError {
            message: format!("Key rejected: {}", err),
        }
    }
}
