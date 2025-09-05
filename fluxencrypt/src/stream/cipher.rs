//! Streaming cipher implementation for large data processing.
//!
//! This module provides streaming encryption and decryption capabilities
//! that can handle large files and data streams efficiently without
//! requiring the entire dataset to be loaded into memory.

use crate::config::Config;
use crate::encryption::hybrid::HybridCipher;
use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};
use std::io::{Read, Write};
use std::path::Path;

/// A streaming cipher for processing large amounts of data
#[derive(Debug)]
pub struct StreamCipher {
    config: Config,
    chunk_size: usize,
}

/// A file-based streaming cipher for encrypting/decrypting files
#[derive(Debug)]
pub struct FileStreamCipher {
    cipher: StreamCipher,
}

/// Progress callback for streaming operations
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

impl StreamCipher {
    /// Create a new streaming cipher
    pub fn new(config: Config) -> Self {
        let chunk_size = config.stream_chunk_size;
        Self { config, chunk_size }
    }

    /// Encrypt a stream of data
    ///
    /// # Arguments
    /// * `public_key` - The public key to encrypt with
    /// * `input` - The input stream to read from
    /// * `output` - The output stream to write encrypted data to
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub fn encrypt_stream<R, W>(
        &self,
        public_key: &PublicKey,
        mut input: R,
        mut output: W,
        progress: Option<ProgressCallback>,
    ) -> Result<u64>
    where
        R: Read,
        W: Write,
    {
        let mut total_processed = 0u64;
        let mut buffer = vec![0u8; self.chunk_size];

        // Simple streaming encryption using hybrid encryption per chunk
        // Note: This is not the most efficient approach for large streams,
        // but provides a working implementation

        loop {
            let bytes_read = input.read(&mut buffer).map_err(FluxError::from)?;

            if bytes_read == 0 {
                break; // End of stream
            }

            // Process chunk
            let chunk = &buffer[..bytes_read];
            let encrypted_chunk = self.encrypt_chunk(public_key, chunk)?;

            // Write chunk size first (for proper decryption)
            output.write_all(&(encrypted_chunk.len() as u32).to_be_bytes())?;
            output.write_all(&encrypted_chunk)?;

            total_processed += bytes_read as u64;

            // Call progress callback if provided
            if let Some(ref callback) = progress {
                // TODO: Get total size somehow for accurate progress
                callback(total_processed, total_processed);
            }
        }

        Ok(total_processed)
    }

    /// Decrypt a stream of data
    ///
    /// # Arguments
    /// * `private_key` - The private key to decrypt with
    /// * `input` - The input stream to read encrypted data from
    /// * `output` - The output stream to write decrypted data to
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub fn decrypt_stream<R, W>(
        &self,
        private_key: &PrivateKey,
        mut input: R,
        mut output: W,
        progress: Option<ProgressCallback>,
    ) -> Result<u64>
    where
        R: Read,
        W: Write,
    {
        let mut total_processed = 0u64;

        // Simple streaming decryption using hybrid decryption per chunk
        // Note: This reads chunks with their size prefixes

        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let bytes_read = input.read(&mut buffer).map_err(FluxError::from)?;

            if bytes_read == 0 {
                break; // End of stream
            }

            // Read chunk size first
            let mut size_buffer = [0u8; 4];
            input.read_exact(&mut size_buffer)?;
            let chunk_size = u32::from_be_bytes(size_buffer) as usize;

            // Read the actual encrypted chunk
            let mut encrypted_chunk = vec![0u8; chunk_size];
            input.read_exact(&mut encrypted_chunk)?;

            // Process chunk
            let decrypted_chunk = self.decrypt_chunk(private_key, &encrypted_chunk)?;
            output.write_all(&decrypted_chunk)?;

            total_processed += chunk_size as u64;

            total_processed += bytes_read as u64;

            // Call progress callback if provided
            if let Some(ref callback) = progress {
                callback(total_processed, total_processed);
            }
        }

        Ok(total_processed)
    }

    /// Encrypt a single chunk of data
    fn encrypt_chunk(&self, public_key: &PublicKey, chunk: &[u8]) -> Result<Vec<u8>> {
        let hybrid_cipher = HybridCipher::new(self.config.clone());
        hybrid_cipher.encrypt(public_key, chunk)
    }

    /// Decrypt a single chunk of data
    fn decrypt_chunk(&self, private_key: &PrivateKey, chunk: &[u8]) -> Result<Vec<u8>> {
        let hybrid_cipher = HybridCipher::new(self.config.clone());
        hybrid_cipher.decrypt(private_key, chunk)
    }

    /// Get the chunk size used for streaming
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Get the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl Default for StreamCipher {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl FileStreamCipher {
    /// Create a new file stream cipher
    pub fn new(config: Config) -> Self {
        Self {
            cipher: StreamCipher::new(config),
        }
    }

    /// Encrypt a file
    ///
    /// # Arguments
    /// * `input_path` - Path to the input file
    /// * `output_path` - Path to the output encrypted file
    /// * `public_key` - The public key to encrypt with
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub fn encrypt_file<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        public_key: &PublicKey,
        progress: Option<ProgressCallback>,
    ) -> Result<u64> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        // Check if input file exists
        if !input_path.exists() {
            return Err(FluxError::invalid_input(format!(
                "Input file does not exist: {}",
                input_path.display()
            )));
        }

        // Create parent directory for output if needed
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let input_file = std::fs::File::open(input_path)?;
        let output_file = std::fs::File::create(output_path)?;

        log::info!(
            "Encrypting file: {} -> {}",
            input_path.display(),
            output_path.display()
        );

        let bytes_processed =
            self.cipher
                .encrypt_stream(public_key, input_file, output_file, progress)?;

        log::info!("File encryption completed: {} bytes", bytes_processed);
        Ok(bytes_processed)
    }

    /// Decrypt a file
    ///
    /// # Arguments
    /// * `input_path` - Path to the encrypted input file
    /// * `output_path` - Path to the output decrypted file
    /// * `private_key` - The private key to decrypt with
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub fn decrypt_file<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        private_key: &PrivateKey,
        progress: Option<ProgressCallback>,
    ) -> Result<u64> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        // Check if input file exists
        if !input_path.exists() {
            return Err(FluxError::invalid_input(format!(
                "Input file does not exist: {}",
                input_path.display()
            )));
        }

        // Create parent directory for output if needed
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let input_file = std::fs::File::open(input_path)?;
        let output_file = std::fs::File::create(output_path)?;

        log::info!(
            "Decrypting file: {} -> {}",
            input_path.display(),
            output_path.display()
        );

        let bytes_processed =
            self.cipher
                .decrypt_stream(private_key, input_file, output_file, progress)?;

        log::info!("File decryption completed: {} bytes", bytes_processed);
        Ok(bytes_processed)
    }

    /// Get the underlying stream cipher
    pub fn stream_cipher(&self) -> &StreamCipher {
        &self.cipher
    }
}

impl Default for FileStreamCipher {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use tempfile::tempdir;

    #[test]
    fn test_stream_cipher_creation() {
        let cipher = StreamCipher::default();
        assert_eq!(cipher.chunk_size(), 64 * 1024); // Default 64KB
    }

    #[test]
    fn test_file_stream_cipher_creation() {
        let cipher = FileStreamCipher::default();
        assert_eq!(cipher.stream_cipher().chunk_size(), 64 * 1024);
    }

    #[test]
    fn test_encrypt_stream_basic() {
        use std::io::Cursor;

        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = StreamCipher::default();

        let input = Cursor::new(b"Hello, world!");
        let output = Cursor::new(Vec::new());

        let result = cipher.encrypt_stream(keypair.public_key(), input, output, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 13); // "Hello, world!" is 13 bytes
    }

    #[test]
    fn test_file_not_exists_error() {
        let cipher = FileStreamCipher::default();
        let keypair = KeyPair::generate(2048).unwrap();

        let temp_dir = tempdir().unwrap();
        let input_path = temp_dir.path().join("nonexistent.txt");
        let output_path = temp_dir.path().join("output.enc");

        let result = cipher.encrypt_file(&input_path, &output_path, keypair.public_key(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }
}
