//! Tokio-based async implementations for FluxEncrypt operations.

use fluxencrypt::error::{FluxError, Result};
use fluxencrypt::keys::{PrivateKey, PublicKey};
use fluxencrypt::{Config, HybridCipher};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};

/// Async version of the HybridCipher for non-blocking operations
#[derive(Debug)]
pub struct AsyncHybridCipher {
    cipher: HybridCipher,
}

/// Async file stream cipher for processing large files
#[derive(Debug)]
pub struct AsyncFileStreamCipher {
    cipher: AsyncHybridCipher,
}

/// Progress callback for async operations
pub type AsyncProgressCallback = Box<
    dyn Fn(u64, u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

impl AsyncHybridCipher {
    /// Create a new async hybrid cipher
    pub fn new(config: Config) -> Self {
        Self {
            cipher: HybridCipher::new(config),
        }
    }

    /// Encrypt data asynchronously
    ///
    /// This method uses `tokio::task::spawn_blocking` to run the CPU-intensive
    /// encryption operation on a thread pool, preventing blocking of the async runtime.
    ///
    /// # Arguments
    /// * `public_key` - The RSA public key to encrypt with
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    /// The encrypted data as a byte vector
    pub async fn encrypt_async(&self, public_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        let public_key = public_key.clone();
        let plaintext = plaintext.to_vec();
        let cipher = self.cipher.clone();

        tokio::task::spawn_blocking(move || cipher.encrypt(&public_key, &plaintext))
            .await
            .map_err(|e| FluxError::other(e.into()))?
    }

    /// Decrypt data asynchronously
    ///
    /// This method uses `tokio::task::spawn_blocking` to run the CPU-intensive
    /// decryption operation on a thread pool, preventing blocking of the async runtime.
    ///
    /// # Arguments
    /// * `private_key` - The RSA private key to decrypt with
    /// * `ciphertext` - The encrypted data
    ///
    /// # Returns
    /// The decrypted data as a byte vector
    pub async fn decrypt_async(
        &self,
        private_key: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let private_key = private_key.clone();
        let ciphertext = ciphertext.to_vec();
        let cipher = self.cipher.clone();

        tokio::task::spawn_blocking(move || cipher.decrypt(&private_key, &ciphertext))
            .await
            .map_err(|e| FluxError::other(e.into()))?
    }

    /// Encrypt data from an async reader and write to an async writer
    ///
    /// # Arguments
    /// * `public_key` - The RSA public key to encrypt with
    /// * `reader` - The async reader to read plaintext from
    /// * `writer` - The async writer to write ciphertext to
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub async fn encrypt_stream_async<R, W>(
        &self,
        public_key: &PublicKey,
        mut reader: R,
        mut writer: W,
        progress: Option<AsyncProgressCallback>,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        use tokio::io::AsyncWriteExt;

        let mut stream_state = StreamState::new(self.cipher.config().stream_chunk_size);

        while let Some(chunk) = read_next_chunk(&mut reader, &mut stream_state).await? {
            let encrypted_chunk = encrypt_chunk_blocking(public_key, &chunk, self).await?;

            writer.write_all(&encrypted_chunk).await?;
            stream_state.add_processed(chunk.len() as u64);

            if let Some(ref callback) = progress {
                callback(stream_state.total_processed, stream_state.total_processed).await;
            }
        }

        writer.flush().await?;
        Ok(stream_state.total_processed)
    }

    /// Decrypt data from an async reader and write to an async writer
    ///
    /// # Arguments
    /// * `private_key` - The RSA private key to decrypt with
    /// * `reader` - The async reader to read ciphertext from
    /// * `writer` - The async writer to write plaintext to
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub async fn decrypt_stream_async<R, W>(
        &self,
        private_key: &PrivateKey,
        mut reader: R,
        mut writer: W,
        progress: Option<AsyncProgressCallback>,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        use tokio::io::AsyncWriteExt;

        let mut stream_state = StreamState::new(self.cipher.config().stream_chunk_size);

        while let Some(chunk) = read_next_chunk(&mut reader, &mut stream_state).await? {
            let decrypted_chunk = decrypt_chunk_blocking(private_key, &chunk, self).await?;

            writer.write_all(&decrypted_chunk).await?;
            stream_state.add_processed(chunk.len() as u64);

            if let Some(ref callback) = progress {
                callback(stream_state.total_processed, stream_state.total_processed).await;
            }
        }

        writer.flush().await?;
        Ok(stream_state.total_processed)
    }

    /// Get the underlying sync cipher
    pub fn inner(&self) -> &HybridCipher {
        &self.cipher
    }
}

impl Default for AsyncHybridCipher {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl AsyncFileStreamCipher {
    /// Create a new async file stream cipher
    pub fn new(config: Config) -> Self {
        Self {
            cipher: AsyncHybridCipher::new(config),
        }
    }

    /// Encrypt a file asynchronously
    ///
    /// # Arguments
    /// * `input_path` - Path to the input file
    /// * `output_path` - Path to the output encrypted file
    /// * `public_key` - The public key to encrypt with
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub async fn encrypt_file_async<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        public_key: &PublicKey,
        progress: Option<AsyncProgressCallback>,
    ) -> Result<u64> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        // Open files asynchronously
        let input_file = tokio::fs::File::open(input_path).await.map_err(|e| {
            FluxError::invalid_input(format!(
                "Cannot open input file {}: {}",
                input_path.display(),
                e
            ))
        })?;

        // Create parent directory for output if needed
        if let Some(parent) = output_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let output_file = tokio::fs::File::create(output_path).await.map_err(|e| {
            FluxError::invalid_input(format!(
                "Cannot create output file {}: {}",
                output_path.display(),
                e
            ))
        })?;

        log::info!(
            "Async encrypting file: {} -> {}",
            input_path.display(),
            output_path.display()
        );

        // Encrypt the file
        let bytes_processed = self
            .cipher
            .encrypt_stream_async(public_key, input_file, output_file, progress)
            .await?;

        log::info!("Async file encryption completed: {} bytes", bytes_processed);
        Ok(bytes_processed)
    }

    /// Decrypt a file asynchronously
    ///
    /// # Arguments
    /// * `input_path` - Path to the encrypted input file
    /// * `output_path` - Path to the output decrypted file
    /// * `private_key` - The private key to decrypt with
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// The number of bytes processed
    pub async fn decrypt_file_async<P: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: P,
        private_key: &PrivateKey,
        progress: Option<AsyncProgressCallback>,
    ) -> Result<u64> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        // Open files asynchronously
        let input_file = tokio::fs::File::open(input_path).await.map_err(|e| {
            FluxError::invalid_input(format!(
                "Cannot open input file {}: {}",
                input_path.display(),
                e
            ))
        })?;

        // Create parent directory for output if needed
        if let Some(parent) = output_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let output_file = tokio::fs::File::create(output_path).await.map_err(|e| {
            FluxError::invalid_input(format!(
                "Cannot create output file {}: {}",
                output_path.display(),
                e
            ))
        })?;

        log::info!(
            "Async decrypting file: {} -> {}",
            input_path.display(),
            output_path.display()
        );

        // Decrypt the file
        let bytes_processed = self
            .cipher
            .decrypt_stream_async(private_key, input_file, output_file, progress)
            .await?;

        log::info!("Async file decryption completed: {} bytes", bytes_processed);
        Ok(bytes_processed)
    }

    /// Get the underlying async cipher
    pub fn cipher(&self) -> &AsyncHybridCipher {
        &self.cipher
    }
}

impl Default for AsyncFileStreamCipher {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Process multiple encryption operations concurrently
pub async fn encrypt_multiple_async(
    cipher: &AsyncHybridCipher,
    public_key: &PublicKey,
    data_chunks: Vec<Vec<u8>>,
    max_concurrent: Option<usize>,
) -> Result<Vec<Result<Vec<u8>>>> {
    use futures::stream::{FuturesUnordered, StreamExt};

    let max_concurrent = max_concurrent.unwrap_or(10);
    let mut futures = FuturesUnordered::new();
    let mut results = Vec::new();

    for chunk in data_chunks {
        if futures.len() >= max_concurrent {
            if let Some(result) = futures.next().await {
                results.push(result);
            }
        }

        // Clone chunk to avoid lifetime issues
        let chunk_owned = chunk.clone();
        let future = async move { cipher.encrypt_async(public_key, &chunk_owned).await };
        futures.push(future);
    }

    // Collect remaining results
    while let Some(result) = futures.next().await {
        results.push(result);
    }

    Ok(results)
}

/// Process multiple decryption operations concurrently
pub async fn decrypt_multiple_async(
    cipher: &AsyncHybridCipher,
    private_key: &PrivateKey,
    ciphertext_chunks: Vec<Vec<u8>>,
    max_concurrent: Option<usize>,
) -> Result<Vec<Result<Vec<u8>>>> {
    use futures::stream::{FuturesUnordered, StreamExt};

    let max_concurrent = max_concurrent.unwrap_or(10);
    let mut futures = FuturesUnordered::new();
    let mut results = Vec::new();

    for chunk in ciphertext_chunks {
        if futures.len() >= max_concurrent {
            if let Some(result) = futures.next().await {
                results.push(result);
            }
        }

        // Clone chunk to avoid lifetime issues
        let chunk_owned = chunk.clone();
        let future = async move { cipher.decrypt_async(private_key, &chunk_owned).await };
        futures.push(future);
    }

    // Collect remaining results
    while let Some(result) = futures.next().await {
        results.push(result);
    }

    Ok(results)
}

/// State tracking for streaming operations
#[derive(Debug)]
struct StreamState {
    pub total_processed: u64,
    pub buffer: Vec<u8>,
}

impl StreamState {
    fn new(chunk_size: usize) -> Self {
        Self {
            total_processed: 0,
            buffer: vec![0u8; chunk_size],
        }
    }

    fn add_processed(&mut self, bytes: u64) {
        self.total_processed += bytes;
    }
}

/// Read the next chunk from an async reader
async fn read_next_chunk<R>(reader: &mut R, state: &mut StreamState) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let bytes_read = reader.read(&mut state.buffer).await?;

    if bytes_read == 0 {
        return Ok(None);
    }

    Ok(Some(state.buffer[..bytes_read].to_vec()))
}

/// Encrypt a chunk using blocking task
async fn encrypt_chunk_blocking(
    public_key: &PublicKey,
    chunk: &[u8],
    cipher: &AsyncHybridCipher,
) -> Result<Vec<u8>> {
    let public_key_clone = public_key.clone();
    let chunk_clone = chunk.to_vec();
    let cipher_clone = cipher.cipher.clone();

    tokio::task::spawn_blocking(move || cipher_clone.encrypt(&public_key_clone, &chunk_clone))
        .await
        .map_err(|e| FluxError::other(e.into()))?
}

/// Decrypt a chunk using blocking task
async fn decrypt_chunk_blocking(
    private_key: &PrivateKey,
    chunk: &[u8],
    cipher: &AsyncHybridCipher,
) -> Result<Vec<u8>> {
    let private_key_clone = private_key.clone();
    let chunk_clone = chunk.to_vec();
    let cipher_clone = cipher.cipher.clone();

    tokio::task::spawn_blocking(move || cipher_clone.decrypt(&private_key_clone, &chunk_clone))
        .await
        .map_err(|e| FluxError::other(e.into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxencrypt::keys::KeyPair;

    #[tokio::test]
    async fn test_async_cipher_creation() {
        let cipher = AsyncHybridCipher::default();
        assert!(cipher.inner().config().validate().is_ok());
    }

    #[tokio::test]
    async fn test_async_file_cipher_creation() {
        let cipher = AsyncFileStreamCipher::default();
        assert!(cipher.cipher().inner().config().validate().is_ok());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_async_basic() {
        let keypair = KeyPair::generate(2048).unwrap();
        let cipher = AsyncHybridCipher::default();
        let plaintext = b"Hello, async world!";

        let ciphertext = cipher
            .encrypt_async(keypair.public_key(), plaintext)
            .await
            .unwrap();
        assert!(!ciphertext.is_empty());

        let decrypted = cipher
            .decrypt_async(keypair.private_key(), &ciphertext)
            .await
            .unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
