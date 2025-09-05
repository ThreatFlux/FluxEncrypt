//! Batch processing functionality for multiple files and operations.
//!
//! This module provides utilities for processing multiple files in parallel
//! using Rayon for improved performance when dealing with large numbers of
//! files or operations.

use crate::config::Config;
use crate::error::{FluxError, Result};
use crate::keys::{PrivateKey, PublicKey};
use crate::stream::{cipher::ProgressCallback, FileStreamCipher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Type alias for batch operation results
type BatchOperationResult = Result<(usize, u64, Vec<(PathBuf, String)>)>;

/// Batch processor for multiple file operations
#[derive(Debug)]
pub struct BatchProcessor {
    cipher: FileStreamCipher,
    parallel: bool,
}

/// Result of a batch operation
#[derive(Debug)]
pub struct BatchResult {
    /// Total number of files processed successfully
    pub processed_count: usize,
    /// Total number of bytes processed
    pub total_bytes: u64,
    /// Files that failed to process
    pub failed_files: Vec<(PathBuf, String)>,
    /// Processing duration
    pub duration: std::time::Duration,
}

/// Configuration for batch operations
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Whether to continue processing on error
    pub continue_on_error: bool,
    /// Maximum number of parallel operations
    pub max_parallel: Option<usize>,
    /// File name pattern for output files
    pub output_pattern: Option<String>,
    /// Whether to preserve directory structure
    pub preserve_structure: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            continue_on_error: true,
            max_parallel: None, // Use default Rayon thread pool
            output_pattern: None,
            preserve_structure: true,
        }
    }
}

impl BatchProcessor {
    /// Create a new batch processor
    pub fn new(config: Config) -> Self {
        Self {
            cipher: FileStreamCipher::new(config),
            parallel: true,
        }
    }

    /// Create a batch processor without parallel processing
    pub fn sequential(config: Config) -> Self {
        Self {
            cipher: FileStreamCipher::new(config),
            parallel: false,
        }
    }

    /// Encrypt multiple files in batch
    ///
    /// # Arguments
    /// * `input_files` - List of input file paths
    /// * `output_dir` - Directory to write encrypted files to
    /// * `public_key` - The public key to encrypt with
    /// * `batch_config` - Batch processing configuration
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// Batch processing results
    pub fn encrypt_files<P: AsRef<Path>>(
        &self,
        input_files: &[P],
        output_dir: P,
        public_key: &PublicKey,
        batch_config: &BatchConfig,
        progress: Option<ProgressCallback>,
    ) -> Result<BatchResult> {
        let start_time = std::time::Instant::now();
        let output_dir = output_dir.as_ref();

        // Create output directory
        std::fs::create_dir_all(output_dir)?;

        // Prepare file pairs
        let file_pairs: Vec<_> = input_files
            .iter()
            .map(|input| {
                let input_path = input.as_ref();
                let output_path = self.build_output_path(input_path, output_dir, batch_config);
                (input_path.to_path_buf(), output_path)
            })
            .collect();

        // Process files
        let result = if self.parallel {
            self.encrypt_files_parallel(&file_pairs, public_key, batch_config, progress)
        } else {
            self.encrypt_files_sequential(&file_pairs, public_key, batch_config, progress)
        }?;

        Ok(BatchResult {
            processed_count: result.0,
            total_bytes: result.1,
            failed_files: result.2,
            duration: start_time.elapsed(),
        })
    }

    /// Decrypt multiple files in batch
    ///
    /// # Arguments
    /// * `input_files` - List of encrypted input file paths
    /// * `output_dir` - Directory to write decrypted files to
    /// * `private_key` - The private key to decrypt with
    /// * `batch_config` - Batch processing configuration
    /// * `progress` - Optional progress callback
    ///
    /// # Returns
    /// Batch processing results
    pub fn decrypt_files<P: AsRef<Path>>(
        &self,
        input_files: &[P],
        output_dir: P,
        private_key: &PrivateKey,
        batch_config: &BatchConfig,
        progress: Option<ProgressCallback>,
    ) -> Result<BatchResult> {
        let start_time = std::time::Instant::now();
        let output_dir = output_dir.as_ref();

        // Create output directory
        std::fs::create_dir_all(output_dir)?;

        // Prepare file pairs
        let file_pairs: Vec<_> = input_files
            .iter()
            .map(|input| {
                let input_path = input.as_ref();
                let output_path = self.build_output_path(input_path, output_dir, batch_config);
                (input_path.to_path_buf(), output_path)
            })
            .collect();

        // Process files
        let result = if self.parallel {
            self.decrypt_files_parallel(&file_pairs, private_key, batch_config, progress)
        } else {
            self.decrypt_files_sequential(&file_pairs, private_key, batch_config, progress)
        }?;

        Ok(BatchResult {
            processed_count: result.0,
            total_bytes: result.1,
            failed_files: result.2,
            duration: start_time.elapsed(),
        })
    }

    /// Find files in a directory matching a pattern
    pub fn find_files<P: AsRef<Path>>(
        &self,
        directory: P,
        pattern: Option<&str>,
        recursive: bool,
    ) -> Result<Vec<PathBuf>> {
        let directory = directory.as_ref();

        if !directory.is_dir() {
            return Err(FluxError::invalid_input(format!(
                "Not a directory: {}",
                directory.display()
            )));
        }

        let mut files = Vec::new();
        Self::find_files_recursive(directory, pattern, recursive, &mut files)?;

        Ok(files)
    }

    /// Encrypt files parallel implementation
    #[cfg(feature = "parallel")]
    fn encrypt_files_parallel(
        &self,
        file_pairs: &[(PathBuf, PathBuf)],
        public_key: &PublicKey,
        batch_config: &BatchConfig,
        progress: Option<ProgressCallback>,
    ) -> BatchOperationResult {
        use rayon::prelude::*;

        let processed_count = Arc::new(AtomicU64::new(0));
        let total_bytes = Arc::new(AtomicU64::new(0));
        let failed_files = Arc::new(std::sync::Mutex::new(Vec::new()));

        let results: Vec<_> = file_pairs
            .par_iter()
            .map(|(input_path, output_path)| {
                let result = self
                    .cipher
                    .encrypt_file(input_path, output_path, public_key, None);

                match result {
                    Ok(bytes) => {
                        processed_count.fetch_add(1, Ordering::Relaxed);
                        total_bytes.fetch_add(bytes, Ordering::Relaxed);

                        // Call progress callback if provided
                        if let Some(ref callback) = progress {
                            let current_processed = processed_count.load(Ordering::Relaxed);
                            callback(current_processed, file_pairs.len() as u64);
                        }

                        Ok(())
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        failed_files
                            .lock()
                            .unwrap()
                            .push((input_path.clone(), error_msg.clone()));

                        if !batch_config.continue_on_error {
                            return Err(e);
                        }

                        log::warn!("Failed to encrypt {}: {}", input_path.display(), error_msg);
                        Ok(())
                    }
                }
            })
            .collect();

        // Check if any operations failed and continue_on_error is false
        for result in results {
            result?;
        }

        let final_processed = processed_count.load(Ordering::Relaxed) as usize;
        let final_bytes = total_bytes.load(Ordering::Relaxed);
        let final_failed = Arc::try_unwrap(failed_files).unwrap().into_inner().unwrap();

        Ok((final_processed, final_bytes, final_failed))
    }

    /// Encrypt files sequential implementation (fallback when parallel feature is disabled)
    #[cfg(not(feature = "parallel"))]
    fn encrypt_files_parallel(
        &self,
        file_pairs: &[(PathBuf, PathBuf)],
        public_key: &PublicKey,
        batch_config: &BatchConfig,
        progress: Option<ProgressCallback>,
    ) -> BatchOperationResult {
        self.encrypt_files_sequential(file_pairs, public_key, batch_config, progress)
    }

    /// Encrypt files sequentially
    fn encrypt_files_sequential(
        &self,
        file_pairs: &[(PathBuf, PathBuf)],
        public_key: &PublicKey,
        _batch_config: &BatchConfig,
        progress: Option<ProgressCallback>,
    ) -> BatchOperationResult {
        let mut processed_count = 0;
        let mut total_bytes = 0u64;
        let mut failed_files = Vec::new();

        for (i, (input_path, output_path)) in file_pairs.iter().enumerate() {
            match self
                .cipher
                .encrypt_file(input_path, output_path, public_key, None)
            {
                Ok(bytes) => {
                    processed_count += 1;
                    total_bytes += bytes;
                }
                Err(e) => {
                    failed_files.push((input_path.clone(), e.to_string()));
                    log::warn!("Failed to encrypt {}: {}", input_path.display(), e);
                }
            }

            // Call progress callback if provided
            if let Some(ref callback) = progress {
                callback((i + 1) as u64, file_pairs.len() as u64);
            }
        }

        Ok((processed_count, total_bytes, failed_files))
    }

    /// Decrypt files (parallel and sequential implementations similar to encrypt)
    #[cfg(feature = "parallel")]
    fn decrypt_files_parallel(
        &self,
        _file_pairs: &[(PathBuf, PathBuf)],
        _private_key: &PrivateKey,
        _batch_config: &BatchConfig,
        _progress: Option<ProgressCallback>,
    ) -> BatchOperationResult {
        // TODO: Implement similar to encrypt_files_parallel
        unimplemented!("Parallel decrypt not yet implemented")
    }

    #[cfg(not(feature = "parallel"))]
    fn decrypt_files_parallel(
        &self,
        file_pairs: &[(PathBuf, PathBuf)],
        private_key: &PrivateKey,
        batch_config: &BatchConfig,
        progress: Option<ProgressCallback>,
    ) -> BatchOperationResult {
        self.decrypt_files_sequential(file_pairs, private_key, batch_config, progress)
    }

    fn decrypt_files_sequential(
        &self,
        file_pairs: &[(PathBuf, PathBuf)],
        private_key: &PrivateKey,
        _batch_config: &BatchConfig,
        progress: Option<ProgressCallback>,
    ) -> BatchOperationResult {
        let mut processed_count = 0;
        let mut total_bytes = 0u64;
        let mut failed_files = Vec::new();

        for (i, (input_path, output_path)) in file_pairs.iter().enumerate() {
            match self
                .cipher
                .decrypt_file(input_path, output_path, private_key, None)
            {
                Ok(bytes) => {
                    processed_count += 1;
                    total_bytes += bytes;
                }
                Err(e) => {
                    failed_files.push((input_path.clone(), e.to_string()));
                    log::warn!("Failed to decrypt {}: {}", input_path.display(), e);
                }
            }

            // Call progress callback if provided
            if let Some(ref callback) = progress {
                callback((i + 1) as u64, file_pairs.len() as u64);
            }
        }

        Ok((processed_count, total_bytes, failed_files))
    }

    /// Build output path for a file
    fn build_output_path(
        &self,
        input_path: &Path,
        output_dir: &Path,
        batch_config: &BatchConfig,
    ) -> PathBuf {
        let file_name = input_path.file_name().unwrap().to_string_lossy();

        let output_name = if let Some(pattern) = &batch_config.output_pattern {
            pattern.replace("{name}", &file_name)
        } else {
            format!("{}.enc", file_name)
        };

        if batch_config.preserve_structure {
            if let Some(parent) = input_path.parent() {
                output_dir.join(parent).join(output_name)
            } else {
                output_dir.join(output_name)
            }
        } else {
            output_dir.join(output_name)
        }
    }

    /// Recursive file finding implementation
    fn find_files_recursive(
        directory: &Path,
        pattern: Option<&str>,
        recursive: bool,
        files: &mut Vec<PathBuf>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let matches = if let Some(pattern) = pattern {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.contains(pattern))
                } else {
                    true
                };

                if matches {
                    files.push(path);
                }
            } else if path.is_dir() && recursive {
                Self::find_files_recursive(&path, pattern, recursive, files)?;
            }
        }

        Ok(())
    }
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_batch_processor_creation() {
        let processor = BatchProcessor::default();
        assert!(processor.parallel);

        let processor = BatchProcessor::sequential(Config::default());
        assert!(!processor.parallel);
    }

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert!(config.continue_on_error);
        assert!(config.preserve_structure);
        assert!(config.max_parallel.is_none());
        assert!(config.output_pattern.is_none());
    }

    #[test]
    fn test_find_files_empty_directory() {
        let processor = BatchProcessor::default();
        let temp_dir = tempdir().unwrap();

        let files = processor.find_files(temp_dir.path(), None, false).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_output_path_building() {
        let processor = BatchProcessor::default();
        let config = BatchConfig::default();

        let input = Path::new("/path/to/file.txt");
        let output_dir = Path::new("/output");

        let output_path = processor.build_output_path(input, output_dir, &config);

        // Should preserve structure and add .enc extension
        assert!(output_path.to_string_lossy().contains("file.txt.enc"));
    }
}
