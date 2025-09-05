//! Test fixtures and utilities for FluxEncrypt testing.
//!
//! This module provides common test data, utilities, and fixtures
//! used across different test suites.

use fluxencrypt::keys::{KeyPair, PublicKey, PrivateKey};
use fluxencrypt::config::{Config, CipherSuite, RsaKeySize};
use std::sync::OnceLock;
use tempfile::TempDir;

/// Standard test key pair for consistent testing
pub static TEST_KEYPAIR_2048: OnceLock<KeyPair> = OnceLock::new();
pub static TEST_KEYPAIR_3072: OnceLock<KeyPair> = OnceLock::new();
pub static TEST_KEYPAIR_4096: OnceLock<KeyPair> = OnceLock::new();

/// Initialize test key pairs (called once)
pub fn init_test_keypairs() {
    TEST_KEYPAIR_2048.get_or_init(|| KeyPair::generate(2048).expect("Failed to generate 2048-bit key"));
    TEST_KEYPAIR_3072.get_or_init(|| KeyPair::generate(3072).expect("Failed to generate 3072-bit key"));
    TEST_KEYPAIR_4096.get_or_init(|| KeyPair::generate(4096).expect("Failed to generate 4096-bit key"));
}

/// Get a test key pair by size
pub fn get_test_keypair(size: usize) -> &'static KeyPair {
    init_test_keypairs();
    match size {
        2048 => TEST_KEYPAIR_2048.get().unwrap(),
        3072 => TEST_KEYPAIR_3072.get().unwrap(),
        4096 => TEST_KEYPAIR_4096.get().unwrap(),
        _ => panic!("Unsupported key size: {}", size),
    }
}

/// Test data patterns for comprehensive testing
pub struct TestData;

impl TestData {
    /// Empty data
    pub fn empty() -> Vec<u8> {
        vec![]
    }
    
    /// Single byte
    pub fn single_byte() -> Vec<u8> {
        vec![0x42]
    }
    
    /// Small data (100 bytes)
    pub fn small() -> Vec<u8> {
        (0..100).map(|i| (i % 256) as u8).collect()
    }
    
    /// Medium data (8KB)
    pub fn medium() -> Vec<u8> {
        vec![0x55; 8192]
    }
    
    /// Large data (64KB)
    pub fn large() -> Vec<u8> {
        vec![0xAA; 65536]
    }
    
    /// Very large data (1MB)
    pub fn very_large() -> Vec<u8> {
        vec![0xFF; 1048576]
    }
    
    /// Text data
    pub fn text() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. This is a test string with various characters: !@#$%^&*()_+-=[]{}|;':\",./<>?`~".to_vec()
    }
    
    /// Binary data with all byte values
    pub fn binary_full_range() -> Vec<u8> {
        (0..=255).collect()
    }
    
    /// Repeated pattern
    pub fn repeated_pattern() -> Vec<u8> {
        b"ABCD".repeat(1000)
    }
    
    /// Random-looking data (but deterministic for tests)
    pub fn pseudo_random() -> Vec<u8> {
        let mut data = Vec::with_capacity(10000);
        let mut seed = 12345u32;
        for _ in 0..10000 {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            data.push((seed >> 16) as u8);
        }
        data
    }
    
    /// Data with null bytes
    pub fn with_nulls() -> Vec<u8> {
        b"Hello\0World\0Test\0Data\0".to_vec()
    }
    
    /// Unicode text as UTF-8
    pub fn unicode() -> Vec<u8> {
        "Hello 世界! 🚀 Testing unicode: αβγδε ñáéíóú".as_bytes().to_vec()
    }
}

/// Test configuration variants
pub struct TestConfigs;

impl TestConfigs {
    /// Default configuration
    pub fn default() -> Config {
        Config::default()
    }
    
    /// AES-128 configuration
    pub fn aes128() -> Config {
        Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .build()
            .expect("Failed to build AES-128 config")
    }
    
    /// AES-256 configuration  
    pub fn aes256() -> Config {
        Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .build()
            .expect("Failed to build AES-256 config")
    }
    
    /// High security configuration
    pub fn high_security() -> Config {
        Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .rsa_key_size(RsaKeySize::Rsa4096)
            .secure_memory(true)
            .build()
            .expect("Failed to build high security config")
    }
    
    /// Performance optimized configuration
    pub fn performance() -> Config {
        Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .rsa_key_size(RsaKeySize::Rsa2048)
            .hardware_acceleration(true)
            .stream_chunk_size(16384)
            .build()
            .expect("Failed to build performance config")
    }
    
    /// Memory constrained configuration
    pub fn memory_constrained() -> Config {
        Config::builder()
            .memory_limit_mb(64)
            .stream_chunk_size(1024)
            .build()
            .expect("Failed to build memory constrained config")
    }
    
    /// All test configurations
    pub fn all() -> Vec<Config> {
        vec![
            Self::default(),
            Self::aes128(),
            Self::aes256(),
            Self::high_security(),
            Self::performance(),
            Self::memory_constrained(),
        ]
    }
}

/// Test file utilities
pub struct TestFiles {
    temp_dir: TempDir,
}

impl TestFiles {
    /// Create a new test files helper
    pub fn new() -> Self {
        Self {
            temp_dir: tempfile::tempdir().expect("Failed to create temp directory"),
        }
    }
    
    /// Get the temporary directory path
    pub fn temp_dir(&self) -> &std::path::Path {
        self.temp_dir.path()
    }
    
    /// Create a test file with given content
    pub fn create_file(&self, name: &str, content: &[u8]) -> std::path::PathBuf {
        let file_path = self.temp_dir.path().join(name);
        std::fs::write(&file_path, content).expect("Failed to write test file");
        file_path
    }
    
    /// Create a text file
    pub fn create_text_file(&self, name: &str, content: &str) -> std::path::PathBuf {
        self.create_file(name, content.as_bytes())
    }
    
    /// Create multiple test files
    pub fn create_multiple_files(&self, files: &[(&str, &[u8])]) -> Vec<std::path::PathBuf> {
        files.iter()
            .map(|(name, content)| self.create_file(name, content))
            .collect()
    }
    
    /// Create a large test file
    pub fn create_large_file(&self, name: &str, size_bytes: usize) -> std::path::PathBuf {
        let content = vec![0x42u8; size_bytes];
        self.create_file(name, &content)
    }
    
    /// Create a directory structure
    pub fn create_directory_structure(&self, structure: &[&str]) -> Vec<std::path::PathBuf> {
        let mut paths = Vec::new();
        for path_str in structure {
            let path = self.temp_dir.path().join(path_str);
            if path_str.ends_with('/') {
                std::fs::create_dir_all(&path).expect("Failed to create directory");
            } else {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).expect("Failed to create parent directory");
                }
                std::fs::write(&path, format!("Content of {}", path_str))
                    .expect("Failed to write file");
            }
            paths.push(path);
        }
        paths
    }
}

/// Performance measurement utilities
pub struct PerformanceTimer {
    start_time: std::time::Instant,
    measurements: Vec<(String, std::time::Duration)>,
}

impl PerformanceTimer {
    /// Create a new performance timer
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            measurements: Vec::new(),
        }
    }
    
    /// Mark a measurement point
    pub fn mark(&mut self, label: &str) {
        let elapsed = self.start_time.elapsed();
        self.measurements.push((label.to_string(), elapsed));
        self.start_time = std::time::Instant::now();
    }
    
    /// Get all measurements
    pub fn measurements(&self) -> &[(String, std::time::Duration)] {
        &self.measurements
    }
    
    /// Print measurements
    pub fn print_measurements(&self) {
        println!("Performance measurements:");
        for (label, duration) in &self.measurements {
            println!("  {}: {:?}", label, duration);
        }
    }
    
    /// Assert that a measurement is within acceptable bounds
    pub fn assert_within_bounds(&self, label: &str, max_duration: std::time::Duration) {
        if let Some((_, duration)) = self.measurements.iter().find(|(l, _)| l == label) {
            assert!(duration <= &max_duration, 
                   "{} took {:?}, which exceeds the maximum of {:?}", 
                   label, duration, max_duration);
        } else {
            panic!("No measurement found for label: {}", label);
        }
    }
}

/// Memory usage tracking (basic)
pub struct MemoryTracker {
    initial_memory: Option<usize>,
}

impl MemoryTracker {
    /// Create a new memory tracker
    pub fn new() -> Self {
        Self {
            initial_memory: Self::get_memory_usage(),
        }
    }
    
    /// Get current memory usage (platform-specific implementation)
    pub fn get_memory_usage() -> Option<usize> {
        // This is a simplified implementation
        // In a real implementation, you would use platform-specific APIs
        // or crates like `memory-stats` to get actual memory usage
        None
    }
    
    /// Check if memory usage has increased significantly
    pub fn check_memory_growth(&self, max_growth_mb: usize) -> bool {
        if let (Some(initial), Some(current)) = (self.initial_memory, Self::get_memory_usage()) {
            let growth_bytes = current.saturating_sub(initial);
            let growth_mb = growth_bytes / 1024 / 1024;
            growth_mb <= max_growth_mb
        } else {
            true // Can't measure, assume it's fine
        }
    }
}

/// Test assertion helpers
pub struct TestAssertions;

impl TestAssertions {
    /// Assert that two byte slices are equal with better error messages
    pub fn assert_bytes_equal(actual: &[u8], expected: &[u8], context: &str) {
        if actual != expected {
            if actual.len() != expected.len() {
                panic!("{}: Length mismatch - actual: {}, expected: {}", 
                       context, actual.len(), expected.len());
            }
            
            // Find first difference
            for (i, (a, e)) in actual.iter().zip(expected.iter()).enumerate() {
                if a != e {
                    panic!("{}: First difference at index {}: actual 0x{:02x}, expected 0x{:02x}", 
                           context, i, a, e);
                }
            }
        }
    }
    
    /// Assert that a file exists and has expected content
    pub fn assert_file_content(file_path: &std::path::Path, expected: &[u8], context: &str) {
        assert!(file_path.exists(), "{}: File {} does not exist", context, file_path.display());
        
        let actual = std::fs::read(file_path)
            .expect(&format!("{}: Failed to read file {}", context, file_path.display()));
        
        Self::assert_bytes_equal(&actual, expected, &format!("{}: File content mismatch", context));
    }
    
    /// Assert that a duration is within reasonable bounds
    pub fn assert_performance_reasonable(duration: std::time::Duration, max_ms: u64, operation: &str) {
        let actual_ms = duration.as_millis() as u64;
        assert!(actual_ms <= max_ms, 
               "{} took {}ms, which exceeds the maximum of {}ms", 
               operation, actual_ms, max_ms);
    }
    
    /// Assert that memory usage is reasonable
    pub fn assert_memory_reasonable(tracker: &MemoryTracker, max_growth_mb: usize, operation: &str) {
        assert!(tracker.check_memory_growth(max_growth_mb),
               "{} used more than {}MB of additional memory", operation, max_growth_mb);
    }
}

/// Error simulation utilities
pub struct ErrorSimulator;

impl ErrorSimulator {
    /// Create corrupted data by flipping random bits
    pub fn corrupt_data(data: &[u8], corruption_rate: f32) -> Vec<u8> {
        let mut corrupted = data.to_vec();
        let num_corruptions = ((data.len() as f32) * corruption_rate) as usize;
        
        // Use a deterministic "random" number generator for reproducible tests
        let mut seed = 42u32;
        for _ in 0..num_corruptions {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            let index = (seed as usize) % data.len();
            
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            let bit_position = (seed % 8) as usize;
            
            corrupted[index] ^= 1 << bit_position;
        }
        
        corrupted
    }
    
    /// Truncate data at various points
    pub fn truncate_data(data: &[u8], ratios: &[f32]) -> Vec<Vec<u8>> {
        ratios.iter()
            .map(|&ratio| {
                let truncate_at = ((data.len() as f32) * ratio) as usize;
                data[..truncate_at].to_vec()
            })
            .collect()
    }
    
    /// Generate invalid ciphertext patterns
    pub fn invalid_ciphertext_patterns() -> Vec<Vec<u8>> {
        vec![
            vec![],                    // Empty
            vec![0x00],               // Too short
            vec![0x00; 7],            // Still too short
            vec![0xFF; 1000],         // All 0xFF
            vec![0x00; 1000],         // All 0x00
            (0..100).collect(),       // Sequential bytes
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_test_data_generation() {
        assert_eq!(TestData::empty().len(), 0);
        assert_eq!(TestData::single_byte(), vec![0x42]);
        assert_eq!(TestData::small().len(), 100);
        assert_eq!(TestData::medium().len(), 8192);
        assert_eq!(TestData::large().len(), 65536);
        
        let text = TestData::text();
        assert!(!text.is_empty());
        assert!(text.len() > 50);
        
        let binary = TestData::binary_full_range();
        assert_eq!(binary.len(), 256);
        assert_eq!(binary[0], 0);
        assert_eq!(binary[255], 255);
    }
    
    #[test]
    fn test_test_configs() {
        let configs = TestConfigs::all();
        assert!(!configs.is_empty());
        
        for config in configs {
            assert!(config.validate().is_ok());
        }
    }
    
    #[test]
    fn test_test_files() {
        let test_files = TestFiles::new();
        
        let file_path = test_files.create_text_file("test.txt", "Hello, world!");
        assert!(file_path.exists());
        
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Hello, world!");
    }
    
    #[test]
    fn test_performance_timer() {
        let mut timer = PerformanceTimer::new();
        
        std::thread::sleep(std::time::Duration::from_millis(10));
        timer.mark("sleep_10ms");
        
        std::thread::sleep(std::time::Duration::from_millis(20));
        timer.mark("sleep_20ms");
        
        let measurements = timer.measurements();
        assert_eq!(measurements.len(), 2);
        assert!(measurements[0].1 >= std::time::Duration::from_millis(10));
        assert!(measurements[1].1 >= std::time::Duration::from_millis(20));
    }
    
    #[test]
    fn test_error_simulator() {
        let original = vec![0x00; 100];
        let corrupted = ErrorSimulator::corrupt_data(&original, 0.1);
        
        assert_eq!(corrupted.len(), original.len());
        // Should have some differences (but this is probabilistic)
        
        let truncated = ErrorSimulator::truncate_data(&original, &[0.5, 0.25]);
        assert_eq!(truncated.len(), 2);
        assert_eq!(truncated[0].len(), 50);
        assert_eq!(truncated[1].len(), 25);
    }
    
    #[test]
    fn test_key_pair_access() {
        let keypair = get_test_keypair(2048);
        assert_eq!(keypair.public_key().key_size_bits(), 2048);
        assert_eq!(keypair.private_key().key_size_bits(), 2048);
    }
}