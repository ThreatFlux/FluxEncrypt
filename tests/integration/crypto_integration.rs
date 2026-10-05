//! Comprehensive integration tests for FluxEncrypt crypto functionality.
//!
//! These tests verify that all cryptographic components work together correctly
//! and provide the expected security properties.

use fluxencrypt::config::{CipherSuite, KeyDerivation, RsaKeySize};
use fluxencrypt::keys::{
    KeyPair,
    storage::{KeyStorage, StorageOptions},
};
use fluxencrypt::stream::{BatchProcessor, FileStreamCipher};
use fluxencrypt::{Config, Cryptum, HybridCipher};
use std::fs;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[test]
fn test_full_encryption_pipeline() {
    // Test the complete encryption pipeline from key generation to decryption
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");

    // Test different cipher suites
    for cipher_suite in &[CipherSuite::Aes128Gcm, CipherSuite::Aes256Gcm] {
        let config = Config::builder()
            .cipher_suite(*cipher_suite)
            .build()
            .expect("Failed to build config");

        let cipher = HybridCipher::new(config);

        // Test various data sizes
        let test_data = [
            vec![],            // Empty data
            vec![0x42; 1],     // Single byte
            vec![0x55; 100],   // Small data
            vec![0xAA; 8192],  // Medium data
            vec![0xFF; 65536], // Large data
        ];

        for (i, plaintext) in test_data.iter().enumerate() {
            let ciphertext = cipher
                .encrypt(keypair.public_key(), plaintext)
                .unwrap_or_else(|error| {
                    panic!(
                        "Encryption failed for test case {} with {:?}: {error}",
                        i, cipher_suite
                    )
                });

            let decrypted = cipher
                .decrypt(keypair.private_key(), &ciphertext)
                .unwrap_or_else(|error| {
                    panic!(
                        "Decryption failed for test case {} with {:?}: {error}",
                        i, cipher_suite
                    )
                });

            assert_eq!(
                decrypted, *plaintext,
                "Decrypted data doesn't match for test case {} with {:?}",
                i, cipher_suite
            );
        }
    }
}

#[test]
fn test_cryptum_api_integration() {
    let cryptum = Cryptum::with_defaults().expect("Failed to create Cryptum instance");
    let keypair = cryptum
        .generate_keypair(2048)
        .expect("Failed to generate keypair");

    let test_data = b"Testing Cryptum API integration";

    // Test basic encryption/decryption
    let ciphertext = cryptum
        .encrypt(keypair.public_key(), test_data)
        .expect("Cryptum encryption failed");
    let decrypted = cryptum
        .decrypt(keypair.private_key(), &ciphertext)
        .expect("Cryptum decryption failed");

    assert_eq!(decrypted, test_data);

    // Test file encryption/decryption
    let temp_dir = tempdir().expect("Failed to create temp dir");

    let input_file = temp_dir.path().join("test_input.txt");
    let encrypted_file = temp_dir.path().join("test_encrypted.enc");
    let output_file = temp_dir.path().join("test_output.txt");

    fs::write(&input_file, test_data).expect("Failed to write test file");

    let encrypted_bytes = cryptum
        .encrypt_file(&input_file, &encrypted_file, keypair.public_key())
        .expect("File encryption failed");

    assert!(encrypted_file.exists());
    assert!(encrypted_bytes > 0);

    let decrypted_bytes = cryptum
        .decrypt_file(&encrypted_file, &output_file, keypair.private_key())
        .expect("File decryption failed");

    assert_eq!(encrypted_bytes, test_data.len() as u64);
    assert!(decrypted_bytes > encrypted_bytes);

    let decrypted_content = fs::read(&output_file).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, test_data);
}

#[test]
fn test_key_storage_integration() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let keypair = KeyPair::generate(3072).expect("Failed to generate key pair");

    // Test key storage and loading
    let storage = KeyStorage::with_encryption();
    let public_key_path = temp_dir.path().join("test_public.pem");
    let private_key_path = temp_dir.path().join("test_private.pem");

    let options = StorageOptions {
        overwrite: true,
        password: Some("test_password".to_string()),
        ..Default::default()
    };

    // Save key pair
    storage
        .save_keypair(&keypair, &public_key_path, &private_key_path, &options)
        .expect("Failed to save key pair");

    assert!(public_key_path.exists());
    assert!(private_key_path.exists());
    assert!(
        fs::read_to_string(&private_key_path)
            .unwrap()
            .contains("BEGIN ENCRYPTED PRIVATE KEY")
    );
    assert!(
        storage
            .load_private_key(&private_key_path, Some("wrong password"))
            .is_err()
    );

    // Load keys
    let loaded_public = storage
        .load_public_key(&public_key_path)
        .expect("Failed to load public key");
    let loaded_private = storage
        .load_private_key(&private_key_path, options.password.as_deref())
        .expect("Failed to load private key");

    assert_hybrid_roundtrip(
        &loaded_public,
        &loaded_private,
        b"Key storage integration test",
    );
}

fn assert_hybrid_roundtrip(
    public: &fluxencrypt::keys::PublicKey,
    private: &fluxencrypt::keys::PrivateKey,
    plaintext: &[u8],
) {
    let cipher = HybridCipher::default();
    let encrypted = cipher
        .encrypt(public, plaintext)
        .expect("encrypt loaded key");
    assert_eq!(
        cipher
            .decrypt(private, &encrypted)
            .expect("decrypt loaded key"),
        plaintext
    );
}

#[test]
fn test_config_variations() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let test_data = b"Configuration variation test";

    // Test different configuration combinations
    let configs = [
        Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .rsa_key_size(RsaKeySize::Rsa2048)
            .memory_limit_mb(256)
            .build()
            .expect("Config build failed"),
        Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .rsa_key_size(RsaKeySize::Rsa3072)
            .key_derivation(KeyDerivation::Pbkdf2 {
                iterations: 100_000,
                salt_len: 32,
            })
            .build()
            .expect("Config build failed"),
        Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .rsa_key_size(RsaKeySize::Rsa4096)
            .hardware_acceleration(false)
            .secure_memory(true)
            .build()
            .expect("Config build failed"),
    ];

    for (i, config) in configs.iter().enumerate() {
        assert!(config.validate().is_ok(), "Config {} should be valid", i);

        let cipher = HybridCipher::new(config.clone());

        let ciphertext = cipher
            .encrypt(keypair.public_key(), test_data)
            .unwrap_or_else(|error| panic!("Encryption failed for config {}: {error}", i));
        let decrypted = cipher
            .decrypt(keypair.private_key(), &ciphertext)
            .unwrap_or_else(|error| panic!("Decryption failed for config {}: {error}", i));

        assert_eq!(decrypted, test_data, "Data mismatch for config {}", i);
    }
}

#[test]
fn test_concurrent_operations() {
    use std::thread;

    let keypair = Arc::new(KeyPair::generate(2048).expect("Failed to generate key pair"));
    let cipher = Arc::new(HybridCipher::default());

    let mut handles = vec![];

    // Perform concurrent encryption/decryption operations
    for i in 0..10 {
        let keypair_clone = keypair.clone();
        let cipher_clone = cipher.clone();

        let handle = thread::spawn(move || {
            let test_data = format!("Concurrent test data {}", i);
            let plaintext = test_data.as_bytes();

            let ciphertext = cipher_clone
                .encrypt(keypair_clone.public_key(), plaintext)
                .expect("Concurrent encryption failed");
            let decrypted = cipher_clone
                .decrypt(keypair_clone.private_key(), &ciphertext)
                .expect("Concurrent decryption failed");

            assert_eq!(decrypted, plaintext);
            i
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let thread_id = handle.join().expect("Thread panicked");
        println!("Thread {} completed successfully", thread_id);
    }
}

#[test]
fn test_stream_cipher_integration() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let temp_dir = tempdir().expect("Failed to create temp dir");

    let (input_file, test_data) = write_stream_input(temp_dir.path());
    let config = stream_test_config();
    let cipher = FileStreamCipher::new(config);

    let encrypted_file = temp_dir.path().join("large_encrypted.enc");
    let decrypted_file = temp_dir.path().join("large_decrypted.txt");

    // Encrypt
    let (encrypt_progress, progress_callback) = tracked_progress();

    let encrypted_bytes = cipher
        .encrypt_file(
            &input_file,
            &encrypted_file,
            keypair.public_key(),
            progress_callback,
        )
        .expect("Stream encryption failed");

    assert!(encrypted_bytes > 0);
    assert!(encrypted_file.exists());
    assert!(*encrypt_progress.lock().unwrap() > 0);

    // Decrypt
    let (decrypt_progress, progress_callback) = tracked_progress();

    let decrypted_bytes = cipher
        .decrypt_file(
            &encrypted_file,
            &decrypted_file,
            keypair.private_key(),
            progress_callback,
        )
        .expect("Stream decryption failed");

    assert_eq!(encrypted_bytes, test_data.len() as u64);
    assert_eq!(decrypted_bytes, *decrypt_progress.lock().unwrap());
    assert!(decrypted_bytes > encrypted_bytes);
    assert!(*decrypt_progress.lock().unwrap() > 0);

    // Verify content
    let decrypted_content =
        fs::read_to_string(&decrypted_file).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, test_data);
}

fn write_stream_input(root: &std::path::Path) -> (std::path::PathBuf, String) {
    let content = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n".repeat(1000);
    let path = root.join("large_input.txt");
    fs::write(&path, &content).expect("write stream input");
    (path, content)
}

fn stream_test_config() -> Config {
    Config::builder()
        .stream_chunk_size(4096)
        .build()
        .expect("stream config")
}

fn tracked_progress() -> (
    Arc<Mutex<u64>>,
    Option<fluxencrypt::stream::ProgressCallback>,
) {
    let progress = Arc::new(Mutex::new(0));
    let captured = Arc::clone(&progress);
    let callback = Box::new(move |processed: u64, _total: u64| {
        *captured.lock().unwrap() = processed;
    }) as fluxencrypt::stream::ProgressCallback;
    (progress, Some(callback))
}

#[test]
fn test_batch_processing() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let temp_dir = tempdir().expect("Failed to create temp dir");

    // Create multiple test files
    let test_files = vec![
        ("file1.txt", "First test file content"),
        ("file2.txt", "Second test file content with more data"),
        ("file3.txt", "Third file content"),
    ];

    let (input_files, expected_outputs) = create_batch_inputs(temp_dir.path(), &test_files);

    // Test batch encryption
    let config = Config::default();
    let batch_processor = BatchProcessor::new(config.clone());

    let encrypted_dir = temp_dir.path().join("encrypted");
    fs::create_dir(&encrypted_dir).expect("Failed to create encrypted directory");

    let result = batch_processor
        .encrypt_files(
            &input_files,
            encrypted_dir.clone(),
            keypair.public_key(),
            &fluxencrypt::stream::batch::BatchConfig {
                preserve_structure: false,
                ..Default::default()
            },
            None,
        )
        .expect("Batch encryption failed");
    assert_eq!(result.processed_count, test_files.len());
    assert!(result.failed_files.is_empty());
    let encrypted_files: Vec<_> = input_files
        .iter()
        .map(|input| {
            encrypted_dir.join(format!(
                "{}.enc",
                input.file_name().unwrap().to_str().unwrap()
            ))
        })
        .collect();
    for encrypted_file in &encrypted_files {
        assert!(encrypted_file.exists());
    }

    verify_batch_outputs(
        &config,
        temp_dir.path(),
        keypair.private_key(),
        &encrypted_files,
        &expected_outputs,
    );
}

fn verify_batch_outputs(
    config: &Config,
    root: &std::path::Path,
    private_key: &fluxencrypt::keys::PrivateKey,
    encrypted_files: &[std::path::PathBuf],
    expected_outputs: &[Vec<u8>],
) {
    // Verify decryption
    let decrypted_dir = root.join("decrypted");
    fs::create_dir(&decrypted_dir).expect("Failed to create decrypted directory");

    for (i, encrypted_file) in encrypted_files.iter().enumerate() {
        let decrypted_file = decrypted_dir.join(format!("decrypted_{}.txt", i));
        let cipher = FileStreamCipher::new(config.clone());
        cipher
            .decrypt_file(encrypted_file, &decrypted_file, private_key, None)
            .expect("Batch decryption failed");

        let content = fs::read(&decrypted_file).expect("Failed to read decrypted file");
        assert_eq!(content, expected_outputs[i]);
    }
}

fn create_batch_inputs(
    root: &std::path::Path,
    files: &[(&str, &str)],
) -> (Vec<std::path::PathBuf>, Vec<Vec<u8>>) {
    let mut inputs = Vec::new();
    let mut expected = Vec::new();
    for (name, content) in files {
        let path = root.join(name);
        fs::write(&path, content).expect("write batch input");
        inputs.push(path);
        expected.push(content.as_bytes().to_vec());
    }
    (inputs, expected)
}

#[test]
fn test_error_recovery_scenarios() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let cipher = HybridCipher::default();

    // Test recovery from various error conditions

    // 1. Invalid ciphertext
    let invalid_ciphertext = b"This is not valid ciphertext";
    let result = cipher.decrypt(keypair.private_key(), invalid_ciphertext);
    assert!(result.is_err());

    // 2. Truncated ciphertext
    let plaintext = b"Test data for truncation";
    let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();

    // Truncate ciphertext at various points
    for truncate_at in [0, 4, 8, ciphertext.len() / 2] {
        if truncate_at < ciphertext.len() {
            let truncated = &ciphertext[..truncate_at];
            let result = cipher.decrypt(keypair.private_key(), truncated);
            assert!(
                result.is_err(),
                "Should fail with truncated ciphertext at position {}",
                truncate_at
            );
        }
    }

    // 3. Corrupted key material
    let other_key = KeyPair::generate(2048).expect("other key");
    assert!(
        cipher
            .decrypt(other_key.private_key(), &ciphertext)
            .is_err()
    );
}

#[test]
fn test_interoperability() {
    // Test that data encrypted with one configuration can be decrypted with another
    // (as long as they're compatible)
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let test_data = b"Interoperability test data";

    let config1 = Config::builder()
        .cipher_suite(CipherSuite::Aes256Gcm)
        .build()
        .expect("Failed to build config1");

    let config2 = Config::builder()
        .cipher_suite(CipherSuite::Aes256Gcm)
        .stream_chunk_size(8192) // Different stream settings
        .build()
        .expect("Failed to build config2");

    let cipher1 = HybridCipher::new(config1);
    let cipher2 = HybridCipher::new(config2);

    // Encrypt with cipher1, decrypt with cipher2
    let ciphertext = cipher1
        .encrypt(keypair.public_key(), test_data)
        .expect("Encryption with cipher1 failed");
    let decrypted = cipher2
        .decrypt(keypair.private_key(), &ciphertext)
        .expect("Decryption with cipher2 failed");

    assert_eq!(decrypted, test_data);

    // Encrypt with cipher2, decrypt with cipher1
    let ciphertext = cipher2
        .encrypt(keypair.public_key(), test_data)
        .expect("Encryption with cipher2 failed");
    let decrypted = cipher1
        .decrypt(keypair.private_key(), &ciphertext)
        .expect("Decryption with cipher1 failed");

    assert_eq!(decrypted, test_data);
}

#[test]
fn test_performance_characteristics() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let cipher = HybridCipher::default();

    // Test performance with different data sizes
    let data_sizes = vec![1024, 8192, 65536, 524288, 1048576]; // 1KB to 1MB

    for &size in &data_sizes {
        let test_data = vec![0x42u8; size];
        if size > 512 * 1024 {
            let error = cipher
                .encrypt(keypair.public_key(), &test_data)
                .unwrap_err();
            assert!(error.to_string().contains("512 KB limit"));
            continue;
        }

        let start = std::time::Instant::now();
        let ciphertext = cipher
            .encrypt(keypair.public_key(), &test_data)
            .expect("Performance test encryption failed");
        let encrypt_duration = start.elapsed();

        let start = std::time::Instant::now();
        let decrypted = cipher
            .decrypt(keypair.private_key(), &ciphertext)
            .expect("Performance test decryption failed");
        let decrypt_duration = start.elapsed();

        assert_eq!(decrypted, test_data);

        println!(
            "Size: {} bytes, Encrypt: {:?}, Decrypt: {:?}",
            size, encrypt_duration, decrypt_duration
        );

        // Basic performance assertions (these would be tuned based on requirements)
        assert!(
            encrypt_duration.as_millis() < 1000,
            "Encryption took too long for {} bytes",
            size
        );
        assert!(
            decrypt_duration.as_millis() < 1000,
            "Decryption took too long for {} bytes",
            size
        );
    }
}
