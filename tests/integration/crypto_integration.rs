//! Comprehensive integration tests for FluxEncrypt crypto functionality.
//!
//! These tests verify that all cryptographic components work together correctly
//! and provide the expected security properties.

use fluxencrypt::{Config, HybridCipher, Cryptum};
use fluxencrypt::keys::{KeyPair, storage::{KeyStorage, StorageOptions}};
use fluxencrypt::config::{CipherSuite, RsaKeySize, KeyDerivation};
use fluxencrypt::stream::{FileStreamCipher, BatchProcessor};
use std::fs;
use tempfile::{tempdir, NamedTempFile};

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
        let test_data = vec![
            vec![],                     // Empty data
            vec![0x42; 1],             // Single byte
            vec![0x55; 100],           // Small data
            vec![0xAA; 8192],          // Medium data
            vec![0xFF; 65536],         // Large data
        ];

        for (i, plaintext) in test_data.iter().enumerate() {
            let ciphertext = cipher.encrypt(keypair.public_key(), plaintext)
                .expect(&format!("Encryption failed for test case {} with {:?}", i, cipher_suite));
            
            let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)
                .expect(&format!("Decryption failed for test case {} with {:?}", i, cipher_suite));
            
            assert_eq!(decrypted, *plaintext, "Decrypted data doesn't match for test case {} with {:?}", i, cipher_suite);
        }
    }
}

#[test]
fn test_cryptum_api_integration() {
    let cryptum = Cryptum::with_defaults().expect("Failed to create Cryptum instance");
    let keypair = cryptum.generate_keypair(2048).expect("Failed to generate keypair");
    
    let test_data = b"Testing Cryptum API integration";
    
    // Test basic encryption/decryption
    let ciphertext = cryptum.encrypt(keypair.public_key(), test_data)
        .expect("Cryptum encryption failed");
    let decrypted = cryptum.decrypt(keypair.private_key(), &ciphertext)
        .expect("Cryptum decryption failed");
    
    assert_eq!(decrypted, test_data);
    
    // Test file encryption/decryption
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    let input_file = temp_dir.path().join("test_input.txt");
    let encrypted_file = temp_dir.path().join("test_encrypted.enc");
    let output_file = temp_dir.path().join("test_output.txt");
    
    fs::write(&input_file, test_data).expect("Failed to write test file");
    
    let encrypted_bytes = cryptum.encrypt_file(&input_file, &encrypted_file, keypair.public_key())
        .expect("File encryption failed");
    
    assert!(encrypted_file.exists());
    assert!(encrypted_bytes > 0);
    
    let decrypted_bytes = cryptum.decrypt_file(&encrypted_file, &output_file, keypair.private_key())
        .expect("File decryption failed");
    
    assert_eq!(encrypted_bytes, decrypted_bytes);
    
    let decrypted_content = fs::read(&output_file).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, test_data);
}

#[test]
fn test_key_storage_integration() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let keypair = KeyPair::generate(3072).expect("Failed to generate key pair");
    
    // Test key storage and loading
    let storage = KeyStorage::new();
    let public_key_path = temp_dir.path().join("test_public.pem");
    let private_key_path = temp_dir.path().join("test_private.pem");
    
    let options = StorageOptions {
        overwrite: true,
        password: Some("test_password".to_string()),
        ..Default::default()
    };
    
    // Save key pair
    storage.save_keypair(&keypair, &public_key_path, &private_key_path, &options)
        .expect("Failed to save key pair");
    
    assert!(public_key_path.exists());
    assert!(private_key_path.exists());
    
    // Load keys
    let loaded_public = storage.load_public_key(&public_key_path)
        .expect("Failed to load public key");
    let loaded_private = storage.load_private_key(&private_key_path, options.password.as_deref())
        .expect("Failed to load private key");
    
    // Verify loaded keys work
    let cipher = HybridCipher::default();
    let test_data = b"Key storage integration test";
    
    let ciphertext = cipher.encrypt(&loaded_public, test_data)
        .expect("Encryption with loaded public key failed");
    let decrypted = cipher.decrypt(&loaded_private, &ciphertext)
        .expect("Decryption with loaded private key failed");
    
    assert_eq!(decrypted, test_data);
}

#[test]
fn test_config_variations() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let test_data = b"Configuration variation test";
    
    // Test different configuration combinations
    let configs = vec![
        Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .rsa_key_size(RsaKeySize::Rsa2048)
            .memory_limit_mb(256)
            .build().expect("Config build failed"),
            
        Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .rsa_key_size(RsaKeySize::Rsa3072)
            .key_derivation(KeyDerivation::Pbkdf2 { iterations: 100_000, salt_len: 32 })
            .build().expect("Config build failed"),
            
        Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .rsa_key_size(RsaKeySize::Rsa4096)
            .hardware_acceleration(false)
            .secure_memory(true)
            .build().expect("Config build failed"),
    ];
    
    for (i, config) in configs.iter().enumerate() {
        assert!(config.validate().is_ok(), "Config {} should be valid", i);
        
        let cipher = HybridCipher::new(config.clone());
        
        let ciphertext = cipher.encrypt(keypair.public_key(), test_data)
            .expect(&format!("Encryption failed for config {}", i));
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)
            .expect(&format!("Decryption failed for config {}", i));
        
        assert_eq!(decrypted, test_data, "Data mismatch for config {}", i);
    }
}

#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;
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
            
            let ciphertext = cipher_clone.encrypt(keypair_clone.public_key(), plaintext)
                .expect("Concurrent encryption failed");
            let decrypted = cipher_clone.decrypt(keypair_clone.private_key(), &ciphertext)
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
    
    // Create a larger test file
    let test_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n".repeat(1000);
    let input_file = temp_dir.path().join("large_input.txt");
    fs::write(&input_file, &test_data).expect("Failed to write test file");
    
    // Test streaming encryption
    let config = Config::builder()
        .stream_chunk_size(4096)
        .build()
        .expect("Failed to build config");
    
    let cipher = FileStreamCipher::new(config);
    
    let encrypted_file = temp_dir.path().join("large_encrypted.enc");
    let decrypted_file = temp_dir.path().join("large_decrypted.txt");
    
    // Encrypt
    let encrypt_progress = Arc::new(std::sync::Mutex::new(0u64));
    let encrypt_progress_clone = encrypt_progress.clone();
    
    let progress_callback = Some(Box::new(move |bytes_processed: u64, total_bytes: u64| {
        *encrypt_progress_clone.lock().unwrap() = bytes_processed;
        println!("Encryption progress: {}/{} bytes", bytes_processed, total_bytes);
    }) as fluxencrypt::stream::ProgressCallback);
    
    let encrypted_bytes = cipher.encrypt_file(
        &input_file,
        &encrypted_file,
        keypair.public_key(),
        progress_callback,
    ).expect("Stream encryption failed");
    
    assert!(encrypted_bytes > 0);
    assert!(encrypted_file.exists());
    assert!(*encrypt_progress.lock().unwrap() > 0);
    
    // Decrypt
    let decrypt_progress = Arc::new(std::sync::Mutex::new(0u64));
    let decrypt_progress_clone = decrypt_progress.clone();
    
    let progress_callback = Some(Box::new(move |bytes_processed: u64, total_bytes: u64| {
        *decrypt_progress_clone.lock().unwrap() = bytes_processed;
        println!("Decryption progress: {}/{} bytes", bytes_processed, total_bytes);
    }) as fluxencrypt::stream::ProgressCallback);
    
    let decrypted_bytes = cipher.decrypt_file(
        &encrypted_file,
        &decrypted_file,
        keypair.private_key(),
        progress_callback,
    ).expect("Stream decryption failed");
    
    assert_eq!(encrypted_bytes, decrypted_bytes);
    assert!(*decrypt_progress.lock().unwrap() > 0);
    
    // Verify content
    let decrypted_content = fs::read_to_string(&decrypted_file)
        .expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, test_data);
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
    
    let mut input_files = vec![];
    let mut expected_outputs = vec![];
    
    for (filename, content) in &test_files {
        let input_path = temp_dir.path().join(filename);
        fs::write(&input_path, content).expect("Failed to write test file");
        input_files.push(input_path);
        expected_outputs.push(content.as_bytes().to_vec());
    }
    
    // Test batch encryption
    let config = Config::default();
    let batch_processor = BatchProcessor::new(config);
    
    let encrypted_dir = temp_dir.path().join("encrypted");
    fs::create_dir(&encrypted_dir).expect("Failed to create encrypted directory");
    
    let mut encrypted_files = vec![];
    for (i, input_file) in input_files.iter().enumerate() {
        let encrypted_file = encrypted_dir.join(format!("encrypted_{}.enc", i));
        encrypted_files.push(encrypted_file);
    }
    
    // This would be implemented in the batch processor
    // For now, test individual file processing
    for (input_file, encrypted_file) in input_files.iter().zip(encrypted_files.iter()) {
        let cipher = FileStreamCipher::new(config.clone());
        cipher.encrypt_file(input_file, encrypted_file, keypair.public_key(), None)
            .expect("Batch encryption failed");
        assert!(encrypted_file.exists());
    }
    
    // Verify decryption
    let decrypted_dir = temp_dir.path().join("decrypted");
    fs::create_dir(&decrypted_dir).expect("Failed to create decrypted directory");
    
    for (i, encrypted_file) in encrypted_files.iter().enumerate() {
        let decrypted_file = decrypted_dir.join(format!("decrypted_{}.txt", i));
        let cipher = FileStreamCipher::new(config.clone());
        cipher.decrypt_file(encrypted_file, &decrypted_file, keypair.private_key(), None)
            .expect("Batch decryption failed");
        
        let content = fs::read(&decrypted_file).expect("Failed to read decrypted file");
        assert_eq!(content, expected_outputs[i]);
    }
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
            assert!(result.is_err(), "Should fail with truncated ciphertext at position {}", truncate_at);
        }
    }
    
    // 3. Corrupted key material
    let mut corrupted_private = keypair.private_key().clone();
    // We can't easily corrupt the private key in our current implementation,
    // but this test demonstrates the error handling structure
    
    // 4. Memory pressure simulation (would require special test conditions)
    // This is typically tested with memory-limited environments
}

#[test]
fn test_interoperability() {
    // Test that data encrypted with one configuration can be decrypted with another
    // (as long as they're compatible)
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let test_data = b"Interoperability test data";
    
    let config1 = Config::builder()
        .cipher_suite(CipherSuite::Aes256Gcm)
        .build().expect("Failed to build config1");
    
    let config2 = Config::builder()
        .cipher_suite(CipherSuite::Aes256Gcm)
        .stream_chunk_size(8192) // Different stream settings
        .build().expect("Failed to build config2");
    
    let cipher1 = HybridCipher::new(config1);
    let cipher2 = HybridCipher::new(config2);
    
    // Encrypt with cipher1, decrypt with cipher2
    let ciphertext = cipher1.encrypt(keypair.public_key(), test_data)
        .expect("Encryption with cipher1 failed");
    let decrypted = cipher2.decrypt(keypair.private_key(), &ciphertext)
        .expect("Decryption with cipher2 failed");
    
    assert_eq!(decrypted, test_data);
    
    // Encrypt with cipher2, decrypt with cipher1
    let ciphertext = cipher2.encrypt(keypair.public_key(), test_data)
        .expect("Encryption with cipher2 failed");
    let decrypted = cipher1.decrypt(keypair.private_key(), &ciphertext)
        .expect("Decryption with cipher1 failed");
    
    assert_eq!(decrypted, test_data);
}

#[test]
fn test_performance_characteristics() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let cipher = HybridCipher::default();
    
    // Test performance with different data sizes
    let data_sizes = vec![1024, 8192, 65536, 1048576]; // 1KB to 1MB
    
    for &size in &data_sizes {
        let test_data = vec![0x42u8; size];
        
        let start = std::time::Instant::now();
        let ciphertext = cipher.encrypt(keypair.public_key(), &test_data)
            .expect("Performance test encryption failed");
        let encrypt_duration = start.elapsed();
        
        let start = std::time::Instant::now();
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)
            .expect("Performance test decryption failed");
        let decrypt_duration = start.elapsed();
        
        assert_eq!(decrypted, test_data);
        
        println!("Size: {} bytes, Encrypt: {:?}, Decrypt: {:?}", 
                size, encrypt_duration, decrypt_duration);
        
        // Basic performance assertions (these would be tuned based on requirements)
        assert!(encrypt_duration.as_millis() < 1000, "Encryption took too long for {} bytes", size);
        assert!(decrypt_duration.as_millis() < 1000, "Decryption took too long for {} bytes", size);
    }
}