//! Integration tests for FluxEncrypt.
//!
//! These tests verify that all components work together correctly
//! and that the public API behaves as expected.

use fluxencrypt::{Config, HybridCipher};
use fluxencrypt::keys::{KeyPair, storage::{KeyStorage, StorageOptions}};
use fluxencrypt::stream::FileStreamCipher;
use fluxencrypt::env::EnvSecretProvider;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_end_to_end_encryption() {
    // Generate key pair
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    
    // Create cipher
    let cipher = HybridCipher::new(Config::default());
    
    // Test data
    let plaintext = b"Integration test data for FluxEncrypt";
    
    // Encrypt
    let ciphertext = cipher.encrypt(keypair.public_key(), plaintext)
        .expect("Encryption failed");
    
    // Decrypt
    let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)
        .expect("Decryption failed");
    
    // Verify
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_file_encryption_integration() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    
    // Create test file
    let input_file = temp_dir.path().join("test_input.txt");
    let test_data = "This is test data for file encryption integration test.\n".repeat(100);
    fs::write(&input_file, &test_data).expect("Failed to write test file");
    
    // Encrypt file
    let encrypted_file = temp_dir.path().join("test_encrypted.enc");
    let cipher = FileStreamCipher::new(Config::default());
    
    let bytes_encrypted = cipher.encrypt_file(
        &input_file,
        &encrypted_file,
        keypair.public_key(),
        None,
    ).expect("File encryption failed");
    
    assert!(encrypted_file.exists());
    assert!(bytes_encrypted > 0);
    
    // Decrypt file
    let decrypted_file = temp_dir.path().join("test_decrypted.txt");
    let bytes_decrypted = cipher.decrypt_file(
        &encrypted_file,
        &decrypted_file,
        keypair.private_key(),
        None,
    ).expect("File decryption failed");
    
    assert!(decrypted_file.exists());
    assert_eq!(bytes_encrypted, bytes_decrypted);
    
    // Verify content
    let decrypted_data = fs::read_to_string(&decrypted_file)
        .expect("Failed to read decrypted file");
    assert_eq!(test_data, decrypted_data);
}

#[test]
fn test_key_storage_integration() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    
    // Save keys
    let public_key_path = temp_dir.path().join("test_public.pem");
    let private_key_path = temp_dir.path().join("test_private.pem");
    
    let storage = KeyStorage::new();
    let options = StorageOptions {
        overwrite: true,
        ..Default::default()
    };
    
    storage.save_keypair(&keypair, &public_key_path, &private_key_path, &options)
        .expect("Failed to save key pair");
    
    assert!(public_key_path.exists());
    assert!(private_key_path.exists());
    
    // Load keys
    let loaded_public = storage.load_public_key(&public_key_path)
        .expect("Failed to load public key");
    let loaded_private = storage.load_private_key(&private_key_path, None)
        .expect("Failed to load private key");
    
    // Test that loaded keys work for encryption/decryption
    let cipher = HybridCipher::new(Config::default());
    let plaintext = b"Key storage integration test";
    
    let ciphertext = cipher.encrypt(&loaded_public, plaintext)
        .expect("Encryption with loaded key failed");
    let decrypted = cipher.decrypt(&loaded_private, &ciphertext)
        .expect("Decryption with loaded key failed");
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_config_validation_integration() {
    use fluxencrypt::config::{CipherSuite, KeyDerivation, RsaKeySize};
    
    // Test valid configurations
    let valid_configs = vec![
        Config::default(),
        Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .rsa_key_size(RsaKeySize::Rsa3072)
            .build().expect("Valid config should build"),
        Config::builder()
            .key_derivation(KeyDerivation::Pbkdf2 { iterations: 200_000, salt_len: 32 })
            .memory_limit_mb(512)
            .build().expect("Valid config should build"),
    ];
    
    for config in valid_configs {
        assert!(config.validate().is_ok(), "Config validation should pass");
        
        // Test that config works with cipher
        let _cipher = HybridCipher::new(config);
    }
    
    // Test invalid configurations
    let invalid_result = Config::builder()
        .memory_limit_mb(0)
        .build();
    assert!(invalid_result.is_err(), "Invalid config should fail to build");
}

#[test]
fn test_error_handling_integration() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let cipher = HybridCipher::new(Config::default());
    
    // Test decryption with invalid data
    let invalid_ciphertext = b"This is not valid ciphertext";
    let result = cipher.decrypt(keypair.private_key(), invalid_ciphertext);
    assert!(result.is_err(), "Decryption of invalid data should fail");
    
    // Test file operations with non-existent files
    let file_cipher = FileStreamCipher::new(Config::default());
    let non_existent = std::path::Path::new("/this/path/does/not/exist");
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let output = temp_dir.path().join("output");
    
    let result = file_cipher.encrypt_file(
        non_existent,
        &output,
        keypair.public_key(),
        None,
    );
    assert!(result.is_err(), "Encryption of non-existent file should fail");
}

#[test]
#[ignore] // Requires environment setup
fn test_environment_integration() {
    use std::env;
    
    // Set up test environment variables
    env::set_var("TEST_PUBLIC_KEY", "test-public-key-data");
    env::set_var("TEST_PRIVATE_KEY", "test-private-key-data");
    
    let provider = EnvSecretProvider::with_prefix("TEST");
    
    // Test basic functionality (will fail due to invalid key data, but tests the flow)
    let public_result = provider.get_optional_string("PUBLIC_KEY");
    let private_result = provider.get_optional_string("PRIVATE_KEY");
    
    assert_eq!(public_result, Some("test-public-key-data".to_string()));
    assert_eq!(private_result, Some("test-private-key-data".to_string()));
    
    // Clean up
    env::remove_var("TEST_PUBLIC_KEY");
    env::remove_var("TEST_PRIVATE_KEY");
}

#[test]
fn test_multiple_cipher_suites() {
    use fluxencrypt::config::CipherSuite;
    
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let plaintext = b"Multi-cipher test data";
    
    for cipher_suite in &[CipherSuite::Aes128Gcm, CipherSuite::Aes256Gcm] {
        let config = Config::builder()
            .cipher_suite(*cipher_suite)
            .build()
            .expect("Failed to build config");
        
        let cipher = HybridCipher::new(config);
        
        let ciphertext = cipher.encrypt(keypair.public_key(), plaintext)
            .expect("Encryption failed");
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)
            .expect("Decryption failed");
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}

#[test]
fn test_large_data_encryption() {
    let keypair = KeyPair::generate(2048).expect("Failed to generate key pair");
    let cipher = HybridCipher::new(Config::default());
    
    // Test with various data sizes
    let sizes = vec![1024, 8192, 65536];
    
    for size in sizes {
        let plaintext = vec![0x42u8; size];
        
        let ciphertext = cipher.encrypt(keypair.public_key(), &plaintext)
            .expect("Encryption failed");
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)
            .expect("Decryption failed");
        
        assert_eq!(plaintext, decrypted);
        assert!(ciphertext.len() > plaintext.len(), "Ciphertext should be larger than plaintext");
    }
}

#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;
    use std::thread;
    
    let keypair = Arc::new(KeyPair::generate(2048).expect("Failed to generate key pair"));
    let cipher = Arc::new(HybridCipher::new(Config::default()));
    
    let mut handles = vec![];
    
    // Spawn multiple threads doing encryption/decryption
    for i in 0..5 {
        let keypair_clone = keypair.clone();
        let cipher_clone = cipher.clone();
        
        let handle = thread::spawn(move || {
            let plaintext = format!("Thread {} test data", i);
            let plaintext_bytes = plaintext.as_bytes();
            
            let ciphertext = cipher_clone.encrypt(keypair_clone.public_key(), plaintext_bytes)
                .expect("Encryption failed in thread");
            let decrypted = cipher_clone.decrypt(keypair_clone.private_key(), &ciphertext)
                .expect("Decryption failed in thread");
            
            assert_eq!(plaintext_bytes, decrypted.as_slice());
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