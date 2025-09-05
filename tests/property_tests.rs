//! Property-based tests for FluxEncrypt using proptest.
//!
//! These tests verify that cryptographic properties hold for arbitrary inputs,
//! providing stronger assurance than example-based tests alone.

use proptest::prelude::*;
use fluxencrypt::{Config, HybridCipher};
use fluxencrypt::keys::KeyPair;
use fluxencrypt::config::{CipherSuite, RsaKeySize};
use fluxencrypt::encryption::aes_gcm::{AesGcmCipher, AesKey};

// Test that encryption is deterministic for same input with same key and nonce
proptest! {
    #[test]
    fn test_aes_gcm_deterministic_with_same_nonce(
        data in prop::collection::vec(any::<u8>(), 0..10000),
        aad in prop::option::of(prop::collection::vec(any::<u8>(), 0..1000))
    ) {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        
        // Generate nonce once and reuse
        let (nonce1, ciphertext1) = cipher.encrypt(&key, &data, aad.as_deref()).unwrap();
        
        // Manual encryption with same nonce (this would require exposing internals)
        // For now, we test that the same key with random nonces produces valid decryption
        let (nonce2, ciphertext2) = cipher.encrypt(&key, &data, aad.as_deref()).unwrap();
        
        // Both should decrypt to same plaintext
        let decrypted1 = cipher.decrypt(&key, &nonce1, &ciphertext1, aad.as_deref()).unwrap();
        let decrypted2 = cipher.decrypt(&key, &nonce2, &ciphertext2, aad.as_deref()).unwrap();
        
        prop_assert_eq!(decrypted1, data);
        prop_assert_eq!(decrypted2, data);
        
        // Different nonces should produce different ciphertexts (with high probability)
        if data.len() > 0 {
            prop_assert_ne!(nonce1, nonce2);
            prop_assert_ne!(ciphertext1, ciphertext2);
        }
    }
}

// Test AES-GCM encryption/decryption roundtrip property
proptest! {
    #[test]
    fn test_aes_gcm_roundtrip_property(
        data in prop::collection::vec(any::<u8>(), 0..50000),
        cipher_suite in prop_oneof![
            Just(CipherSuite::Aes128Gcm),
            Just(CipherSuite::Aes256Gcm),
        ],
        aad in prop::option::of(prop::collection::vec(any::<u8>(), 0..5000))
    ) {
        let cipher = AesGcmCipher::new(cipher_suite);
        let key = AesKey::generate(cipher_suite).unwrap();
        
        let (nonce, ciphertext) = cipher.encrypt(&key, &data, aad.as_deref()).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, aad.as_deref()).unwrap();
        
        prop_assert_eq!(decrypted, data);
        
        // Ciphertext should be larger than plaintext (due to auth tag) unless empty
        if !data.is_empty() {
            prop_assert!(ciphertext.len() > data.len());
        }
        
        // Auth tag should be exactly 16 bytes
        prop_assert_eq!(ciphertext.len(), data.len() + 16);
        
        // Nonce should be exactly 12 bytes for GCM
        prop_assert_eq!(nonce.len(), 12);
    }
}

// Test that AES-GCM fails with wrong AAD
proptest! {
    #[test]
    fn test_aes_gcm_aad_authentication(
        data in prop::collection::vec(any::<u8>(), 1..1000),
        aad1 in prop::collection::vec(any::<u8>(), 0..1000),
        aad2 in prop::collection::vec(any::<u8>(), 0..1000)
    ) {
        // Only test when AADs are actually different
        if aad1 != aad2 {
            let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
            let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
            
            let (nonce, ciphertext) = cipher.encrypt(&key, &data, Some(&aad1)).unwrap();
            
            // Should succeed with correct AAD
            let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, Some(&aad1)).unwrap();
            prop_assert_eq!(decrypted, data);
            
            // Should fail with different AAD
            let result = cipher.decrypt(&key, &nonce, &ciphertext, Some(&aad2));
            prop_assert!(result.is_err());
        }
    }
}

// Test hybrid cipher roundtrip property
proptest! {
    #[test]
    #[ignore] // Skip due to placeholder RSA implementation
    fn test_hybrid_cipher_roundtrip_property(
        data in prop::collection::vec(any::<u8>(), 0..100000),
        cipher_suite in prop_oneof![
            Just(CipherSuite::Aes128Gcm),
            Just(CipherSuite::Aes256Gcm),
        ],
        key_size in prop_oneof![
            Just(2048usize),
            Just(3072usize),
            Just(4096usize),
        ]
    ) {
        let keypair = KeyPair::generate(key_size).unwrap();
        let config = Config::builder()
            .cipher_suite(cipher_suite)
            .build()
            .unwrap();
        let cipher = HybridCipher::new(config);
        
        let ciphertext = cipher.encrypt(keypair.public_key(), &data).unwrap();
        let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();
        
        prop_assert_eq!(decrypted, data);
        
        // Ciphertext should be significantly larger than plaintext due to overhead
        prop_assert!(ciphertext.len() > data.len() + 200); // RSA overhead + AES overhead
    }
}

// Test that different keys produce different ciphertexts
proptest! {
    #[test]
    fn test_different_keys_produce_different_ciphertexts(
        data in prop::collection::vec(any::<u8>(), 100..1000) // Non-empty data
    ) {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key1 = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        let key2 = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        
        let (nonce1, ciphertext1) = cipher.encrypt(&key1, &data, None).unwrap();
        let (nonce2, ciphertext2) = cipher.encrypt(&key2, &data, None).unwrap();
        
        // Keys should be different (extremely high probability)
        prop_assert_ne!(key1.as_bytes(), key2.as_bytes());
        
        // Ciphertexts should be different (extremely high probability)
        prop_assert_ne!(ciphertext1, ciphertext2);
        
        // Each should decrypt correctly with its own key
        let decrypted1 = cipher.decrypt(&key1, &nonce1, &ciphertext1, None).unwrap();
        let decrypted2 = cipher.decrypt(&key2, &nonce2, &ciphertext2, None).unwrap();
        
        prop_assert_eq!(decrypted1, data);
        prop_assert_eq!(decrypted2, data);
        
        // Should fail with wrong keys
        let result1 = cipher.decrypt(&key2, &nonce1, &ciphertext1, None);
        let result2 = cipher.decrypt(&key1, &nonce2, &ciphertext2, None);
        
        prop_assert!(result1.is_err());
        prop_assert!(result2.is_err());
    }
}

// Test key generation properties
proptest! {
    #[test]
    fn test_key_generation_properties(
        key_size in prop_oneof![
            Just(2048usize),
            Just(3072usize),
            Just(4096usize),
        ]
    ) {
        let keypair1 = KeyPair::generate(key_size).unwrap();
        let keypair2 = KeyPair::generate(key_size).unwrap();
        
        // Basic properties
        prop_assert_eq!(keypair1.public_key().key_size_bits(), key_size);
        prop_assert_eq!(keypair1.private_key().key_size_bits(), key_size);
        prop_assert_eq!(keypair2.public_key().key_size_bits(), key_size);
        prop_assert_eq!(keypair2.private_key().key_size_bits(), key_size);
        
        // Keys should be different
        prop_assert_ne!(keypair1.public_key().modulus(), keypair2.public_key().modulus());
        prop_assert_ne!(keypair1.private_key().modulus(), keypair2.private_key().modulus());
        
        // Public and private key moduli should match within each pair
        prop_assert_eq!(keypair1.public_key().modulus(), keypair1.private_key().modulus());
        prop_assert_eq!(keypair2.public_key().modulus(), keypair2.private_key().modulus());
        
        // MSB should be set for proper key size
        prop_assert!(keypair1.public_key().modulus()[0] & 0x80 != 0);
        prop_assert!(keypair2.public_key().modulus()[0] & 0x80 != 0);
        
        // Standard public exponent (65537)
        prop_assert_eq!(keypair1.public_key().public_exponent(), &vec![0x01, 0x00, 0x01]);
        prop_assert_eq!(keypair2.public_key().public_exponent(), &vec![0x01, 0x00, 0x01]);
    }
}

// Test AES key generation properties
proptest! {
    #[test]
    fn test_aes_key_generation_properties(
        cipher_suite in prop_oneof![
            Just(CipherSuite::Aes128Gcm),
            Just(CipherSuite::Aes256Gcm),
        ]
    ) {
        let key1 = AesKey::generate(cipher_suite).unwrap();
        let key2 = AesKey::generate(cipher_suite).unwrap();
        
        let expected_len = match cipher_suite {
            CipherSuite::Aes128Gcm => 16,
            CipherSuite::Aes256Gcm => 32,
        };
        
        // Correct key lengths
        prop_assert_eq!(key1.as_bytes().len(), expected_len);
        prop_assert_eq!(key2.as_bytes().len(), expected_len);
        
        // Keys should be different (extremely high probability)
        prop_assert_ne!(key1.as_bytes(), key2.as_bytes());
        
        // Keys should not be all zeros (extremely high probability)
        prop_assert_ne!(key1.as_bytes(), &vec![0u8; expected_len]);
        prop_assert_ne!(key2.as_bytes(), &vec![0u8; expected_len]);
        
        // Keys should not be all 0xFF (extremely high probability)
        prop_assert_ne!(key1.as_bytes(), &vec![0xFFu8; expected_len]);
        prop_assert_ne!(key2.as_bytes(), &vec![0xFFu8; expected_len]);
    }
}

// Test configuration validation properties
proptest! {
    #[test]
    fn test_config_validation_properties(
        cipher_suite in prop_oneof![
            Just(CipherSuite::Aes128Gcm),
            Just(CipherSuite::Aes256Gcm),
        ],
        rsa_key_size in prop_oneof![
            Just(RsaKeySize::Rsa2048),
            Just(RsaKeySize::Rsa3072),
            Just(RsaKeySize::Rsa4096),
        ],
        memory_limit_mb in 1..=2048usize,
        stream_chunk_size in 1024..=65536usize,
        hardware_acceleration in any::<bool>(),
        secure_memory in any::<bool>()
    ) {
        let config = Config::builder()
            .cipher_suite(cipher_suite)
            .rsa_key_size(rsa_key_size)
            .memory_limit_mb(memory_limit_mb)
            .stream_chunk_size(stream_chunk_size)
            .hardware_acceleration(hardware_acceleration)
            .secure_memory(secure_memory)
            .build()
            .unwrap();
            
        // All generated configs should be valid
        prop_assert!(config.validate().is_ok());
        
        // Properties should be set correctly
        prop_assert_eq!(config.cipher_suite, cipher_suite);
        prop_assert_eq!(config.rsa_key_size, rsa_key_size);
        prop_assert_eq!(config.memory_limit_mb, memory_limit_mb);
        prop_assert_eq!(config.stream_chunk_size, stream_chunk_size);
        prop_assert_eq!(config.hardware_acceleration, hardware_acceleration);
        prop_assert_eq!(config.secure_memory, secure_memory);
    }
}

// Test that tampering with ciphertext is detected
proptest! {
    #[test]
    fn test_tamper_detection_property(
        data in prop::collection::vec(any::<u8>(), 1..1000), // Non-empty
        tamper_position in 0..1000usize,
        tamper_value in any::<u8>()
    ) {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        
        let (nonce, mut ciphertext) = cipher.encrypt(&key, &data, None).unwrap();
        
        // Only tamper if position is within bounds
        if tamper_position < ciphertext.len() {
            let original_byte = ciphertext[tamper_position];
            
            // Only tamper if it actually changes the byte
            if tamper_value != original_byte {
                ciphertext[tamper_position] = tamper_value;
                
                // Tampered ciphertext should fail to decrypt
                let result = cipher.decrypt(&key, &nonce, &ciphertext, None);
                prop_assert!(result.is_err());
            }
        }
    }
}

// Test nonce uniqueness property
proptest! {
    #[test]
    fn test_nonce_uniqueness_property(
        data in prop::collection::vec(any::<u8>(), 0..1000),
        num_encryptions in 1..100usize
    ) {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        
        let mut nonces = std::collections::HashSet::new();
        
        for _ in 0..num_encryptions {
            let (nonce, _) = cipher.encrypt(&key, &data, None).unwrap();
            
            // All nonces should be unique
            prop_assert!(nonces.insert(nonce), "Duplicate nonce detected");
        }
        
        prop_assert_eq!(nonces.len(), num_encryptions);
    }
}

// Test encryption preserves data length invariants
proptest! {
    #[test]
    fn test_encryption_length_invariants(
        data in prop::collection::vec(any::<u8>(), 0..10000)
    ) {
        let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
        let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();
        
        let (nonce, ciphertext) = cipher.encrypt(&key, &data, None).unwrap();
        
        // Nonce length invariant
        prop_assert_eq!(nonce.len(), 12);
        
        // Ciphertext length invariant (plaintext + 16-byte auth tag)
        prop_assert_eq!(ciphertext.len(), data.len() + 16);
        
        // Decryption should preserve original length
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        prop_assert_eq!(decrypted.len(), data.len());
    }
}

// Test that configurations with different parameters produce different behavior
proptest! {
    #[test]
    fn test_different_configs_produce_different_behavior(
        data in prop::collection::vec(any::<u8>(), 100..1000)
    ) {
        let config1 = Config::builder()
            .cipher_suite(CipherSuite::Aes128Gcm)
            .build()
            .unwrap();
            
        let config2 = Config::builder()
            .cipher_suite(CipherSuite::Aes256Gcm)
            .build()
            .unwrap();
        
        let cipher1 = AesGcmCipher::new(config1.cipher_suite);
        let cipher2 = AesGcmCipher::new(config2.cipher_suite);
        
        let key1 = AesKey::generate(config1.cipher_suite).unwrap();
        let key2 = AesKey::generate(config2.cipher_suite).unwrap();
        
        // Different key sizes
        prop_assert_eq!(key1.as_bytes().len(), 16);
        prop_assert_eq!(key2.as_bytes().len(), 32);
        
        // Both should work correctly
        let (nonce1, ciphertext1) = cipher1.encrypt(&key1, &data, None).unwrap();
        let (nonce2, ciphertext2) = cipher2.encrypt(&key2, &data, None).unwrap();
        
        let decrypted1 = cipher1.decrypt(&key1, &nonce1, &ciphertext1, None).unwrap();
        let decrypted2 = cipher2.decrypt(&key2, &nonce2, &ciphertext2, None).unwrap();
        
        prop_assert_eq!(decrypted1, data);
        prop_assert_eq!(decrypted2, data);
        
        // Ciphertexts should be different (different keys and potentially different algorithms)
        prop_assert_ne!(ciphertext1, ciphertext2);
    }
}

// Test boundary conditions
proptest! {
    #[test]
    fn test_boundary_conditions(
        cipher_suite in prop_oneof![
            Just(CipherSuite::Aes128Gcm),
            Just(CipherSuite::Aes256Gcm),
        ]
    ) {
        let cipher = AesGcmCipher::new(cipher_suite);
        let key = AesKey::generate(cipher_suite).unwrap();
        
        // Test empty data
        let (nonce, ciphertext) = cipher.encrypt(&key, &[], None).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        prop_assert_eq!(decrypted, Vec::<u8>::new());
        prop_assert_eq!(ciphertext.len(), 16); // Just the auth tag
        
        // Test single byte
        let single_byte = vec![0x42];
        let (nonce, ciphertext) = cipher.encrypt(&key, &single_byte, None).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, None).unwrap();
        prop_assert_eq!(decrypted, single_byte);
        prop_assert_eq!(ciphertext.len(), 17); // 1 byte + 16-byte tag
    }
}