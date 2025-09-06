//! Test compatibility with Go cryptum library format
//!
//! This test verifies that FluxEncrypt produces data compatible
//! with the Go cryptum library format requirements.

use fluxencrypt::{
    config::{Config, RsaKeySize, CipherSuite},
    encryption::HybridCipher,
    keys::KeyPair,
};

#[test]
fn test_go_cryptum_format_compatibility() {
    // Use 4096-bit keys (default) and AES-256-GCM (default)
    let config = Config::default();
    assert_eq!(config.rsa_key_size, RsaKeySize::Rsa4096);
    assert_eq!(config.cipher_suite, CipherSuite::Aes256Gcm);
    
    // Generate 4096-bit key pair
    let keypair = KeyPair::generate(4096).unwrap();
    
    // Create hybrid cipher
    let cipher = HybridCipher::new(config);
    
    // Test data (under 512KB limit)
    let plaintext = b"Hello, Go cryptum compatibility!";
    
    // Encrypt data
    let ciphertext = cipher.encrypt(keypair.public_key(), plaintext).unwrap();
    
    // Verify format: [encrypted_session_key(512)][nonce(12)][ciphertext+tag]
    // Minimum size: 512 + 12 + plaintext.len() + 16 (GCM tag)
    let expected_min_size = 512 + 12 + plaintext.len() + 16;
    assert_eq!(ciphertext.len(), expected_min_size);
    
    // Verify encrypted session key is exactly 512 bytes (4096-bit RSA)
    let encrypted_key = &ciphertext[0..512];
    assert_eq!(encrypted_key.len(), 512);
    
    // Verify nonce is exactly 12 bytes (GCM standard)
    let nonce = &ciphertext[512..524];
    assert_eq!(nonce.len(), 12);
    
    // Verify ciphertext + tag
    let aes_ciphertext = &ciphertext[524..];
    assert_eq!(aes_ciphertext.len(), plaintext.len() + 16); // plaintext + GCM tag
    
    // Test decryption
    let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_512kb_size_limit() {
    let config = Config::default();
    let keypair = KeyPair::generate(4096).unwrap();
    let cipher = HybridCipher::new(config);
    
    // Test data exactly at 512KB limit
    let limit_data = vec![0x42u8; 512 * 1024];
    let result = cipher.encrypt(keypair.public_key(), &limit_data);
    assert!(result.is_ok(), "512KB data should be accepted");
    
    // Test data over 512KB limit
    let oversized_data = vec![0x42u8; 512 * 1024 + 1];
    let result = cipher.encrypt(keypair.public_key(), &oversized_data);
    assert!(result.is_err(), "Over 512KB data should be rejected");
    
    if let Err(e) = result {
        assert!(e.to_string().contains("Data too large for blob encryption"));
        assert!(e.to_string().contains("512 KB limit"));
    }
}

#[test]
fn test_pkcs1_key_format() {
    let keypair = KeyPair::generate(2048).unwrap(); // Use 2048 for faster test
    
    // Export keys in PKCS1 format
    let public_pem = keypair.public_key().to_pem().unwrap();
    let private_pem = keypair.private_key().to_pem().unwrap();
    
    // Verify PKCS1 headers (RSA PUBLIC KEY / RSA PRIVATE KEY)
    assert!(public_pem.starts_with("-----BEGIN RSA PUBLIC KEY-----\n"));
    assert!(public_pem.ends_with("\n-----END RSA PUBLIC KEY-----\n"));
    
    assert!(private_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
    assert!(private_pem.ends_with("\n-----END RSA PRIVATE KEY-----\n"));
    
    // Verify we can parse them back
    use fluxencrypt::keys::parsing::{parse_public_key_from_str, parse_private_key_from_str};
    
    let parsed_public = parse_public_key_from_str(&public_pem).unwrap();
    let parsed_private = parse_private_key_from_str(&private_pem).unwrap();
    
    // Keys should be identical
    assert_eq!(parsed_public.modulus(), keypair.public_key().modulus());
    assert_eq!(parsed_private.modulus(), keypair.private_key().modulus());
}

#[test]
fn test_aes_256_gcm_default() {
    let config = Config::default();
    
    // Verify AES-256-GCM is the default
    assert_eq!(config.cipher_suite, CipherSuite::Aes256Gcm);
    
    // Verify key length is 32 bytes (256 bits)
    assert_eq!(config.key_length(), 32);
    
    // Verify nonce length is 12 bytes (GCM standard)
    assert_eq!(config.nonce_length(), 12);
    
    // Verify tag length is 16 bytes (GCM standard)
    assert_eq!(config.tag_length(), 16);
}

#[test]
fn test_rsa_sha512_overhead() {
    use fluxencrypt::encryption::RsaOaepCipher;
    
    let cipher = RsaOaepCipher::new();
    
    // Test different key sizes with SHA-512 overhead
    let test_cases = [
        (2048, 126),  // 256 - 130 = 126 bytes max plaintext
        (3072, 254),  // 384 - 130 = 254 bytes max plaintext  
        (4096, 382),  // 512 - 130 = 382 bytes max plaintext
    ];
    
    for (key_size, expected_max_len) in test_cases {
        let keypair = KeyPair::generate(key_size).unwrap();
        let max_len = cipher.max_plaintext_length(keypair.public_key()).unwrap();
        assert_eq!(
            max_len, expected_max_len,
            "Wrong max plaintext length for {}-bit key with SHA-512",
            key_size
        );
    }
}