// Simple validation script to verify Go cryptum compatibility changes
use fluxencrypt::{
    config::{Config, RsaKeySize, CipherSuite},
    encryption::{HybridCipher, rsa_oaep::RsaOaepCipher},
    keys::KeyPair,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 FluxEncrypt Go Cryptum Compatibility Validation");
    println!("================================================\n");
    
    // 1. Verify default configuration
    println!("✓ Testing default configuration...");
    let config = Config::default();
    assert_eq!(config.rsa_key_size, RsaKeySize::Rsa4096, "Default RSA key size should be 4096-bit");
    assert_eq!(config.cipher_suite, CipherSuite::Aes256Gcm, "Default cipher suite should be AES-256-GCM");
    println!("  - Default RSA key size: 4096-bit ✓");
    println!("  - Default cipher suite: AES-256-GCM ✓");
    println!("  - AES key length: {} bytes ✓", config.key_length());
    println!("  - GCM nonce length: {} bytes ✓", config.nonce_length());
    println!("  - GCM tag length: {} bytes ✓\n", config.tag_length());
    
    // 2. Test RSA-OAEP with SHA-512
    println!("✓ Testing RSA-OAEP with SHA-512...");
    let rsa_cipher = RsaOaepCipher::new();
    
    // Test 4096-bit key max plaintext length
    let keypair_4096 = KeyPair::generate(4096)?;
    let max_plaintext_4096 = rsa_cipher.max_plaintext_length(keypair_4096.public_key())?;
    println!("  - 4096-bit RSA max plaintext: {} bytes (512 - 130 = 382) ✓", max_plaintext_4096);
    assert_eq!(max_plaintext_4096, 382, "4096-bit RSA with SHA-512 should allow 382 bytes max plaintext");
    
    // Test 2048-bit key max plaintext length  
    let keypair_2048 = KeyPair::generate(2048)?;
    let max_plaintext_2048 = rsa_cipher.max_plaintext_length(keypair_2048.public_key())?;
    println!("  - 2048-bit RSA max plaintext: {} bytes (256 - 130 = 126) ✓", max_plaintext_2048);
    assert_eq!(max_plaintext_2048, 126, "2048-bit RSA with SHA-512 should allow 126 bytes max plaintext");
    
    // 3. Test PKCS1 key format
    println!("\n✓ Testing PKCS1 key format...");
    let public_pem = keypair_2048.public_key().to_pem()?;
    let private_pem = keypair_2048.private_key().to_pem()?;
    
    assert!(public_pem.starts_with("-----BEGIN RSA PUBLIC KEY-----"), "Public key should use PKCS1 format");
    assert!(private_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"), "Private key should use PKCS1 format");
    println!("  - Public key uses RSA PUBLIC KEY header ✓");
    println!("  - Private key uses RSA PRIVATE KEY header ✓");
    
    // 4. Test hybrid encryption format
    println!("\n✓ Testing hybrid encryption format...");
    let hybrid_cipher = HybridCipher::new(config);
    let test_data = b"Test data for Go cryptum compatibility";
    
    // Test size limit
    let large_data = vec![0x42u8; 512 * 1024 + 1]; // Over 512KB
    let result = hybrid_cipher.encrypt(keypair_4096.public_key(), &large_data);
    assert!(result.is_err(), "Should reject data over 512KB");
    println!("  - 512KB size limit enforced ✓");
    
    // Test encryption/decryption with correct format
    let ciphertext = hybrid_cipher.encrypt(keypair_4096.public_key(), test_data)?;
    println!("  - Ciphertext length: {} bytes", ciphertext.len());
    
    // Verify format: [encrypted_session_key(512)][nonce(12)][ciphertext+tag]
    let expected_len = 512 + 12 + test_data.len() + 16;
    assert_eq!(ciphertext.len(), expected_len, "Ciphertext should follow Go cryptum format");
    println!("  - Format: [encrypted_key(512)][nonce(12)][ciphertext+tag] ✓");
    
    // Test decryption
    let decrypted = hybrid_cipher.decrypt(keypair_4096.private_key(), &ciphertext)?;
    assert_eq!(decrypted, test_data, "Decryption should recover original data");
    println!("  - Encryption/decryption roundtrip ✓");
    
    println!("\n🎉 All compatibility tests passed!");
    println!("FluxEncrypt is now compatible with Go cryptum library format:");
    println!("  • RSA-OAEP with SHA-512");
    println!("  • AES-256-GCM default");
    println!("  • 4096-bit RSA keys default");
    println!("  • PKCS1 key format");
    println!("  • [encrypted_key(512)][nonce(12)][ciphertext+tag] data format");
    println!("  • 512KB blob encryption size limit");
    
    Ok(())
}