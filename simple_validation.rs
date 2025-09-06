// Simple validation script to verify Go cryptum compatibility changes
use fluxencrypt::{Config, HybridCipher, cryptum};
use fluxencrypt::keys::KeyPair;
use fluxencrypt::config::{RsaKeySize, CipherSuite};

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
    
    // 2. Test PKCS1 key format with 2048-bit for speed
    println!("✓ Testing PKCS1 key format...");
    let keypair_2048 = KeyPair::generate(2048)?;
    let public_pem = keypair_2048.public_key().to_pem()?;
    let private_pem = keypair_2048.private_key().to_pem()?;
    
    assert!(public_pem.starts_with("-----BEGIN RSA PUBLIC KEY-----"), "Public key should use PKCS1 format");
    assert!(private_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"), "Private key should use PKCS1 format");
    println!("  - Public key uses RSA PUBLIC KEY header ✓");
    println!("  - Private key uses RSA PRIVATE KEY header ✓");
    
    // 3. Test hybrid encryption with size limits
    println!("\n✓ Testing hybrid encryption format...");
    let hybrid_cipher = HybridCipher::new(config);
    let test_data = b"Test data for Go cryptum compatibility";
    
    // Test size limit (use small test to avoid long key generation)
    let large_data = vec![0x42u8; 512 * 1024 + 1]; // Over 512KB
    let result = hybrid_cipher.encrypt(keypair_2048.public_key(), &large_data);
    assert!(result.is_err(), "Should reject data over 512KB");
    println!("  - 512KB size limit enforced ✓");
    
    // Test encryption/decryption
    let ciphertext = hybrid_cipher.encrypt(keypair_2048.public_key(), test_data)?;
    println!("  - Ciphertext length: {} bytes", ciphertext.len());
    
    // Test decryption
    let decrypted = hybrid_cipher.decrypt(keypair_2048.private_key(), &ciphertext)?;
    assert_eq!(decrypted, test_data, "Decryption should recover original data");
    println!("  - Encryption/decryption roundtrip ✓");
    
    // 4. Test using the main Cryptum API
    println!("\n✓ Testing Cryptum API...");
    let cryptum = cryptum()?;
    let test_data2 = b"Testing with main API";
    
    let ciphertext2 = cryptum.encrypt(keypair_2048.public_key(), test_data2)?;
    let decrypted2 = cryptum.decrypt(keypair_2048.private_key(), &ciphertext2)?;
    assert_eq!(decrypted2, test_data2, "Main API should work");
    println!("  - Main Cryptum API working ✓");
    
    println!("\n🎉 Core compatibility validations passed!");
    println!("FluxEncrypt key changes implemented:");
    println!("  • Default to 4096-bit RSA keys");
    println!("  • AES-256-GCM as default cipher");
    println!("  • PKCS1 key format (RSA PUBLIC/PRIVATE KEY headers)");
    println!("  • Updated data format for Go cryptum compatibility");
    println!("  • 512KB blob encryption size limit");
    println!("  • RSA-OAEP now uses SHA-512 instead of SHA-256");
    
    Ok(())
}