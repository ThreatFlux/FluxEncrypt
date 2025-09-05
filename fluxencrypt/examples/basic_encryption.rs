//! Basic encryption and decryption example.
//!
//! This example demonstrates the fundamental usage of FluxEncrypt for
//! encrypting and decrypting data using hybrid encryption.

use fluxencrypt::keys::KeyPair;
use fluxencrypt::{Config, HybridCipher};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("FluxEncrypt Basic Encryption Example");
    println!("====================================");

    // Generate a new 2048-bit RSA key pair
    println!("1. Generating RSA key pair (2048-bit)...");
    let keypair = KeyPair::generate(2048)?;
    println!("   ✓ Key pair generated successfully");

    // Create a cipher with default configuration
    println!("2. Creating hybrid cipher...");
    let config = Config::default();
    let cipher = HybridCipher::new(config);
    println!("   ✓ Cipher created with AES-256-GCM");

    // Sample data to encrypt
    let plaintext = b"Hello, FluxEncrypt! This is a basic encryption example.";
    println!(
        "3. Original data: {:?}",
        std::str::from_utf8(plaintext).unwrap()
    );
    println!("   Size: {} bytes", plaintext.len());

    // Encrypt the data
    println!("4. Encrypting data...");
    let ciphertext = cipher.encrypt(keypair.public_key(), plaintext)?;
    println!("   ✓ Data encrypted successfully");
    println!("   Ciphertext size: {} bytes", ciphertext.len());

    // Decrypt the data
    println!("5. Decrypting data...");
    let decrypted = cipher.decrypt(keypair.private_key(), &ciphertext)?;
    println!("   ✓ Data decrypted successfully");
    println!("   Decrypted size: {} bytes", decrypted.len());

    // Verify the data
    println!("6. Verifying data integrity...");
    if plaintext == decrypted.as_slice() {
        println!("   ✓ Data integrity verified - encryption/decryption successful!");
        println!(
            "   Decrypted data: {:?}",
            std::str::from_utf8(&decrypted).unwrap()
        );
    } else {
        eprintln!("   ✗ Data integrity check failed!");
        return Err("Decrypted data does not match original".into());
    }

    println!("\nBasic encryption example completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encryption() {
        // This test would run the main example logic
        // For now, we'll just test key generation
        let keypair = KeyPair::generate(2048).unwrap();
        assert_eq!(keypair.public_key().key_size_bits(), 2048);
        assert_eq!(keypair.private_key().key_size_bits(), 2048);
    }
}
