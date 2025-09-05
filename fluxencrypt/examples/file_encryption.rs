//! File encryption and decryption example.
//!
//! This example shows how to encrypt and decrypt files using FluxEncrypt's
//! streaming capabilities for efficient handling of large files.

use fluxencrypt::keys::KeyPair;
use fluxencrypt::{stream::FileStreamCipher, Config};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("FluxEncrypt File Encryption Example");
    println!("===================================");

    // Create a temporary directory for our files
    let temp_dir = tempdir()?;
    let base_path = temp_dir.path();

    // Generate key pair
    println!("1. Generating RSA key pair...");
    let keypair = KeyPair::generate(2048)?;
    println!("   ✓ Key pair generated");

    // Create sample file
    let input_file = base_path.join("sample.txt");
    let sample_content = "This is a sample file for FluxEncrypt file encryption.\n".repeat(100);
    fs::write(&input_file, &sample_content)?;
    println!(
        "2. Created sample file: {} ({} bytes)",
        input_file.display(),
        sample_content.len()
    );

    // Create file stream cipher
    let config = Config::default();
    let cipher = FileStreamCipher::new(config);

    // Encrypt the file
    println!("3. Encrypting file...");
    let encrypted_file = base_path.join("sample.txt.enc");
    let bytes_encrypted = cipher.encrypt_file(
        &input_file,
        &encrypted_file,
        keypair.public_key(),
        None, // No progress callback for this example
    )?;
    println!("   ✓ File encrypted: {} bytes processed", bytes_encrypted);
    println!("   Encrypted file: {}", encrypted_file.display());

    // Verify encrypted file exists and has different content
    let encrypted_content = fs::read(&encrypted_file)?;
    println!("   Encrypted file size: {} bytes", encrypted_content.len());

    // Decrypt the file
    println!("4. Decrypting file...");
    let decrypted_file = base_path.join("sample_decrypted.txt");
    let bytes_decrypted = cipher.decrypt_file(
        &encrypted_file,
        &decrypted_file,
        keypair.private_key(),
        None, // No progress callback for this example
    )?;
    println!("   ✓ File decrypted: {} bytes processed", bytes_decrypted);
    println!("   Decrypted file: {}", decrypted_file.display());

    // Verify the decrypted content matches original
    println!("5. Verifying file integrity...");
    let decrypted_content = fs::read_to_string(&decrypted_file)?;
    if sample_content == decrypted_content {
        println!("   ✓ File integrity verified - content matches original!");
    } else {
        eprintln!("   ✗ File integrity check failed!");
        return Err("Decrypted content does not match original".into());
    }

    // Display file sizes for comparison
    println!("\nFile Size Comparison:");
    println!("  Original:  {} bytes", sample_content.len());
    println!("  Encrypted: {} bytes", encrypted_content.len());
    println!("  Decrypted: {} bytes", decrypted_content.len());

    println!("\nFile encryption example completed successfully!");
    println!("Files created in: {}", temp_dir.path().display());

    Ok(())
}

/// Example of encrypting multiple files
#[allow(dead_code)]
fn encrypt_multiple_files(
    base_path: &Path,
    keypair: &KeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = FileStreamCipher::new(Config::default());

    // Create multiple sample files
    let files = ["doc1.txt", "doc2.txt", "doc3.txt"];

    for (i, filename) in files.iter().enumerate() {
        let file_path = base_path.join(filename);
        let content = format!("This is document {} content.\n", i + 1).repeat(50);
        fs::write(&file_path, content)?;

        let encrypted_path = base_path.join(format!("{}.enc", filename));
        cipher.encrypt_file(&file_path, &encrypted_path, keypair.public_key(), None)?;

        println!("Encrypted: {} -> {}.enc", filename, filename);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_encryption_example() {
        // Test the core functionality without the full example
        let _keypair = KeyPair::generate(2048).unwrap();
        let cipher = FileStreamCipher::new(Config::default());

        // Test that cipher can be created successfully
        assert!(cipher.stream_cipher().config().validate().is_ok());
    }
}
