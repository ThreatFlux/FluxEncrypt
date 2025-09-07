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

    let temp_dir = setup_temp_directory()?;
    let keypair = generate_keypair()?;
    let (input_file, sample_content) = create_sample_file(&temp_dir)?;
    let cipher = create_cipher();

    let (encrypted_file, encrypted_content) =
        perform_encryption(&cipher, &input_file, &temp_dir, &keypair)?;
    let decrypted_file = perform_decryption(&cipher, &encrypted_file, &temp_dir, &keypair)?;
    verify_integrity(&sample_content, &decrypted_file)?;
    display_results(
        &sample_content,
        &encrypted_content,
        &decrypted_file,
        &temp_dir,
    )?;

    Ok(())
}

fn setup_temp_directory() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    Ok(tempdir()?)
}

fn generate_keypair() -> Result<KeyPair, Box<dyn std::error::Error>> {
    println!("1. Generating RSA key pair (4096-bit)...");
    let keypair = KeyPair::generate(4096)?;
    println!("   ✓ Key pair generated");
    Ok(keypair)
}

fn create_sample_file(
    temp_dir: &tempfile::TempDir,
) -> Result<(std::path::PathBuf, String), Box<dyn std::error::Error>> {
    let input_file = temp_dir.path().join("sample.txt");
    let sample_content = "This is a sample file for FluxEncrypt file encryption.\n".repeat(100);
    fs::write(&input_file, &sample_content)?;
    println!(
        "2. Created sample file: {} ({} bytes)",
        input_file.display(),
        sample_content.len()
    );
    Ok((input_file, sample_content))
}

fn create_cipher() -> FileStreamCipher {
    let config = Config::default();
    FileStreamCipher::new(config)
}

fn perform_encryption(
    cipher: &FileStreamCipher,
    input_file: &Path,
    temp_dir: &tempfile::TempDir,
    keypair: &KeyPair,
) -> Result<(std::path::PathBuf, Vec<u8>), Box<dyn std::error::Error>> {
    println!("3. Encrypting file...");
    let encrypted_file = temp_dir.path().join("sample.txt.enc");
    let bytes_encrypted =
        cipher.encrypt_file(input_file, &encrypted_file, keypair.public_key(), None)?;
    println!("   ✓ File encrypted: {} bytes processed", bytes_encrypted);
    println!("   Encrypted file: {}", encrypted_file.display());

    let encrypted_content = fs::read(&encrypted_file)?;
    println!("   Encrypted file size: {} bytes", encrypted_content.len());

    Ok((encrypted_file, encrypted_content))
}

fn perform_decryption(
    cipher: &FileStreamCipher,
    encrypted_file: &Path,
    temp_dir: &tempfile::TempDir,
    keypair: &KeyPair,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    println!("4. Decrypting file...");
    let decrypted_file = temp_dir.path().join("sample_decrypted.txt");
    let bytes_decrypted =
        cipher.decrypt_file(encrypted_file, &decrypted_file, keypair.private_key(), None)?;
    println!("   ✓ File decrypted: {} bytes processed", bytes_decrypted);
    println!("   Decrypted file: {}", decrypted_file.display());

    Ok(decrypted_file)
}

fn verify_integrity(
    sample_content: &str,
    decrypted_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("5. Verifying file integrity...");
    let decrypted_content = fs::read_to_string(decrypted_file)?;
    if *sample_content == decrypted_content {
        println!("   ✓ File integrity verified - content matches original!");
        Ok(())
    } else {
        eprintln!("   ✗ File integrity check failed!");
        Err("Decrypted content does not match original".into())
    }
}

fn display_results(
    sample_content: &str,
    encrypted_content: &[u8],
    decrypted_file: &Path,
    temp_dir: &tempfile::TempDir,
) -> Result<(), Box<dyn std::error::Error>> {
    let decrypted_content = fs::read_to_string(decrypted_file)?;

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
        let _keypair = KeyPair::generate(4096).unwrap();
        let cipher = FileStreamCipher::new(Config::default());

        // Test that cipher can be created successfully
        assert!(cipher.stream_cipher().config().validate().is_ok());
    }
}
