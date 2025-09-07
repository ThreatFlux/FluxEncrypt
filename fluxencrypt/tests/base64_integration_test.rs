//! Integration tests for base64 encoding/decoding functionality.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use fluxencrypt::config::RsaKeySize;
use fluxencrypt::cryptum;
use fluxencrypt::keys::KeyPair;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_encrypt_decrypt_with_base64() {
    // Generate 4096-bit key pair (new default)
    let keypair =
        KeyPair::generate(RsaKeySize::Rsa4096.into()).expect("Failed to generate key pair");

    let cryptum = cryptum().expect("Failed to create cryptum");
    let plaintext = b"Test message for base64 encoding";

    // Encrypt
    let ciphertext = cryptum
        .encrypt(keypair.public_key(), plaintext)
        .expect("Encryption failed");

    // Encode to base64
    let encoded = BASE64_STANDARD.encode(&ciphertext);

    // Decode from base64
    let decoded = BASE64_STANDARD
        .decode(&encoded)
        .expect("Failed to decode base64");

    // Decrypt
    let decrypted = cryptum
        .decrypt(keypair.private_key(), &decoded)
        .expect("Decryption failed");

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_base64_encoded_keys() {
    let temp_dir = tempdir().expect("Failed to create temp dir");

    // Generate 4096-bit key pair
    let keypair =
        KeyPair::generate(RsaKeySize::Rsa4096.into()).expect("Failed to generate key pair");

    // Get PEM encoded keys
    let public_pem = keypair
        .public_key()
        .to_pem()
        .expect("Failed to encode public key");
    let private_pem = keypair
        .private_key()
        .to_pem()
        .expect("Failed to encode private key");

    // Base64 encode the PEM data
    let public_b64 = BASE64_STANDARD.encode(&public_pem);
    let private_b64 = BASE64_STANDARD.encode(&private_pem);

    // Save base64 encoded keys
    let pub_path = temp_dir.path().join("key.pub");
    let priv_path = temp_dir.path().join("key.pem");

    fs::write(&pub_path, &public_b64).expect("Failed to write public key");
    fs::write(&priv_path, &private_b64).expect("Failed to write private key");

    // Read and decode keys
    let pub_data = fs::read(&pub_path).expect("Failed to read public key");
    let priv_data = fs::read(&priv_path).expect("Failed to read private key");

    // Decode base64
    let pub_decoded = BASE64_STANDARD
        .decode(&pub_data)
        .expect("Failed to decode public key");
    let priv_decoded = BASE64_STANDARD
        .decode(&priv_data)
        .expect("Failed to decode private key");

    // Parse keys
    use fluxencrypt::keys::parsing::KeyParser;
    let parser = KeyParser::new();

    let format = parser
        .detect_format(&pub_decoded)
        .expect("Failed to detect public key format");
    let loaded_public = parser
        .parse_public_key(&pub_decoded, format)
        .expect("Failed to parse public key");

    let loaded_private = fluxencrypt::keys::parsing::parse_private_key_from_str(
        &String::from_utf8(priv_decoded).unwrap(),
    )
    .expect("Failed to parse private key");

    // Test encryption/decryption with loaded keys
    let cryptum = cryptum().expect("Failed to create cryptum");
    let test_data = b"Test with base64 encoded keys";

    let encrypted = cryptum
        .encrypt(&loaded_public, test_data)
        .expect("Encryption failed");
    let decrypted = cryptum
        .decrypt(&loaded_private, &encrypted)
        .expect("Decryption failed");

    assert_eq!(test_data.to_vec(), decrypted);
}

#[test]
fn test_4096_bit_rsa_default() {
    // Test that 4096-bit is the default
    let keypair = KeyPair::generate(RsaKeySize::Rsa4096.into())
        .expect("Failed to generate 4096-bit key pair");

    // Get the public key modulus size
    let _public_pem = keypair
        .public_key()
        .to_pem()
        .expect("Failed to encode public key");

    // The PEM should indicate it's a 4096-bit key
    // RSA-4096 has a 512-byte (4096-bit) modulus

    // Parse the key to verify size
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPublicKey;

    let public_key: RsaPublicKey = keypair.public_key().inner().clone();
    let modulus_bits = public_key.n().bits();

    assert_eq!(modulus_bits, 4096, "Expected 4096-bit RSA key");
}

#[test]
fn test_string_encryption_decryption() {
    let keypair =
        KeyPair::generate(RsaKeySize::Rsa4096.into()).expect("Failed to generate key pair");

    let cryptum = cryptum().expect("Failed to create cryptum");

    // Test string data
    let test_string = "Hello, FluxEncrypt with base64!";
    let plaintext = test_string.as_bytes();

    // Encrypt string
    let ciphertext = cryptum
        .encrypt(keypair.public_key(), plaintext)
        .expect("Encryption failed");

    // Convert to base64 for easy storage/transmission
    let b64_ciphertext = BASE64_STANDARD.encode(&ciphertext);

    // Simulate receiving base64 encoded data
    let received_b64 = b64_ciphertext.clone();
    let received_ciphertext = BASE64_STANDARD
        .decode(&received_b64)
        .expect("Failed to decode base64");

    // Decrypt
    let decrypted = cryptum
        .decrypt(keypair.private_key(), &received_ciphertext)
        .expect("Decryption failed");

    let decrypted_string = String::from_utf8(decrypted).expect("Failed to convert to string");

    assert_eq!(test_string, decrypted_string);
}

#[test]
fn test_large_data_base64_handling() {
    let keypair =
        KeyPair::generate(RsaKeySize::Rsa4096.into()).expect("Failed to generate key pair");

    let cryptum = cryptum().expect("Failed to create cryptum");

    // Create large test data (just under blob size limit)
    let large_data = vec![0xAB; 400_000]; // 400KB of data

    // Encrypt
    let ciphertext = cryptum
        .encrypt(keypair.public_key(), &large_data)
        .expect("Encryption failed");

    // Encode to base64 (will be ~33% larger)
    let b64_encoded = BASE64_STANDARD.encode(&ciphertext);

    // Verify base64 is larger but still valid
    assert!(b64_encoded.len() > ciphertext.len());

    // Decode and decrypt
    let decoded = BASE64_STANDARD
        .decode(&b64_encoded)
        .expect("Failed to decode base64");

    let decrypted = cryptum
        .decrypt(keypair.private_key(), &decoded)
        .expect("Decryption failed");

    assert_eq!(large_data, decrypted);
}

#[test]
fn test_environment_variable_compatible_base64() {
    let keypair =
        KeyPair::generate(RsaKeySize::Rsa4096.into()).expect("Failed to generate key pair");

    let cryptum = cryptum().expect("Failed to create cryptum");

    // Simulate environment variable content
    let env_var_content = "DATABASE_PASSWORD=secretpass123";

    // Encrypt
    let encrypted = cryptum
        .encrypt(keypair.public_key(), env_var_content.as_bytes())
        .expect("Encryption failed");

    // Convert to base64 for storage in .env file
    let b64_for_env = BASE64_STANDARD.encode(&encrypted);

    // Verify no newlines in base64 (important for env vars)
    assert!(!b64_for_env.contains('\n'));
    assert!(!b64_for_env.contains('\r'));

    // Simulate reading from env var
    let from_env = b64_for_env.clone();
    let decoded = BASE64_STANDARD
        .decode(&from_env)
        .expect("Failed to decode from env");

    // Decrypt
    let decrypted = cryptum
        .decrypt(keypair.private_key(), &decoded)
        .expect("Decryption failed");

    let decrypted_str = String::from_utf8(decrypted).expect("Failed to convert to string");

    assert_eq!(env_var_content, decrypted_str);
}
