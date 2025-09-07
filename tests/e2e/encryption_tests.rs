//! Tests for encryption and decryption workflows.

use crate::cli_helpers::*;
use std::fs;

const TEST_CONTENT: &str = "This is a test file for end-to-end CLI testing.\nIt contains multiple lines.\nAnd some special characters: !@#$%^&*()";

#[test]
#[ignore = "Requires built CLI binary"]
fn test_encrypt_decrypt_workflow() {
    let env = TestEnvironment::new();

    // Step 1: Generate keys
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    let (input_file, encrypted_file, decrypted_file) = setup_test_files(&env);

    // Step 2: Create test file
    fs::write(&input_file, TEST_CONTENT).expect("Failed to write test file");

    // Step 3: Encrypt file
    encrypt_file(&env, &input_file, &encrypted_file);

    // Step 4: Decrypt file
    decrypt_file(&env, &encrypted_file, &decrypted_file);

    // Step 5: Verify content
    let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, TEST_CONTENT,
        "Decrypted content should match original"
    );
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_encrypt_with_cipher_suites() {
    let env = TestEnvironment::new();

    // Generate keys once
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    let input_file = env.temp_dir.path().join("input.txt");
    fs::write(&input_file, TEST_CONTENT).unwrap();

    // Test different cipher suites
    let cipher_suites = vec!["aes128gcm", "aes256gcm"];

    for cipher_suite in &cipher_suites {
        test_cipher_suite(&env, &input_file, cipher_suite);
    }
}

fn setup_test_files(
    env: &TestEnvironment,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let input_file = env.temp_dir.path().join("input.txt");
    let encrypted_file = env.temp_dir.path().join("encrypted.enc");
    let decrypted_file = env.temp_dir.path().join("decrypted.txt");
    (input_file, encrypted_file, decrypted_file)
}

fn encrypt_file(
    env: &TestEnvironment,
    input_file: &std::path::Path,
    encrypted_file: &std::path::Path,
) {
    let output = run_cli(&[
        "encrypt",
        "--public-key",
        env.public_key_path.to_str().unwrap(),
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        encrypted_file.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Encryption");
    assert!(encrypted_file.exists(), "Encrypted file should be created");
}

fn decrypt_file(
    env: &TestEnvironment,
    encrypted_file: &std::path::Path,
    decrypted_file: &std::path::Path,
) {
    let output = run_cli(&[
        "decrypt",
        "--private-key",
        env.private_key_path.to_str().unwrap(),
        "--input",
        encrypted_file.to_str().unwrap(),
        "--output",
        decrypted_file.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Decryption");
    assert!(decrypted_file.exists(), "Decrypted file should be created");
}

fn test_cipher_suite(env: &TestEnvironment, input_file: &std::path::Path, cipher_suite: &str) {
    let encrypted_file = env
        .temp_dir
        .path()
        .join(format!("encrypted_{}.enc", cipher_suite));
    let decrypted_file = env
        .temp_dir
        .path()
        .join(format!("decrypted_{}.txt", cipher_suite));

    // Encrypt
    let output = run_cli(&[
        "encrypt",
        "--public-key",
        env.public_key_path.to_str().unwrap(),
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        encrypted_file.to_str().unwrap(),
        "--cipher-suite",
        cipher_suite,
    ]);
    assert_cli_success(&output, &format!("Encryption with {}", cipher_suite));

    // Decrypt
    let output = run_cli(&[
        "decrypt",
        "--private-key",
        env.private_key_path.to_str().unwrap(),
        "--input",
        encrypted_file.to_str().unwrap(),
        "--output",
        decrypted_file.to_str().unwrap(),
    ]);
    assert_cli_success(&output, &format!("Decryption with {}", cipher_suite));

    // Verify
    let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
    assert_eq!(decrypted_content, TEST_CONTENT);
}
