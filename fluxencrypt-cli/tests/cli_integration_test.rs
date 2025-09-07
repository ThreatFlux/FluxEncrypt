//! Integration tests for FluxEncrypt CLI commands.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn get_cli_command() -> Command {
    Command::cargo_bin("fluxencrypt-cli").unwrap()
}

#[test]
fn test_keygen_default_4096_bits() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    let mut cmd = get_cli_command();
    cmd.arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("test_key");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("4096-bit RSA key pair"));

    // Verify files were created
    assert!(output_dir.join("test_key.pub").exists());
    assert!(output_dir.join("test_key.pem").exists());
}

#[test]
fn test_keygen_base64_encoding() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    let mut cmd = get_cli_command();
    cmd.arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("test_b64")
        .arg("--base64");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Saving keys in base64 format"));

    // Verify the public key is base64 encoded
    let pub_key = fs::read_to_string(output_dir.join("test_b64.pub")).unwrap();
    // Base64 encoded PEM should not start with "-----BEGIN"
    assert!(!pub_key.starts_with("-----BEGIN"));
    // Should be valid base64
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    assert!(STANDARD.decode(&pub_key).is_ok());
}

#[test]
fn test_encrypt_string_with_data_flag() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    // First generate a key pair
    let mut keygen = get_cli_command();
    keygen
        .arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("test");
    keygen.assert().success();

    // Test string encryption with --data flag
    let mut encrypt = get_cli_command();
    encrypt
        .arg("encrypt")
        .arg("--key")
        .arg(output_dir.join("test.pub"))
        .arg("--data")
        .arg("Hello, World!");

    let output = encrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Output should be base64 encoded by default
    let lines: Vec<&str> = stdout.lines().collect();
    let encrypted_line = lines.last().unwrap();

    // Should be valid base64
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    assert!(STANDARD.decode(encrypted_line).is_ok());
}

#[test]
fn test_encrypt_decrypt_roundtrip_base64() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    // Generate key pair
    let mut keygen = get_cli_command();
    keygen
        .arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("roundtrip");
    keygen.assert().success();

    let test_message = "Test message for base64 roundtrip";
    let encrypted_file = output_dir.join("encrypted.txt");

    // Encrypt to file (should be base64 by default)
    let mut encrypt = get_cli_command();
    encrypt
        .arg("encrypt")
        .arg("--key")
        .arg(output_dir.join("roundtrip.pub"))
        .arg("--data")
        .arg(test_message)
        .arg("--output")
        .arg(&encrypted_file);

    encrypt
        .assert()
        .success()
        .stdout(predicate::str::contains("(base64 encoded)"));

    // Verify encrypted file contains base64
    let encrypted_content = fs::read_to_string(&encrypted_file).unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    assert!(STANDARD.decode(&encrypted_content).is_ok());

    // Decrypt from file
    let mut decrypt = get_cli_command();
    decrypt
        .arg("decrypt")
        .arg("--key")
        .arg(output_dir.join("roundtrip.pem"))
        .arg("--input")
        .arg(&encrypted_file);

    let output = decrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Verify decrypted message matches
    assert!(stdout.contains(test_message));
}

#[test]
fn test_encrypt_raw_binary_mode() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    // Generate key pair
    let mut keygen = get_cli_command();
    keygen
        .arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("raw_test");
    keygen.assert().success();

    let raw_file = output_dir.join("raw.bin");

    // Encrypt with --raw flag
    let mut encrypt = get_cli_command();
    encrypt
        .arg("encrypt")
        .arg("--key")
        .arg(output_dir.join("raw_test.pub"))
        .arg("--data")
        .arg("Raw binary test")
        .arg("--output")
        .arg(&raw_file)
        .arg("--raw");

    encrypt
        .assert()
        .success()
        .stdout(predicate::str::contains("(raw binary)"));

    // Verify file is NOT base64
    let raw_content = fs::read(&raw_file).unwrap();
    let raw_str = String::from_utf8(raw_content.clone());
    // Raw binary should not be valid UTF-8 string (most likely)
    // or if it is, it shouldn't be valid base64
    if let Ok(s) = raw_str {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        assert!(STANDARD.decode(&s).is_err() || s.contains('\0'));
    }

    // Decrypt with --raw flag
    let mut decrypt = get_cli_command();
    decrypt
        .arg("decrypt")
        .arg("--key")
        .arg(output_dir.join("raw_test.pem"))
        .arg("--input")
        .arg(&raw_file)
        .arg("--raw");

    let output = decrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Raw binary test"));
}

#[test]
fn test_decrypt_base64_string_with_data_flag() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    // Generate key pair
    let mut keygen = get_cli_command();
    keygen
        .arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("data_test");
    keygen.assert().success();

    let test_message = "Decrypt via --data flag";

    // First encrypt to get base64
    let mut encrypt = get_cli_command();
    encrypt
        .arg("encrypt")
        .arg("--key")
        .arg(output_dir.join("data_test.pub"))
        .arg("--data")
        .arg(test_message);

    let output = encrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    let encrypted_b64 = lines.last().unwrap();

    // Decrypt using --data flag with base64 string
    let mut decrypt = get_cli_command();
    decrypt
        .arg("decrypt")
        .arg("--key")
        .arg(output_dir.join("data_test.pem"))
        .arg("--data")
        .arg(encrypted_b64);

    let output = decrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains(test_message));
}

#[test]
fn test_base64_key_usage() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    // Generate base64 encoded keys
    let mut keygen = get_cli_command();
    keygen
        .arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("b64_keys")
        .arg("--base64");
    keygen.assert().success();

    // Use base64 encoded key for encryption
    let mut encrypt = get_cli_command();
    encrypt
        .arg("encrypt")
        .arg("--key")
        .arg(output_dir.join("b64_keys.pub"))
        .arg("--data")
        .arg("Test with base64 keys");

    let output = encrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    let encrypted = lines.last().unwrap();

    // Decrypt with base64 encoded private key
    let mut decrypt = get_cli_command();
    decrypt
        .arg("decrypt")
        .arg("--key")
        .arg(output_dir.join("b64_keys.pem"))
        .arg("--data")
        .arg(encrypted);

    let output = decrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Test with base64 keys"));
}

#[test]
fn test_file_encryption_base64_default() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    // Generate keys
    let mut keygen = get_cli_command();
    keygen
        .arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("file_test");
    keygen.assert().success();

    // Create test file
    let input_file = output_dir.join("input.txt");
    let encrypted_file = output_dir.join("encrypted.txt");
    fs::write(&input_file, "File content for encryption").unwrap();

    // Encrypt file (should produce base64 by default)
    let mut encrypt = get_cli_command();
    encrypt
        .arg("encrypt")
        .arg("--key")
        .arg(output_dir.join("file_test.pub"))
        .arg("--input")
        .arg(&input_file)
        .arg("--output")
        .arg(&encrypted_file);

    encrypt
        .assert()
        .success()
        .stdout(predicate::str::contains("Successfully encrypted"));

    // Verify encrypted file is base64
    let encrypted_content = fs::read_to_string(&encrypted_file).unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    assert!(STANDARD.decode(&encrypted_content).is_ok());

    // Decrypt file
    let decrypted_file = output_dir.join("decrypted.txt");
    let mut decrypt = get_cli_command();
    decrypt
        .arg("decrypt")
        .arg("--key")
        .arg(output_dir.join("file_test.pem"))
        .arg("--input")
        .arg(&encrypted_file)
        .arg("--output")
        .arg(&decrypted_file);

    decrypt.assert().success();

    // Verify content matches
    let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
    assert_eq!(decrypted_content, "File content for encryption");
}

#[test]
fn test_stdin_stdout_encryption() {
    let temp_dir = tempdir().unwrap();
    let output_dir = temp_dir.path();

    // Generate keys
    let mut keygen = get_cli_command();
    keygen
        .arg("keygen")
        .arg("-o")
        .arg(output_dir)
        .arg("-n")
        .arg("stdio_test");
    keygen.assert().success();

    // Test stdin encryption (should output base64 to stdout)
    let mut encrypt = get_cli_command();
    encrypt
        .arg("encrypt")
        .arg("--key")
        .arg(output_dir.join("stdio_test.pub"))
        .write_stdin("Data from stdin");

    let output = encrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    let encrypted = lines.last().unwrap();

    // Should be valid base64
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    assert!(STANDARD.decode(encrypted).is_ok());

    // Decrypt from stdin
    let mut decrypt = get_cli_command();
    decrypt
        .arg("decrypt")
        .arg("--key")
        .arg(output_dir.join("stdio_test.pem"))
        .write_stdin(encrypted.to_string());

    let output = decrypt.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Data from stdin"));
}
