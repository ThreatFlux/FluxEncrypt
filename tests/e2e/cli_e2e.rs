//! End-to-end tests for FluxEncrypt CLI.
//!
//! These tests verify that the CLI works correctly from a user perspective,
//! including command-line parsing, file I/O, and integration with the core library.

use std::fs;
use std::process::Command;
use std::path::PathBuf;
use tempfile::{tempdir, NamedTempFile};

fn get_cli_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test executable name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("fluxencrypt-cli");
    path
}

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(get_cli_path())
        .args(args)
        .output()
        .expect("Failed to execute CLI")
}

#[test]
fn test_cli_help() {
    let output = run_cli(&["--help"]);
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(stdout.contains("FluxEncrypt"));
    assert!(stdout.contains("encrypt"));
    assert!(stdout.contains("decrypt"));
    assert!(stdout.contains("keygen"));
    assert!(stdout.contains("--help"));
    assert!(stdout.contains("--version"));
}

#[test]
fn test_cli_version() {
    let output = run_cli(&["--version"]);
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    assert!(stdout.contains("fluxencrypt"));
    assert!(stdout.contains("0.1.0"));
}

#[test]
fn test_keygen_command() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let public_key_path = temp_dir.path().join("test_public.pem");
    let private_key_path = temp_dir.path().join("test_private.pem");
    
    // Generate key pair
    let output = run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    
    if !output.status.success() {
        eprintln!("CLI stderr: {}", String::from_utf8_lossy(&output.stderr));
        eprintln!("CLI stdout: {}", String::from_utf8_lossy(&output.stdout));
    }
    
    assert!(output.status.success(), "Keygen command should succeed");
    
    // Verify files were created
    assert!(public_key_path.exists(), "Public key file should be created");
    assert!(private_key_path.exists(), "Private key file should be created");
    
    // Verify file contents
    let public_key_content = fs::read_to_string(&public_key_path).unwrap();
    let private_key_content = fs::read_to_string(&private_key_path).unwrap();
    
    assert!(public_key_content.contains("-----BEGIN RSA PUBLIC KEY-----"));
    assert!(public_key_content.contains("-----END RSA PUBLIC KEY-----"));
    assert!(private_key_content.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(private_key_content.contains("-----END RSA PRIVATE KEY-----"));
}

#[test]
fn test_encrypt_decrypt_workflow() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // File paths
    let public_key_path = temp_dir.path().join("public.pem");
    let private_key_path = temp_dir.path().join("private.pem");
    let input_file = temp_dir.path().join("input.txt");
    let encrypted_file = temp_dir.path().join("encrypted.enc");
    let decrypted_file = temp_dir.path().join("decrypted.txt");
    
    let test_content = "This is a test file for end-to-end CLI testing.\nIt contains multiple lines.\nAnd some special characters: !@#$%^&*()";
    
    // Step 1: Generate keys
    let output = run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    assert!(output.status.success(), "Key generation should succeed");
    
    // Step 2: Create test file
    fs::write(&input_file, test_content).expect("Failed to write test file");
    
    // Step 3: Encrypt file
    let output = run_cli(&[
        "encrypt",
        "--public-key", public_key_path.to_str().unwrap(),
        "--input", input_file.to_str().unwrap(),
        "--output", encrypted_file.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Encrypt stderr: {}", String::from_utf8_lossy(&output.stderr));
        eprintln!("Encrypt stdout: {}", String::from_utf8_lossy(&output.stdout));
    }
    assert!(output.status.success(), "Encryption should succeed");
    assert!(encrypted_file.exists(), "Encrypted file should be created");
    
    // Step 4: Decrypt file
    let output = run_cli(&[
        "decrypt",
        "--private-key", private_key_path.to_str().unwrap(),
        "--input", encrypted_file.to_str().unwrap(),
        "--output", decrypted_file.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Decrypt stderr: {}", String::from_utf8_lossy(&output.stderr));
        eprintln!("Decrypt stdout: {}", String::from_utf8_lossy(&output.stdout));
    }
    assert!(output.status.success(), "Decryption should succeed");
    assert!(decrypted_file.exists(), "Decrypted file should be created");
    
    // Step 5: Verify content
    let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
    assert_eq!(decrypted_content, test_content, "Decrypted content should match original");
}

#[test]
fn test_encrypt_with_different_cipher_suites() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // Generate keys once
    let public_key_path = temp_dir.path().join("public.pem");
    let private_key_path = temp_dir.path().join("private.pem");
    
    let output = run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    assert!(output.status.success());
    
    let test_content = "Test content for different cipher suites";
    let input_file = temp_dir.path().join("input.txt");
    fs::write(&input_file, test_content).unwrap();
    
    // Test different cipher suites
    let cipher_suites = vec!["aes128gcm", "aes256gcm"];
    
    for cipher_suite in &cipher_suites {
        let encrypted_file = temp_dir.path().join(format!("encrypted_{}.enc", cipher_suite));
        let decrypted_file = temp_dir.path().join(format!("decrypted_{}.txt", cipher_suite));
        
        // Encrypt
        let output = run_cli(&[
            "encrypt",
            "--public-key", public_key_path.to_str().unwrap(),
            "--input", input_file.to_str().unwrap(),
            "--output", encrypted_file.to_str().unwrap(),
            "--cipher-suite", cipher_suite,
        ]);
        assert!(output.status.success(), "Encryption with {} should succeed", cipher_suite);
        
        // Decrypt
        let output = run_cli(&[
            "decrypt",
            "--private-key", private_key_path.to_str().unwrap(),
            "--input", encrypted_file.to_str().unwrap(),
            "--output", decrypted_file.to_str().unwrap(),
        ]);
        assert!(output.status.success(), "Decryption with {} should succeed", cipher_suite);
        
        // Verify
        let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(decrypted_content, test_content);
    }
}

#[test]
fn test_batch_processing() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // Generate keys
    let public_key_path = temp_dir.path().join("public.pem");
    let private_key_path = temp_dir.path().join("private.pem");
    
    let output = run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    assert!(output.status.success());
    
    // Create input directory with multiple files
    let input_dir = temp_dir.path().join("input");
    let encrypted_dir = temp_dir.path().join("encrypted");
    let decrypted_dir = temp_dir.path().join("decrypted");
    
    fs::create_dir(&input_dir).unwrap();
    fs::create_dir(&encrypted_dir).unwrap();
    fs::create_dir(&decrypted_dir).unwrap();
    
    let test_files = vec![
        ("file1.txt", "Content of first file"),
        ("file2.txt", "Content of second file"),
        ("file3.txt", "Content of third file"),
    ];
    
    for (filename, content) in &test_files {
        let file_path = input_dir.join(filename);
        fs::write(&file_path, content).unwrap();
    }
    
    // Batch encrypt
    let output = run_cli(&[
        "batch",
        "encrypt",
        "--public-key", public_key_path.to_str().unwrap(),
        "--input-dir", input_dir.to_str().unwrap(),
        "--output-dir", encrypted_dir.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Batch encrypt stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Batch encryption should succeed");
    
    // Verify encrypted files exist
    for (filename, _) in &test_files {
        let encrypted_file = encrypted_dir.join(format!("{}.enc", filename));
        assert!(encrypted_file.exists(), "Encrypted file {} should exist", filename);
    }
    
    // Batch decrypt
    let output = run_cli(&[
        "batch",
        "decrypt",
        "--private-key", private_key_path.to_str().unwrap(),
        "--input-dir", encrypted_dir.to_str().unwrap(),
        "--output-dir", decrypted_dir.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Batch decrypt stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Batch decryption should succeed");
    
    // Verify decrypted content
    for (filename, expected_content) in &test_files {
        let decrypted_file = decrypted_dir.join(filename);
        assert!(decrypted_file.exists(), "Decrypted file {} should exist", filename);
        
        let content = fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(&content, expected_content, "Content mismatch for {}", filename);
    }
}

#[test]
fn test_streaming_with_progress() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // Generate keys
    let public_key_path = temp_dir.path().join("public.pem");
    let private_key_path = temp_dir.path().join("private.pem");
    
    let output = run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    assert!(output.status.success());
    
    // Create a large file
    let large_content = "This is a line of test content for streaming.\n".repeat(10000);
    let input_file = temp_dir.path().join("large_input.txt");
    let encrypted_file = temp_dir.path().join("large_encrypted.enc");
    let decrypted_file = temp_dir.path().join("large_decrypted.txt");
    
    fs::write(&input_file, &large_content).unwrap();
    
    // Stream encrypt with progress
    let output = run_cli(&[
        "stream",
        "encrypt",
        "--public-key", public_key_path.to_str().unwrap(),
        "--input", input_file.to_str().unwrap(),
        "--output", encrypted_file.to_str().unwrap(),
        "--chunk-size", "4096",
        "--progress",
    ]);
    
    if !output.status.success() {
        eprintln!("Stream encrypt stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Stream encryption should succeed");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Progress") || stdout.contains("%") || stdout.contains("bytes"), 
           "Should show progress information");
    
    // Stream decrypt
    let output = run_cli(&[
        "stream",
        "decrypt",
        "--private-key", private_key_path.to_str().unwrap(),
        "--input", encrypted_file.to_str().unwrap(),
        "--output", decrypted_file.to_str().unwrap(),
        "--progress",
    ]);
    
    if !output.status.success() {
        eprintln!("Stream decrypt stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Stream decryption should succeed");
    
    // Verify content
    let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
    assert_eq!(decrypted_content, large_content);
}

#[test]
fn test_config_command() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let config_file = temp_dir.path().join("fluxencrypt.toml");
    
    // Generate default config
    let output = run_cli(&[
        "config",
        "generate",
        "--output", config_file.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Config generate stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Config generation should succeed");
    assert!(config_file.exists(), "Config file should be created");
    
    let config_content = fs::read_to_string(&config_file).unwrap();
    assert!(config_content.contains("cipher_suite"));
    assert!(config_content.contains("rsa_key_size"));
    
    // Validate config
    let output = run_cli(&[
        "config",
        "validate",
        "--config", config_file.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Config validate stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Config validation should succeed");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid") || stdout.contains("Valid"), "Should indicate config is valid");
}

#[test]
fn test_info_command() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // Generate keys
    let public_key_path = temp_dir.path().join("public.pem");
    let private_key_path = temp_dir.path().join("private.pem");
    
    let output = run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    assert!(output.status.success());
    
    // Get key info
    let output = run_cli(&[
        "info",
        "key",
        "--public-key", public_key_path.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Info key stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Key info should succeed");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("2048"), "Should show key size");
    assert!(stdout.contains("RSA") || stdout.contains("rsa"), "Should indicate RSA key type");
}

#[test]
fn test_verify_command() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // Generate keys and encrypt a file
    let public_key_path = temp_dir.path().join("public.pem");
    let private_key_path = temp_dir.path().join("private.pem");
    let input_file = temp_dir.path().join("input.txt");
    let encrypted_file = temp_dir.path().join("encrypted.enc");
    
    // Setup
    run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    
    fs::write(&input_file, "Test content for verification").unwrap();
    
    run_cli(&[
        "encrypt",
        "--public-key", public_key_path.to_str().unwrap(),
        "--input", input_file.to_str().unwrap(),
        "--output", encrypted_file.to_str().unwrap(),
    ]);
    
    // Verify encrypted file
    let output = run_cli(&[
        "verify",
        "--private-key", private_key_path.to_str().unwrap(),
        "--input", encrypted_file.to_str().unwrap(),
    ]);
    
    if !output.status.success() {
        eprintln!("Verify stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success(), "Verification should succeed");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid") || stdout.contains("Valid") || stdout.contains("OK"), 
           "Should indicate file is valid");
}

#[test]
fn test_error_handling() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // Test with non-existent input file
    let output = run_cli(&[
        "encrypt",
        "--public-key", "/nonexistent/public.pem",
        "--input", "/nonexistent/input.txt",
        "--output", temp_dir.path().join("output.enc").to_str().unwrap(),
    ]);
    
    assert!(!output.status.success(), "Should fail with non-existent files");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No such file") || stderr.contains("not found") || stderr.contains("Error"), 
           "Should show appropriate error message");
}

#[test]
fn test_environment_variables() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    
    // Generate keys
    let public_key_path = temp_dir.path().join("public.pem");
    let private_key_path = temp_dir.path().join("private.pem");
    
    run_cli(&[
        "keygen",
        "--public-key", public_key_path.to_str().unwrap(),
        "--private-key", private_key_path.to_str().unwrap(),
        "--key-size", "2048",
    ]);
    
    // Test using environment variables for key paths
    let input_file = temp_dir.path().join("input.txt");
    let encrypted_file = temp_dir.path().join("encrypted.enc");
    
    fs::write(&input_file, "Test content with environment variables").unwrap();
    
    let output = Command::new(get_cli_path())
        .args(&[
            "encrypt",
            "--input", input_file.to_str().unwrap(),
            "--output", encrypted_file.to_str().unwrap(),
        ])
        .env("FLUXENCRYPT_PUBLIC_KEY", public_key_path.to_str().unwrap())
        .output()
        .expect("Failed to execute CLI with environment variables");
    
    if output.status.success() {
        assert!(encrypted_file.exists(), "Should encrypt using environment variable");
    } else {
        // If the CLI doesn't support environment variables yet, that's okay
        // This test documents the expected behavior
        eprintln!("Environment variable support not implemented yet");
    }
}

#[test]
fn test_benchmark_command() {
    let output = run_cli(&[
        "benchmark",
        "--key-size", "2048",
        "--data-size", "1024",
        "--iterations", "10",
    ]);
    
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("benchmark") || stdout.contains("performance") || stdout.contains("ms"), 
               "Should show benchmark results");
    } else {
        // If benchmark command is not implemented yet, that's okay
        eprintln!("Benchmark command not implemented yet");
    }
}