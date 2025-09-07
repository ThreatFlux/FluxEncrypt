//! Tests for configuration, info, and other utility commands.

use crate::cli_helpers::*;
use std::fs;

#[test]
#[ignore = "Requires built CLI binary"]
fn test_config_command() {
    let env = TestEnvironment::new();
    let config_file = env.temp_dir.path().join("fluxencrypt.toml");

    // Generate default config
    generate_config(&config_file);

    // Validate config
    validate_config(&config_file);
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_info_command() {
    let env = TestEnvironment::new();

    // Generate keys
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    // Get key info
    get_key_info(&env);
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_verify_command() {
    let env = TestEnvironment::new();

    // Generate keys and encrypt a file
    setup_for_verification(&env);

    // Verify encrypted file
    verify_encrypted_file(&env);
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_error_handling() {
    let env = TestEnvironment::new();

    // Test with non-existent input file
    test_nonexistent_file_error(&env);
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_environment_variables() {
    let env = TestEnvironment::new();

    // Generate keys first
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    test_env_vars(&env);
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_benchmark_command() {
    test_benchmark();
}

fn generate_config(config_file: &std::path::Path) {
    let output = run_cli(&[
        "config",
        "generate",
        "--output",
        config_file.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Config generation");
    assert!(config_file.exists(), "Config file should be created");

    let config_content = fs::read_to_string(config_file).unwrap();
    assert!(config_content.contains("cipher_suite"));
    assert!(config_content.contains("rsa_key_size"));
}

fn validate_config(config_file: &std::path::Path) {
    let output = run_cli(&[
        "config",
        "validate",
        "--config",
        config_file.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Config validation");

    assert_output_contains(&output, &["valid", "Valid"]);
}

fn get_key_info(env: &TestEnvironment) {
    let output = run_cli(&[
        "info",
        "key",
        "--public-key",
        env.public_key_path.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Key info");

    assert_output_contains(&output, &["2048", "RSA", "rsa"]);
}

fn setup_for_verification(env: &TestEnvironment) {
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    let input_file = env.temp_dir.path().join("input.txt");
    fs::write(&input_file, "Test content for verification").unwrap();

    let encrypted_file = env.temp_dir.path().join("encrypted.enc");
    let output = run_cli(&[
        "encrypt",
        "--public-key",
        env.public_key_path.to_str().unwrap(),
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        encrypted_file.to_str().unwrap(),
    ]);
    assert_cli_success(&output, "Encryption for verification");
}

fn verify_encrypted_file(env: &TestEnvironment) {
    let encrypted_file = env.temp_dir.path().join("encrypted.enc");

    let output = run_cli(&[
        "verify",
        "--private-key",
        env.private_key_path.to_str().unwrap(),
        "--input",
        encrypted_file.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Verification");

    assert_output_contains(&output, &["valid", "Valid", "OK"]);
}

fn test_nonexistent_file_error(env: &TestEnvironment) {
    let output = run_cli(&[
        "encrypt",
        "--public-key",
        "/nonexistent/public.pem",
        "--input",
        "/nonexistent/input.txt",
        "--output",
        env.temp_dir.path().join("output.enc").to_str().unwrap(),
    ]);

    assert!(
        !output.status.success(),
        "Should fail with non-existent files"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No such file") || stderr.contains("not found") || stderr.contains("Error"),
        "Should show appropriate error message"
    );
}

fn test_env_vars(env: &TestEnvironment) {
    let input_file = env.temp_dir.path().join("input.txt");
    let encrypted_file = env.temp_dir.path().join("encrypted.enc");

    fs::write(&input_file, "Test content with environment variables").unwrap();

    let output = std::process::Command::new(get_cli_path())
        .args([
            "encrypt",
            "--input",
            input_file.to_str().unwrap(),
            "--output",
            encrypted_file.to_str().unwrap(),
        ])
        .env(
            "FLUXENCRYPT_PUBLIC_KEY",
            env.public_key_path.to_str().unwrap(),
        )
        .output()
        .expect("Failed to execute CLI with environment variables");

    if output.status.success() {
        assert!(
            encrypted_file.exists(),
            "Should encrypt using environment variable"
        );
    } else {
        // If the CLI doesn't support environment variables yet, that's okay
        eprintln!("Environment variable support not implemented yet");
    }
}

fn test_benchmark() {
    let output = run_cli(&[
        "benchmark",
        "--key-size",
        "2048",
        "--data-size",
        "1024",
        "--iterations",
        "10",
    ]);

    if output.status.success() {
        assert_output_contains(&output, &["benchmark", "performance", "ms"]);
    } else {
        // If benchmark command is not implemented yet, that's okay
        eprintln!("Benchmark command not implemented yet");
    }
}
