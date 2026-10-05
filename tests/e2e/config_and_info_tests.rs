//! Tests for configuration, info, and other utility commands.

use crate::cli_helpers::*;
use std::fs;

#[test]
fn test_config_command() {
    let env = TestEnvironment::new();
    let output = std::process::Command::new(get_cli_path())
        .args(["config", "show"])
        .env("HOME", env.temp_dir.path())
        .env("XDG_CONFIG_HOME", env.temp_dir.path())
        .env("APPDATA", env.temp_dir.path())
        .output()
        .expect("config show");
    assert_cli_success(&output, "Config show");
    assert_output_contains(&output, &["Configuration"]);
}

#[test]
fn test_info_command() {
    let env = TestEnvironment::new();

    // Generate keys
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    // Get key info
    get_key_info(&env);
}

#[test]
fn test_verify_command() {
    let env = TestEnvironment::new();

    // Generate keys and encrypt a file
    setup_for_verification(&env);

    // Verify encrypted file
    verify_encrypted_file(&env);
}

#[test]
fn test_error_handling() {
    let env = TestEnvironment::new();

    // Test with non-existent input file
    test_nonexistent_file_error(&env);
}

#[test]
fn test_environment_variables() {
    let env = TestEnvironment::new();

    // Generate keys first
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    test_env_vars(&env);
}

#[test]
fn test_benchmark_command() {
    test_benchmark();
}

fn get_key_info(env: &TestEnvironment) {
    let output = run_cli(&["info", "--file", env.public_key_path.to_str().unwrap()]);

    assert_cli_success(&output, "Key info");

    assert_output_contains(&output, &["Public Key", "PEM"]);
}

fn setup_for_verification(env: &TestEnvironment) {
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    let input_file = env.temp_dir.path().join("input.txt");
    fs::write(&input_file, "Test content for verification").unwrap();

    let encrypted_file = env.temp_dir.path().join("encrypted.enc");
    let output = run_cli(&[
        "encrypt",
        "--raw",
        "--key",
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
        "--key",
        env.private_key_path.to_str().unwrap(),
        "--file",
        encrypted_file.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Verification");

    assert_output_contains(&output, &["completed successfully"]);
}

fn test_nonexistent_file_error(env: &TestEnvironment) {
    let output = run_cli(&[
        "encrypt",
        "--key",
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

    assert_cli_success(&output, "Environment public key encryption");
    assert!(encrypted_file.exists());
}

fn test_benchmark() {
    let output = run_cli(&[
        "benchmark",
        "--key-sizes",
        "2048",
        "--sizes",
        "1",
        "--iterations",
        "10",
    ]);

    assert_cli_success(&output, "Benchmark command");
    assert_output_contains(&output, &["Benchmark"]);
}
