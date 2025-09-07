//! Tests for streaming operations with progress tracking.

use crate::cli_helpers::*;
use std::fs;

#[test]
#[ignore = "Requires built CLI binary"]
fn test_streaming_with_progress() {
    let env = TestEnvironment::new();

    // Generate keys
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    let (large_input, encrypted_file, decrypted_file) = setup_streaming_files(&env);

    // Create a large file
    let large_content = "This is a line of test content for streaming.\n".repeat(10000);
    fs::write(&large_input, &large_content).unwrap();

    // Stream encrypt with progress
    stream_encrypt_with_progress(&env, &large_input, &encrypted_file);

    // Stream decrypt
    stream_decrypt_with_progress(&env, &encrypted_file, &decrypted_file);

    // Verify content
    let decrypted_content = fs::read_to_string(&decrypted_file).unwrap();
    assert_eq!(decrypted_content, large_content);
}

fn setup_streaming_files(
    env: &TestEnvironment,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let large_input = env.temp_dir.path().join("large_input.txt");
    let encrypted_file = env.temp_dir.path().join("large_encrypted.enc");
    let decrypted_file = env.temp_dir.path().join("large_decrypted.txt");
    (large_input, encrypted_file, decrypted_file)
}

fn stream_encrypt_with_progress(
    env: &TestEnvironment,
    input_file: &std::path::Path,
    encrypted_file: &std::path::Path,
) {
    let output = run_cli(&[
        "stream",
        "encrypt",
        "--public-key",
        env.public_key_path.to_str().unwrap(),
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        encrypted_file.to_str().unwrap(),
        "--chunk-size",
        "4096",
        "--progress",
    ]);

    assert_cli_success(&output, "Stream encryption");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Progress") || stdout.contains("%") || stdout.contains("bytes"),
        "Should show progress information"
    );
}

fn stream_decrypt_with_progress(
    env: &TestEnvironment,
    encrypted_file: &std::path::Path,
    decrypted_file: &std::path::Path,
) {
    let output = run_cli(&[
        "stream",
        "decrypt",
        "--private-key",
        env.private_key_path.to_str().unwrap(),
        "--input",
        encrypted_file.to_str().unwrap(),
        "--output",
        decrypted_file.to_str().unwrap(),
        "--progress",
    ]);

    assert_cli_success(&output, "Stream decryption");
}
