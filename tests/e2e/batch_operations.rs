//! Tests for batch processing operations.

use crate::cli_helpers::*;
use std::fs;

#[test]
#[ignore = "Requires built CLI binary"]
fn test_batch_processing() {
    let env = TestEnvironment::new();

    // Generate keys
    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    let (input_dir, encrypted_dir, decrypted_dir) = setup_batch_directories(&env);
    create_test_files(&input_dir);

    // Batch encrypt
    batch_encrypt(&env, &input_dir, &encrypted_dir);

    // Batch decrypt
    batch_decrypt(&env, &encrypted_dir, &decrypted_dir);

    // Verify results
    verify_batch_results(&decrypted_dir);
}

fn setup_batch_directories(
    env: &TestEnvironment,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let input_dir = env.temp_dir.path().join("input");
    let encrypted_dir = env.temp_dir.path().join("encrypted");
    let decrypted_dir = env.temp_dir.path().join("decrypted");

    fs::create_dir(&input_dir).unwrap();
    fs::create_dir(&encrypted_dir).unwrap();
    fs::create_dir(&decrypted_dir).unwrap();

    (input_dir, encrypted_dir, decrypted_dir)
}

fn create_test_files(input_dir: &std::path::Path) {
    let test_files = vec![
        ("file1.txt", "Content of first file"),
        ("file2.txt", "Content of second file"),
        ("file3.txt", "Content of third file"),
    ];

    for (filename, content) in &test_files {
        let file_path = input_dir.join(filename);
        fs::write(&file_path, content).unwrap();
    }
}

fn batch_encrypt(
    env: &TestEnvironment,
    input_dir: &std::path::Path,
    encrypted_dir: &std::path::Path,
) {
    let output = run_cli(&[
        "batch",
        "encrypt",
        "--public-key",
        env.public_key_path.to_str().unwrap(),
        "--input-dir",
        input_dir.to_str().unwrap(),
        "--output-dir",
        encrypted_dir.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Batch encryption");

    // Verify encrypted files exist
    let test_files = ["file1.txt", "file2.txt", "file3.txt"];
    for filename in &test_files {
        let encrypted_file = encrypted_dir.join(format!("{}.enc", filename));
        assert!(
            encrypted_file.exists(),
            "Encrypted file {} should exist",
            filename
        );
    }
}

fn batch_decrypt(
    env: &TestEnvironment,
    encrypted_dir: &std::path::Path,
    decrypted_dir: &std::path::Path,
) {
    let output = run_cli(&[
        "batch",
        "decrypt",
        "--private-key",
        env.private_key_path.to_str().unwrap(),
        "--input-dir",
        encrypted_dir.to_str().unwrap(),
        "--output-dir",
        decrypted_dir.to_str().unwrap(),
    ]);

    assert_cli_success(&output, "Batch decryption");
}

fn verify_batch_results(decrypted_dir: &std::path::Path) {
    let expected_files = vec![
        ("file1.txt", "Content of first file"),
        ("file2.txt", "Content of second file"),
        ("file3.txt", "Content of third file"),
    ];

    for (filename, expected_content) in &expected_files {
        let decrypted_file = decrypted_dir.join(filename);
        assert!(
            decrypted_file.exists(),
            "Decrypted file {} should exist",
            filename
        );

        let content = fs::read_to_string(&decrypted_file).unwrap();
        assert_eq!(
            &content, expected_content,
            "Content mismatch for {}",
            filename
        );
    }
}
