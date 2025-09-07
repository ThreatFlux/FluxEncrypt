//! Tests for basic CLI commands (help, version, keygen).

use crate::cli_helpers::*;
use std::fs;

#[test]
#[ignore = "Requires built CLI binary"]
fn test_cli_help() {
    let output = run_cli(&["--help"]);
    assert_cli_success(&output, "CLI help");

    assert_output_contains(
        &output,
        &[
            "FluxEncrypt",
            "encrypt",
            "decrypt",
            "keygen",
            "--help",
            "--version",
        ],
    );
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_cli_version() {
    let output = run_cli(&["--version"]);
    assert_cli_success(&output, "CLI version");

    assert_output_contains(&output, &["fluxencrypt", "0.1.0"]);
}

#[test]
#[ignore = "Requires built CLI binary"]
fn test_keygen_command() {
    let env = TestEnvironment::new();

    let output = env.generate_keys();
    assert_cli_success(&output, "Key generation");

    // Verify files were created
    assert!(
        env.public_key_path.exists(),
        "Public key file should be created"
    );
    assert!(
        env.private_key_path.exists(),
        "Private key file should be created"
    );

    // Verify file contents
    let public_key_content = fs::read_to_string(&env.public_key_path).unwrap();
    let private_key_content = fs::read_to_string(&env.private_key_path).unwrap();

    assert!(public_key_content.contains("-----BEGIN RSA PUBLIC KEY-----"));
    assert!(public_key_content.contains("-----END RSA PUBLIC KEY-----"));
    assert!(private_key_content.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(private_key_content.contains("-----END RSA PRIVATE KEY-----"));
}
