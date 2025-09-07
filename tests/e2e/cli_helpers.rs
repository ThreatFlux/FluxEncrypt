//! Helper functions for CLI end-to-end tests.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Get the CLI path in a secure way
pub fn get_cli_path() -> PathBuf {
    // Use a more secure approach than current_exe
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    let mut path = PathBuf::from(target_dir);
    path.push(profile);
    path.push("fluxencrypt-cli");

    // Add .exe extension on Windows
    if cfg!(target_os = "windows") {
        path.set_extension("exe");
    }

    path
}

/// Run CLI command and return output
pub fn run_cli(args: &[&str]) -> std::process::Output {
    let cli_path = get_cli_path();
    if !cli_path.exists() {
        build_cli();
    }

    Command::new(cli_path)
        .args(args)
        .output()
        .expect("Failed to execute CLI")
}

/// Build the CLI binary
fn build_cli() {
    let _ = Command::new("cargo")
        .args(["build", "-p", "fluxencrypt-cli", "--bin", "fluxencrypt-cli"])
        .output();
}

/// Setup test environment with temporary directory and key files
pub struct TestEnvironment {
    pub temp_dir: TempDir,
    pub public_key_path: PathBuf,
    pub private_key_path: PathBuf,
}

impl Default for TestEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl TestEnvironment {
    pub fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let public_key_path = temp_dir.path().join("public.pem");
        let private_key_path = temp_dir.path().join("private.pem");

        Self {
            temp_dir,
            public_key_path,
            private_key_path,
        }
    }

    /// Generate keys for this test environment
    pub fn generate_keys(&self) -> std::process::Output {
        run_cli(&[
            "keygen",
            "--public-key",
            self.public_key_path.to_str().unwrap(),
            "--private-key",
            self.private_key_path.to_str().unwrap(),
            "--key-size",
            "2048",
        ])
    }
}

/// Assert that a CLI command succeeds
pub fn assert_cli_success(output: &std::process::Output, context: &str) {
    if !output.status.success() {
        eprintln!(
            "{} stderr: {}",
            context,
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!(
            "{} stdout: {}",
            context,
            String::from_utf8_lossy(&output.stdout)
        );
    }
    assert!(output.status.success(), "{} should succeed", context);
}

/// Assert that output contains expected content
pub fn assert_output_contains(output: &std::process::Output, expected: &[&str]) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    for &expected_str in expected {
        assert!(
            stdout.contains(expected_str),
            "Output should contain '{}'. Actual output: {}",
            expected_str,
            stdout
        );
    }
}
