//! Utility functions for CLI operations.

use crate::commands::CommandResult;
use dialoguer::Confirm;
use fluxencrypt::keys::parsing::KeyParser;
use fluxencrypt::keys::{PrivateKey, PublicKey};
use std::env;
use std::fs;
use std::path::Path;

/// Confirm overwriting an existing file
pub fn confirm_overwrite(path: &Path) -> anyhow::Result<bool> {
    let result = Confirm::new()
        .with_prompt(format!(
            "File '{}' already exists. Overwrite?",
            path.display()
        ))
        .default(false)
        .interact()?;
    Ok(result)
}

/// Create output directory if it doesn't exist
pub fn create_output_directory(path: &Path) -> CommandResult {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Load a public key from file path or environment variable
///
/// # Arguments
/// * `key_path` - Optional path to the public key file. If None, tries FLUXENCRYPT_PUBLIC_KEY env var
///
/// # Returns
/// The loaded public key
pub fn load_public_key(key_path: Option<&str>) -> anyhow::Result<PublicKey> {
    let key_data = if let Some(path) = key_path {
        // Load from file
        fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read public key file '{}': {}", path, e))?
    } else {
        // Try loading from environment variable
        let env_key = env::var("FLUXENCRYPT_PUBLIC_KEY")
            .map_err(|_| anyhow::anyhow!("No public key file specified and FLUXENCRYPT_PUBLIC_KEY environment variable not set"))?;

        // Check if it's a file path or actual key data
        if env_key.starts_with("-----BEGIN") || env_key.contains("\n") {
            // Direct key data
            env_key.into_bytes()
        } else {
            // File path
            fs::read(&env_key).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read public key file from env var '{}': {}",
                    env_key,
                    e
                )
            })?
        }
    };

    let parser = KeyParser::new();

    // Check if the data is base64 encoded
    let decoded_data = if !key_data.starts_with(b"-----BEGIN") {
        // Try to decode as base64
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        match STANDARD.decode(&key_data) {
            Ok(decoded) => decoded,
            Err(_) => key_data, // Not base64, use as-is
        }
    } else {
        key_data
    };

    // Try to detect the format
    let format = parser
        .detect_format(&decoded_data)
        .ok_or_else(|| anyhow::anyhow!("Could not detect public key format"))?;

    parser
        .parse_public_key(&decoded_data, format)
        .map_err(|e| anyhow::anyhow!("Failed to parse public key: {}", e))
}

/// Load a private key from file path or environment variable
///
/// # Arguments
/// * `key_path` - Optional path to the private key file. If None, tries FLUXENCRYPT_PRIVATE_KEY env var
/// * `password` - Optional password for encrypted keys
///
/// # Returns
/// The loaded private key
pub fn load_private_key(
    key_path: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<PrivateKey> {
    let key_data = if let Some(path) = key_path {
        // Load from file
        fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read private key file '{}': {}", path, e))?
    } else {
        // Try loading from environment variable
        let env_key = env::var("FLUXENCRYPT_PRIVATE_KEY")
            .map_err(|_| anyhow::anyhow!("No private key file specified and FLUXENCRYPT_PRIVATE_KEY environment variable not set"))?;

        // Check if it's a file path or actual key data
        if env_key.starts_with("-----BEGIN") || env_key.contains("\n") {
            // Direct key data
            env_key.into_bytes()
        } else {
            // File path
            fs::read(&env_key).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read private key file from env var '{}': {}",
                    env_key,
                    e
                )
            })?
        }
    };

    // Check if the data is base64 encoded
    let decoded_data = if !key_data.starts_with(b"-----BEGIN") {
        // Try to decode as base64
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        match STANDARD.decode(&key_data) {
            Ok(decoded) => decoded,
            Err(_) => key_data, // Not base64, use as-is
        }
    } else {
        key_data
    };

    let key_str = String::from_utf8(decoded_data)
        .map_err(|e| anyhow::anyhow!("Private key data is not valid UTF-8: {}", e))?;

    // Check if the key is encrypted
    if key_str.contains("ENCRYPTED") && password.is_none() {
        return Err(anyhow::anyhow!(
            "Private key is encrypted but no password provided"
        ));
    }

    if let Some(pwd) = password {
        // Try to parse as encrypted key
        fluxencrypt::keys::parsing::parse_encrypted_private_key_from_str(&key_str, pwd)
            .map_err(|e| anyhow::anyhow!("Failed to parse encrypted private key: {}", e))
    } else {
        // Parse as regular key
        fluxencrypt::keys::parsing::parse_private_key_from_str(&key_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))
    }
}
