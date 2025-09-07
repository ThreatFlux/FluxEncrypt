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
    let key_data = load_key_data(key_path, "FLUXENCRYPT_PUBLIC_KEY", "public key")?;
    let decoded_data = decode_key_data_if_needed(&key_data)?;
    parse_public_key(&decoded_data)
}

fn load_key_data(key_path: Option<&str>, env_var: &str, key_type: &str) -> anyhow::Result<Vec<u8>> {
    match key_path {
        Some(path) => read_key_from_file(path),
        None => load_key_from_env(env_var, key_type),
    }
}

fn read_key_from_file(path: &str) -> anyhow::Result<Vec<u8>> {
    fs::read(path).map_err(|e| anyhow::anyhow!("Failed to read key file '{}': {}", path, e))
}

fn load_key_from_env(env_var: &str, key_type: &str) -> anyhow::Result<Vec<u8>> {
    let env_key = env::var(env_var).map_err(|_| {
        anyhow::anyhow!(
            "No {} file specified and {} environment variable not set",
            key_type,
            env_var
        )
    })?;

    if is_direct_key_data(&env_key) {
        Ok(env_key.into_bytes())
    } else {
        read_key_from_env_file(&env_key)
    }
}

fn is_direct_key_data(data: &str) -> bool {
    data.starts_with("-----BEGIN") || data.contains('\n')
}

fn read_key_from_env_file(env_key: &str) -> anyhow::Result<Vec<u8>> {
    fs::read(env_key)
        .map_err(|e| anyhow::anyhow!("Failed to read key file from env var '{}': {}", env_key, e))
}

fn decode_key_data_if_needed(key_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if key_data.starts_with(b"-----BEGIN") {
        return Ok(key_data.to_vec());
    }

    // Try to decode as base64
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    match STANDARD.decode(key_data) {
        Ok(decoded) => Ok(decoded),
        Err(_) => Ok(key_data.to_vec()), // Not base64, use as-is
    }
}

fn parse_public_key(decoded_data: &[u8]) -> anyhow::Result<PublicKey> {
    let parser = KeyParser::new();

    let format = parser
        .detect_format(decoded_data)
        .ok_or_else(|| anyhow::anyhow!("Could not detect public key format"))?;

    parser
        .parse_public_key(decoded_data, format)
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
    let key_data = load_key_data(key_path, "FLUXENCRYPT_PRIVATE_KEY", "private key")?;
    let decoded_data = decode_key_data_if_needed(&key_data)?;
    let key_str = convert_key_data_to_string(&decoded_data)?;

    validate_encryption_password(&key_str, password)?;
    parse_private_key(&key_str, password)
}

fn convert_key_data_to_string(decoded_data: &[u8]) -> anyhow::Result<String> {
    String::from_utf8(decoded_data.to_vec())
        .map_err(|e| anyhow::anyhow!("Private key data is not valid UTF-8: {}", e))
}

fn validate_encryption_password(key_str: &str, password: Option<&str>) -> anyhow::Result<()> {
    if is_encrypted_key(key_str) && password.is_none() {
        return Err(anyhow::anyhow!(
            "Private key is encrypted but no password provided"
        ));
    }
    Ok(())
}

fn is_encrypted_key(key_str: &str) -> bool {
    key_str.contains("ENCRYPTED")
}

fn parse_private_key(key_str: &str, password: Option<&str>) -> anyhow::Result<PrivateKey> {
    match password {
        Some(pwd) => parse_encrypted_private_key(key_str, pwd),
        None => parse_unencrypted_private_key(key_str),
    }
}

fn parse_encrypted_private_key(key_str: &str, password: &str) -> anyhow::Result<PrivateKey> {
    fluxencrypt::keys::parsing::parse_encrypted_private_key_from_str(key_str, password)
        .map_err(|e| anyhow::anyhow!("Failed to parse encrypted private key: {}", e))
}

fn parse_unencrypted_private_key(key_str: &str) -> anyhow::Result<PrivateKey> {
    fluxencrypt::keys::parsing::parse_private_key_from_str(key_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))
}
