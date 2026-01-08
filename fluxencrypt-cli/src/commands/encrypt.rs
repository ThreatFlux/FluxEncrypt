//! Encrypt command implementation.

use crate::commands::CommandResult;
use base64::prelude::*;
use clap::Args;
use colored::*;
use fluxencrypt::{cryptum, Cryptum};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

/// Input source variants for encryption
enum InputSource {
    File(String),
    DirectData(String),
    EnvFile(String),
    Stdin,
}

/// Encrypt a file or data
#[derive(Args)]
pub struct EncryptCommand {
    /// Input file to encrypt (or use stdin if not provided)
    #[arg(short, long)]
    input: Option<String>,

    /// Output file for encrypted data (required for file input, optional for stdin - defaults to stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Public key file path (or use FLUXENCRYPT_PUBLIC_KEY env var if not specified)
    #[arg(short, long)]
    key: Option<String>,

    /// Data to encrypt directly (alternative to input file or stdin)
    #[arg(short, long)]
    data: Option<String>,

    /// Read data from environment file (.env format)
    #[arg(short, long)]
    env: Option<String>,

    /// Output raw binary instead of base64 encoded (only applies to file output)
    #[arg(long)]
    raw: bool,
}

pub fn execute(cmd: EncryptCommand) -> CommandResult {
    validate_arguments(&cmd)?;

    let public_key = load_public_key(cmd.key.as_deref())?;
    let cryptum = create_cryptum_instance()?;
    let stdin = io::stdin();

    handle_input(
        determine_input_source(&cmd),
        &cryptum,
        cmd.output,
        &public_key,
        cmd.raw,
        stdin,
    )
}

fn handle_input<R: Read>(
    source: InputSource,
    cryptum: &Cryptum,
    output: Option<String>,
    public_key: &fluxencrypt::keys::PublicKey,
    raw: bool,
    stdin: R,
) -> CommandResult {
    match source {
        InputSource::File(input_file) => {
            let output_file = require_output_file(output)?;
            handle_file_encryption(cryptum, &input_file, &output_file, public_key, raw)
        }
        InputSource::DirectData(data) => {
            handle_data_encryption(cryptum, &data, output, public_key, raw)
        }
        InputSource::EnvFile(env_file) => {
            handle_env_file_encryption(cryptum, &env_file, output, public_key, raw)
        }
        InputSource::Stdin => handle_stdin_encryption(cryptum, output, public_key, raw, stdin),
    }
}

fn encrypt_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    public_key: &fluxencrypt::keys::PublicKey,
    raw_output: bool,
) -> CommandResult {
    validate_input_file(input_path)?;
    let file_size = get_file_size(input_path)?;

    if should_use_small_file_encryption(file_size) {
        encrypt_small_file(cryptum, input_path, output_path, public_key, raw_output)
    } else {
        encrypt_large_file(
            cryptum,
            input_path,
            output_path,
            public_key,
            raw_output,
            file_size,
        )
    }
}

/// Validate command arguments to ensure no conflicting options
fn validate_arguments(cmd: &EncryptCommand) -> CommandResult {
    if cmd.input.is_some() && cmd.data.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --input and --data"));
    }

    if cmd.input.is_some() && cmd.env.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --input and --env"));
    }

    if cmd.data.is_some() && cmd.env.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --data and --env"));
    }

    Ok(())
}

/// Load the public key from the specified path or environment
fn load_public_key(key_path: Option<&str>) -> Result<fluxencrypt::keys::PublicKey, anyhow::Error> {
    crate::utils::load_public_key(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to load public key: {}", e))
}

/// Create a cryptum instance
fn create_cryptum_instance() -> Result<Cryptum, anyhow::Error> {
    cryptum().map_err(|e| anyhow::anyhow!("Failed to create cryptum instance: {}", e))
}

/// Determine the input source based on command arguments
fn determine_input_source(cmd: &EncryptCommand) -> InputSource {
    if let Some(input_file) = &cmd.input {
        InputSource::File(input_file.clone())
    } else if let Some(data) = &cmd.data {
        InputSource::DirectData(data.clone())
    } else if let Some(env_file) = &cmd.env {
        InputSource::EnvFile(env_file.clone())
    } else {
        InputSource::Stdin
    }
}

/// Require output file for file encryption
fn require_output_file(output: Option<String>) -> Result<String, anyhow::Error> {
    output.ok_or_else(|| anyhow::anyhow!("Output file is required when encrypting files"))
}

/// Handle file-based encryption
fn handle_file_encryption(
    cryptum: &Cryptum,
    input_file: &str,
    output_file: &str,
    public_key: &fluxencrypt::keys::PublicKey,
    raw: bool,
) -> CommandResult {
    encrypt_file(cryptum, input_file, output_file, public_key, raw)?;

    println!(
        "{} Successfully encrypted {} to {}",
        "✓".green().bold(),
        input_file.cyan(),
        output_file.cyan()
    );

    Ok(())
}

/// Handle direct data encryption
fn handle_data_encryption(
    cryptum: &Cryptum,
    data: &str,
    output: Option<String>,
    public_key: &fluxencrypt::keys::PublicKey,
    raw: bool,
) -> CommandResult {
    let encrypted_data = encrypt_data(cryptum, data.as_bytes(), public_key)?;

    if let Some(output_file) = output {
        write_encrypted_to_file(&encrypted_data, &output_file, raw)?;
        print_file_success_message(&output_file, raw, "data");
    } else {
        print_encoded_to_stdout(&encrypted_data);
    }

    Ok(())
}

/// Handle environment file encryption
fn handle_env_file_encryption(
    cryptum: &Cryptum,
    env_file: &str,
    output: Option<String>,
    public_key: &fluxencrypt::keys::PublicKey,
    raw: bool,
) -> CommandResult {
    let env_data = fs::read_to_string(env_file)
        .map_err(|e| anyhow::anyhow!("Failed to read environment file: {}", e))?;

    let encrypted_data = encrypt_data(cryptum, env_data.as_bytes(), public_key)?;

    if let Some(output_file) = output {
        write_encrypted_to_file(&encrypted_data, &output_file, raw)?;
        println!(
            "{} Successfully encrypted environment file {} to {} {}",
            "✓".green().bold(),
            env_file.cyan(),
            output_file.cyan(),
            format_output_type(raw)
        );
    } else {
        print_encoded_to_stdout(&encrypted_data);
    }

    Ok(())
}

/// Handle stdin encryption
fn handle_stdin_encryption<R: Read>(
    cryptum: &Cryptum,
    output: Option<String>,
    public_key: &fluxencrypt::keys::PublicKey,
    raw: bool,
    mut reader: R,
) -> CommandResult {
    let stdin_data = read_stdin_data(&mut reader)?;
    let encrypted_data = encrypt_data(cryptum, &stdin_data, public_key)?;

    if let Some(output_file) = output {
        write_encrypted_to_file(&encrypted_data, &output_file, raw)?;
        print_file_success_message(&output_file, raw, "stdin data");
    } else {
        print_encoded_to_stdout(&encrypted_data);
    }

    Ok(())
}

/// Read data from stdin
fn read_stdin_data<R: Read>(reader: &mut R) -> Result<Vec<u8>, anyhow::Error> {
    let mut stdin_data = Vec::new();
    reader
        .read_to_end(&mut stdin_data)
        .map_err(|e| anyhow::anyhow!("Failed to read from stdin: {}", e))?;

    if stdin_data.is_empty() {
        return Err(anyhow::anyhow!("No input data provided"));
    }

    Ok(stdin_data)
}

/// Encrypt data using the cryptum instance
fn encrypt_data(
    cryptum: &Cryptum,
    data: &[u8],
    public_key: &fluxencrypt::keys::PublicKey,
) -> Result<Vec<u8>, anyhow::Error> {
    cryptum
        .encrypt(public_key, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))
}

/// Write encrypted data to a file
fn write_encrypted_to_file(encrypted_data: &[u8], output_file: &str, raw: bool) -> CommandResult {
    let output_data = if raw {
        encrypted_data.to_vec()
    } else {
        BASE64_STANDARD.encode(encrypted_data).into_bytes()
    };

    fs::write(output_file, &output_data)
        .map_err(|e| anyhow::anyhow!("Failed to write to output file: {}", e))?;

    Ok(())
}

/// Print success message for file output
fn print_file_success_message(output_file: &str, raw: bool, data_type: &str) {
    println!(
        "{} Successfully encrypted {} to {} {}",
        "✓".green().bold(),
        data_type.cyan(),
        output_file.cyan(),
        format_output_type(raw)
    );
}

/// Print encoded data to stdout
fn print_encoded_to_stdout(encrypted_data: &[u8]) {
    let encoded = BASE64_STANDARD.encode(encrypted_data);
    println!("{}", encoded);
}

/// Format output type description
fn format_output_type(raw: bool) -> &'static str {
    if raw {
        "(raw binary)"
    } else {
        "(base64 encoded)"
    }
}

/// Validate that the input file exists
fn validate_input_file(input_path: &str) -> CommandResult {
    if !Path::new(input_path).exists() {
        return Err(anyhow::anyhow!(
            "Input file '{}' does not exist",
            input_path
        ));
    }
    Ok(())
}

/// Get file size for determining encryption strategy
fn get_file_size(input_path: &str) -> Result<u64, anyhow::Error> {
    fs::metadata(input_path)
        .map(|metadata| metadata.len())
        .map_err(|e| anyhow::anyhow!("Failed to read file metadata: {}", e))
}

/// Determine if small file encryption should be used
fn should_use_small_file_encryption(file_size: u64) -> bool {
    file_size <= 1_000_000
}

/// Encrypt small files using hybrid encryption
fn encrypt_small_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    public_key: &fluxencrypt::keys::PublicKey,
    raw_output: bool,
) -> CommandResult {
    let plaintext =
        fs::read(input_path).map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?;

    let ciphertext = cryptum
        .encrypt(public_key, &plaintext)
        .map_err(|e| anyhow::anyhow!("File encryption failed: {}", e))?;

    write_output_file(&ciphertext, output_path, raw_output)?;

    log::info!(
        "Encrypted {} bytes from {} to {} (hybrid mode)",
        plaintext.len(),
        input_path,
        output_path
    );

    Ok(())
}

/// Encrypt large files with appropriate method based on output format
fn encrypt_large_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    public_key: &fluxencrypt::keys::PublicKey,
    raw_output: bool,
    file_size: u64,
) -> CommandResult {
    if raw_output {
        encrypt_large_file_streaming(cryptum, input_path, output_path, public_key, file_size)
    } else {
        encrypt_large_file_base64(cryptum, input_path, output_path, public_key)
    }
}

/// Encrypt large files for base64 output (read all at once)
fn encrypt_large_file_base64(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    public_key: &fluxencrypt::keys::PublicKey,
) -> CommandResult {
    let plaintext =
        fs::read(input_path).map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?;

    let pb = create_progress_bar(plaintext.len() as u64);

    let ciphertext = cryptum
        .encrypt(public_key, &plaintext)
        .map_err(|e| anyhow::anyhow!("File encryption failed: {}", e))?;

    pb.finish_with_message("Encryption complete");

    let encoded = BASE64_STANDARD.encode(&ciphertext);
    fs::write(output_path, encoded.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;

    log::info!(
        "Encrypted {} bytes from {} to {} (base64 encoded)",
        plaintext.len(),
        input_path,
        output_path
    );

    Ok(())
}

/// Encrypt large files using streaming for raw binary output
fn encrypt_large_file_streaming(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    public_key: &fluxencrypt::keys::PublicKey,
    file_size: u64,
) -> CommandResult {
    let pb = create_progress_bar(file_size);
    let pb_clone = pb.clone();
    let progress_callback = Box::new(move |current, _total| {
        pb_clone.set_position(current);
    });

    let bytes_processed = cryptum
        .encrypt_file_with_progress(input_path, output_path, public_key, progress_callback)
        .map_err(|e| anyhow::anyhow!("File encryption failed: {}", e))?;

    pb.finish_with_message("Encryption complete");

    log::info!(
        "Encrypted {} bytes from {} to {} (streaming mode, raw binary)",
        bytes_processed,
        input_path,
        output_path
    );

    Ok(())
}

/// Create a progress bar with standard styling
fn create_progress_bar(size: u64) -> ProgressBar {
    let pb = ProgressBar::new(size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb
}

/// Write output file in the appropriate format
fn write_output_file(ciphertext: &[u8], output_path: &str, raw_output: bool) -> CommandResult {
    let output_data = if raw_output {
        ciphertext.to_vec()
    } else {
        BASE64_STANDARD.encode(ciphertext).into_bytes()
    };

    fs::write(output_path, &output_data)
        .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    use fluxencrypt::keys::KeyPair;

    fn setup() -> (Cryptum, fluxencrypt::keys::PublicKey) {
        let cryptum = cryptum().expect("cryptum instance");
        let keypair = KeyPair::generate(2048).expect("keypair");
        (cryptum, keypair.public_key().clone())
    }

    #[test]
    fn handle_input_file_branch() {
        let (crypt, pk) = setup();
        let input = NamedTempFile::new().unwrap();
        std::fs::write(input.path(), b"data").unwrap();
        let output = NamedTempFile::new().unwrap();

        handle_input(
            InputSource::File(input.path().to_string_lossy().into()),
            &crypt,
            Some(output.path().to_string_lossy().into()),
            &pk,
            false,
            Cursor::new(vec![]),
        )
        .unwrap();

        assert!(output.path().metadata().unwrap().len() > 0);
    }

    #[test]
    fn handle_input_direct_data_branch() {
        let (crypt, pk) = setup();
        let output = NamedTempFile::new().unwrap();
        handle_input(
            InputSource::DirectData("hello".into()),
            &crypt,
            Some(output.path().to_string_lossy().into()),
            &pk,
            false,
            Cursor::new(vec![]),
        )
        .unwrap();

        assert!(output.path().metadata().unwrap().len() > 0);
    }

    #[test]
    fn handle_input_env_file_branch() {
        let (crypt, pk) = setup();
        let env_file = NamedTempFile::new().unwrap();
        std::fs::write(env_file.path(), "KEY=value").unwrap();
        let output = NamedTempFile::new().unwrap();

        handle_input(
            InputSource::EnvFile(env_file.path().to_string_lossy().into()),
            &crypt,
            Some(output.path().to_string_lossy().into()),
            &pk,
            false,
            Cursor::new(vec![]),
        )
        .unwrap();

        assert!(output.path().metadata().unwrap().len() > 0);
    }

    #[test]
    fn handle_input_stdin_branch() {
        let (crypt, pk) = setup();
        let output = NamedTempFile::new().unwrap();

        handle_input(
            InputSource::Stdin,
            &crypt,
            Some(output.path().to_string_lossy().into()),
            &pk,
            false,
            Cursor::new(b"stdin data".to_vec()),
        )
        .unwrap();

        assert!(output.path().metadata().unwrap().len() > 0);
    }
}
