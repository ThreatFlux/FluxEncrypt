//! Decrypt command implementation.

use crate::commands::CommandResult;
use base64::prelude::*;
use clap::Args;
use colored::*;
use fluxencrypt::{cryptum, Cryptum};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

/// Decrypt a file or data
#[derive(Args)]
pub struct DecryptCommand {
    /// Input file to decrypt (or use stdin if not provided)
    #[arg(short, long)]
    input: Option<String>,

    /// Output file for decrypted data (optional - defaults to stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Private key file path (or use FLUXENCRYPT_PRIVATE_KEY env var if not specified)
    #[arg(short, long)]
    key: Option<String>,

    /// Password for encrypted private keys
    #[arg(long)]
    password: Option<String>,

    /// Data to decrypt directly (base64 encoded, alternative to input file or stdin)
    #[arg(short, long)]
    data: Option<String>,

    /// Input is raw binary instead of base64 encoded (only applies to file input)
    #[arg(long)]
    raw: bool,
}

#[derive(Debug)]
enum InputSource {
    File(String),
    DirectData(String),
    Stdin,
}

fn validate_arguments(cmd: &DecryptCommand) -> CommandResult {
    if cmd.input.is_some() && cmd.data.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --input and --data"));
    }
    Ok(())
}

fn load_private_key(cmd: &DecryptCommand) -> anyhow::Result<fluxencrypt::keys::PrivateKey> {
    crate::utils::load_private_key(cmd.key.as_deref(), cmd.password.as_deref())
        .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))
}

fn create_cryptum_instance() -> anyhow::Result<Cryptum> {
    cryptum().map_err(|e| anyhow::anyhow!("Failed to create cryptum instance: {}", e))
}

fn determine_input_source(cmd: &DecryptCommand) -> InputSource {
    if let Some(ref input_file) = cmd.input {
        InputSource::File(input_file.clone())
    } else if let Some(ref data) = cmd.data {
        InputSource::DirectData(data.clone())
    } else {
        InputSource::Stdin
    }
}

fn handle_file_input(
    cryptum: &Cryptum,
    file_path: &str,
    cmd: &DecryptCommand,
    private_key: &fluxencrypt::keys::PrivateKey,
) -> CommandResult {
    if let Some(ref output_file) = cmd.output {
        decrypt_file(cryptum, file_path, output_file, private_key, cmd.raw)?;
        println!(
            "{} Successfully decrypted {} to {}",
            "✓".green().bold(),
            file_path.cyan(),
            output_file.cyan()
        );
    } else {
        decrypt_file_to_stdout(cryptum, file_path, private_key, cmd.raw)?;
    }
    Ok(())
}

fn handle_direct_data(
    cryptum: &Cryptum,
    data: &str,
    output: &Option<String>,
    private_key: &fluxencrypt::keys::PrivateKey,
) -> CommandResult {
    let encrypted_data = decode_base64_data(data)?;
    let decrypted_data = decrypt_data(cryptum, private_key, &encrypted_data)?;
    write_output(&decrypted_data, output, "data")
}

fn handle_stdin_input(
    cryptum: &Cryptum,
    output: &Option<String>,
    private_key: &fluxencrypt::keys::PrivateKey,
) -> CommandResult {
    let stdin_data = read_from_stdin()?;
    let encrypted_data = decode_base64_data(&stdin_data)?;
    let decrypted_data = decrypt_data(cryptum, private_key, &encrypted_data)?;
    write_output(&decrypted_data, output, "stdin data")
}

fn decode_base64_data(data: &str) -> anyhow::Result<Vec<u8>> {
    base64::prelude::BASE64_STANDARD
        .decode(data.trim())
        .map_err(|e| anyhow::anyhow!("Failed to decode base64 data: {}", e))
}

fn decrypt_data(
    cryptum: &Cryptum,
    private_key: &fluxencrypt::keys::PrivateKey,
    encrypted_data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    cryptum
        .decrypt(private_key, encrypted_data)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

fn read_from_stdin() -> anyhow::Result<String> {
    let mut stdin_data = String::new();
    io::stdin()
        .read_to_string(&mut stdin_data)
        .map_err(|e| anyhow::anyhow!("Failed to read from stdin: {}", e))?;

    if stdin_data.trim().is_empty() {
        return Err(anyhow::anyhow!("No input data provided"));
    }

    Ok(stdin_data)
}

fn write_output(data: &[u8], output: &Option<String>, source_description: &str) -> CommandResult {
    if let Some(output_file) = output {
        fs::write(output_file, data)
            .map_err(|e| anyhow::anyhow!("Failed to write to output file: {}", e))?;
        println!(
            "{} Successfully decrypted {} to {}",
            "✓".green().bold(),
            source_description,
            output_file.cyan()
        );
    } else {
        io::stdout()
            .write_all(data)
            .map_err(|e| anyhow::anyhow!("Failed to write to stdout: {}", e))?;
    }
    Ok(())
}

pub fn execute(cmd: DecryptCommand) -> CommandResult {
    validate_arguments(&cmd)?;

    let private_key = load_private_key(&cmd)?;
    let cryptum = create_cryptum_instance()?;

    match determine_input_source(&cmd) {
        InputSource::File(file_path) => handle_file_input(&cryptum, &file_path, &cmd, &private_key),
        InputSource::DirectData(data) => {
            handle_direct_data(&cryptum, &data, &cmd.output, &private_key)
        }
        InputSource::Stdin => handle_stdin_input(&cryptum, &cmd.output, &private_key),
    }
}

fn decrypt_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
    raw_input: bool,
) -> CommandResult {
    validate_input_file_exists(input_path)?;
    let file_size = get_file_size(input_path)?;

    if is_small_file(file_size) {
        decrypt_small_file(cryptum, input_path, output_path, private_key, raw_input)
    } else if raw_input {
        decrypt_large_raw_file(cryptum, input_path, output_path, private_key, file_size)
    } else {
        decrypt_large_base64_file(cryptum, input_path, output_path, private_key)
    }
}

fn validate_input_file_exists(input_path: &str) -> CommandResult {
    if !Path::new(input_path).exists() {
        return Err(anyhow::anyhow!(
            "Input file '{}' does not exist",
            input_path
        ));
    }
    Ok(())
}

fn get_file_size(input_path: &str) -> anyhow::Result<u64> {
    fs::metadata(input_path)
        .map(|metadata| metadata.len())
        .map_err(|e| anyhow::anyhow!("Failed to get file metadata: {}", e))
}

fn is_small_file(file_size: u64) -> bool {
    file_size <= 1_000_000 // 1MB
}

fn decrypt_small_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
    raw_input: bool,
) -> CommandResult {
    let file_data = read_file_data(input_path)?;
    let ciphertext = prepare_ciphertext(&file_data, raw_input)?;
    let plaintext = decrypt_data(cryptum, private_key, &ciphertext)?;

    write_file_data(output_path, &plaintext)?;

    log::info!(
        "Decrypted {} bytes from {} to {} (hybrid mode)",
        plaintext.len(),
        input_path,
        output_path
    );

    Ok(())
}

fn decrypt_large_base64_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
) -> CommandResult {
    let file_data = read_file_as_string(input_path)?;
    let ciphertext = decode_base64_data(&file_data)?;

    let pb = create_progress_bar(ciphertext.len() as u64);
    let plaintext = decrypt_data(cryptum, private_key, &ciphertext)?;
    pb.finish_with_message("Decryption complete");

    write_file_data(output_path, &plaintext)?;

    log::info!(
        "Decrypted {} bytes from {} to {} (base64 decoded)",
        plaintext.len(),
        input_path,
        output_path
    );

    Ok(())
}

fn decrypt_large_raw_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
    file_size: u64,
) -> CommandResult {
    let pb = create_progress_bar(file_size);
    let progress_callback = create_progress_callback(pb.clone());

    let bytes_processed = cryptum
        .decrypt_file_with_progress(input_path, output_path, private_key, progress_callback)
        .map_err(|e| anyhow::anyhow!("File decryption failed: {}", e))?;

    pb.finish_with_message("Decryption complete");

    log::info!(
        "Decrypted {} bytes from {} to {} (streaming mode, raw binary)",
        bytes_processed,
        input_path,
        output_path
    );

    Ok(())
}

fn read_file_data(input_path: &str) -> anyhow::Result<Vec<u8>> {
    fs::read(input_path).map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))
}

fn read_file_as_string(input_path: &str) -> anyhow::Result<String> {
    fs::read_to_string(input_path).map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))
}

fn prepare_ciphertext(file_data: &[u8], raw_input: bool) -> anyhow::Result<Vec<u8>> {
    if raw_input {
        Ok(file_data.to_vec())
    } else {
        let file_str = String::from_utf8(file_data.to_vec()).map_err(|e| {
            anyhow::anyhow!("Input file is not valid UTF-8 for base64 decoding: {}", e)
        })?;
        BASE64_STANDARD
            .decode(file_str.trim())
            .map_err(|e| anyhow::anyhow!("Failed to decode base64 from input file: {}", e))
    }
}

fn write_file_data(output_path: &str, data: &[u8]) -> anyhow::Result<()> {
    fs::write(output_path, data).map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))
}

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

fn create_progress_callback(pb: ProgressBar) -> Box<dyn Fn(u64, u64) + Send + Sync> {
    Box::new(move |current, _total| {
        pb.set_position(current);
    })
}

fn decrypt_file_to_stdout(
    cryptum: &Cryptum,
    input_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
    raw_input: bool,
) -> CommandResult {
    validate_input_file_exists(input_path)?;

    let file_data = read_file_data(input_path)?;
    let encrypted_data = prepare_ciphertext(&file_data, raw_input)?;
    let decrypted_data = decrypt_data(cryptum, private_key, &encrypted_data)?;

    io::stdout()
        .write_all(&decrypted_data)
        .map_err(|e| anyhow::anyhow!("Failed to write to stdout: {}", e))?;

    Ok(())
}
