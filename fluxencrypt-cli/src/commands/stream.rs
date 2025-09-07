//! Stream command implementations.

use crate::commands::CommandResult;
use clap::Args;
use colored::*;
use fluxencrypt::{config::Config, keys::parsing::KeyParser, stream::FileStreamCipher};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Args)]
pub struct StreamEncryptCommand {
    /// Input file to encrypt
    #[arg(short, long)]
    input: String,

    /// Output file for encrypted data
    #[arg(short, long)]
    output: String,

    /// Public key file path
    #[arg(short, long)]
    key: String,

    /// Chunk size in bytes (default: 1MB)
    #[arg(long, default_value = "1048576")]
    chunk_size: usize,

    /// Show detailed progress information
    #[arg(long)]
    verbose: bool,
}

#[derive(Args)]
pub struct StreamDecryptCommand {
    /// Input file to decrypt
    #[arg(short, long)]
    input: String,

    /// Output file for decrypted data
    #[arg(short, long)]
    output: String,

    /// Private key file path
    #[arg(short, long)]
    key: String,

    /// Chunk size in bytes (default: 1MB)
    #[arg(long, default_value = "1048576")]
    chunk_size: usize,

    /// Show detailed progress information
    #[arg(long)]
    verbose: bool,
}

pub fn execute_encrypt(cmd: StreamEncryptCommand) -> CommandResult {
    println!("{} Starting streaming encryption...", "🔒".green().bold());
    let start_time = Instant::now();

    validate_stream_input(&cmd.input)?;
    let public_key = load_stream_public_key(&cmd.key)?;
    let file_size = get_stream_file_size(&cmd.input)?;

    print_verbose_info_if_enabled(&cmd, file_size);

    let pb = create_stream_progress_bar(file_size, "Encrypting...");
    let cipher = create_file_stream_cipher();
    let progress_callback = create_stream_progress_callback(pb.clone());

    let bytes_processed = perform_stream_encryption(
        &cipher,
        &cmd.input,
        &cmd.output,
        &public_key,
        progress_callback,
    )?;

    finalize_stream_operation(
        pb,
        start_time,
        "Streaming Encryption",
        bytes_processed,
        cmd.verbose,
        &cmd.input,
        &cmd.output,
    );

    Ok(())
}

pub fn execute_decrypt(cmd: StreamDecryptCommand) -> CommandResult {
    println!("{} Starting streaming decryption...", "🔓".yellow().bold());
    let start_time = Instant::now();

    validate_stream_input(&cmd.input)?;
    let private_key = load_stream_private_key(&cmd.key)?;
    let file_size = get_stream_file_size(&cmd.input)?;

    print_verbose_decrypt_info_if_enabled(&cmd, file_size);

    let pb = create_decrypt_progress_bar(file_size);
    let cipher = create_file_stream_cipher();
    let progress_callback = create_stream_progress_callback(pb.clone());

    let bytes_processed = perform_stream_decryption(
        &cipher,
        &cmd.input,
        &cmd.output,
        &private_key,
        progress_callback,
    )?;

    finalize_stream_operation(
        pb,
        start_time,
        "Streaming Decryption",
        bytes_processed,
        cmd.verbose,
        &cmd.input,
        &cmd.output,
    );

    Ok(())
}

fn load_public_key(key_path: &str) -> anyhow::Result<fluxencrypt::keys::PublicKey> {
    let key_data = fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read key file '{}': {}", key_path, e))?;

    let parser = KeyParser::new();

    // Try to detect the format
    let format = parser
        .detect_format(&key_data)
        .ok_or_else(|| anyhow::anyhow!("Could not detect key format"))?;

    parser
        .parse_public_key(&key_data, format)
        .map_err(|e| anyhow::anyhow!("Failed to parse public key: {}", e))
}

fn load_private_key(key_path: &str) -> anyhow::Result<fluxencrypt::keys::PrivateKey> {
    let key_data = fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read key file '{}': {}", key_path, e))?;

    let parser = KeyParser::new();

    // Try to detect the format
    let format = parser
        .detect_format(&key_data)
        .ok_or_else(|| anyhow::anyhow!("Could not detect key format"))?;

    parser
        .parse_private_key(&key_data, format)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))
}

fn display_operation_results(
    operation: &str,
    bytes_processed: u64,
    elapsed: std::time::Duration,
    verbose: bool,
) {
    println!("\n{} {} Results:", "📊".blue().bold(), operation);
    println!(
        "  {} Bytes processed: {}",
        "📦".blue(),
        format_bytes(bytes_processed).cyan()
    );
    println!(
        "  {} Duration: {:.2}s",
        "⏱".yellow(),
        elapsed.as_secs_f64().to_string().cyan()
    );

    if bytes_processed > 0 && elapsed.as_secs_f64() > 0.0 {
        let throughput = bytes_processed as f64 / elapsed.as_secs_f64();
        println!(
            "  {} Throughput: {}/s",
            "🚀".magenta(),
            format_bytes(throughput as u64).cyan()
        );
    }

    if verbose {
        let mb_per_sec = if elapsed.as_secs_f64() > 0.0 {
            (bytes_processed as f64 / 1_048_576.0) / elapsed.as_secs_f64()
        } else {
            0.0
        };

        println!(
            "  {} Processing rate: {:.1} MB/s",
            "⚡".green(),
            mb_per_sec.to_string().cyan()
        );

        if bytes_processed >= 1_048_576 {
            let chunks_processed = bytes_processed.div_ceil(1_048_576); // Round up
            println!(
                "  {} Chunks processed: ~{}",
                "🔢".purple(),
                chunks_processed.to_string().cyan()
            );
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Validate that the stream input file exists
fn validate_stream_input(input_path: &str) -> CommandResult {
    if !Path::new(input_path).exists() {
        return Err(anyhow::anyhow!(
            "Input file '{}' does not exist",
            input_path
        ));
    }
    Ok(())
}

/// Load public key for stream encryption
fn load_stream_public_key(key_path: &str) -> Result<fluxencrypt::keys::PublicKey, anyhow::Error> {
    load_public_key(key_path).map_err(|e| anyhow::anyhow!("Failed to load public key: {}", e))
}

/// Load private key for stream decryption
fn load_stream_private_key(key_path: &str) -> Result<fluxencrypt::keys::PrivateKey, anyhow::Error> {
    load_private_key(key_path).map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))
}

/// Get file size for stream processing
fn get_stream_file_size(input_path: &str) -> Result<u64, anyhow::Error> {
    fs::metadata(input_path)
        .map(|metadata| metadata.len())
        .map_err(|e| anyhow::anyhow!("Failed to read file metadata: {}", e))
}

/// Print verbose information if enabled for encryption
fn print_verbose_info_if_enabled(cmd: &StreamEncryptCommand, file_size: u64) {
    if cmd.verbose {
        println!(
            "{} File size: {}",
            "📊".blue(),
            format_bytes(file_size).cyan()
        );
        println!(
            "{} Chunk size: {}",
            "⚙️".yellow(),
            format_bytes(cmd.chunk_size as u64).cyan()
        );
    }
}

/// Print verbose information if enabled for decryption
fn print_verbose_decrypt_info_if_enabled(cmd: &StreamDecryptCommand, file_size: u64) {
    if cmd.verbose {
        println!(
            "{} File size: {}",
            "📊".blue(),
            format_bytes(file_size).cyan()
        );
        println!(
            "{} Chunk size: {}",
            "⚙️".yellow(),
            format_bytes(cmd.chunk_size as u64).cyan()
        );
    }
}

/// Create progress bar for stream encryption
fn create_stream_progress_bar(file_size: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create progress bar for stream decryption
fn create_decrypt_progress_bar(file_size: u64) -> ProgressBar {
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Decrypting...");
    pb
}

/// Create file stream cipher with default config
fn create_file_stream_cipher() -> FileStreamCipher {
    let config = Config::default();
    FileStreamCipher::new(config)
}

/// Create progress callback for streaming operations
fn create_stream_progress_callback(pb: ProgressBar) -> Box<dyn Fn(u64, u64) + Send + Sync> {
    Box::new(move |current, _total| {
        pb.set_position(current);
    })
}

/// Perform stream encryption operation
fn perform_stream_encryption(
    cipher: &FileStreamCipher,
    input_path: &str,
    output_path: &str,
    public_key: &fluxencrypt::keys::PublicKey,
    progress_callback: Box<dyn Fn(u64, u64) + Send + Sync>,
) -> Result<u64, anyhow::Error> {
    cipher
        .encrypt_file(input_path, output_path, public_key, Some(progress_callback))
        .map_err(|e| anyhow::anyhow!("Stream encryption failed: {}", e))
}

/// Perform stream decryption operation
fn perform_stream_decryption(
    cipher: &FileStreamCipher,
    input_path: &str,
    output_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
    progress_callback: Box<dyn Fn(u64, u64) + Send + Sync>,
) -> Result<u64, anyhow::Error> {
    cipher
        .decrypt_file(
            input_path,
            output_path,
            private_key,
            Some(progress_callback),
        )
        .map_err(|e| anyhow::anyhow!("Stream decryption failed: {}", e))
}

/// Finalize stream operation with results display
fn finalize_stream_operation(
    pb: ProgressBar,
    start_time: Instant,
    operation_name: &str,
    bytes_processed: u64,
    verbose: bool,
    input_path: &str,
    output_path: &str,
) {
    pb.finish_with_message(format!("{} completed!", operation_name));

    let elapsed = start_time.elapsed();
    display_operation_results(operation_name, bytes_processed, elapsed, verbose);

    println!(
        "{} Successfully {} {} to {}",
        "✓".green().bold(),
        if operation_name.contains("Encryption") {
            "encrypted"
        } else {
            "decrypted"
        },
        input_path.cyan(),
        output_path.cyan()
    );
}
