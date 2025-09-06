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

    // Validate input file
    if !Path::new(&cmd.input).exists() {
        return Err(anyhow::anyhow!("Input file '{}' does not exist", cmd.input));
    }

    // Load the public key
    let public_key = load_public_key(&cmd.key)
        .map_err(|e| anyhow::anyhow!("Failed to load public key: {}", e))?;

    // Get file size for progress tracking
    let file_size = fs::metadata(&cmd.input)?.len();

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

    // Create progress bar
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Encrypting...");

    // Create stream cipher with config
    let config = Config::default();
    let cipher = FileStreamCipher::new(config);

    // Create progress callback
    let pb_clone = pb.clone();
    let progress_callback = Box::new(move |current, _total| {
        pb_clone.set_position(current);
    });

    // Perform streaming encryption
    let bytes_processed = cipher.encrypt_file(
        &cmd.input,
        &cmd.output,
        &public_key,
        Some(progress_callback),
    )?;

    // Finish progress bar
    pb.finish_with_message("Encryption completed!");

    // Display results
    let elapsed = start_time.elapsed();
    display_operation_results(
        "Streaming Encryption",
        bytes_processed,
        elapsed,
        cmd.verbose,
    );

    println!(
        "{} Successfully encrypted {} to {}",
        "✓".green().bold(),
        cmd.input.cyan(),
        cmd.output.cyan()
    );

    Ok(())
}

pub fn execute_decrypt(cmd: StreamDecryptCommand) -> CommandResult {
    println!("{} Starting streaming decryption...", "🔓".yellow().bold());

    let start_time = Instant::now();

    // Validate input file
    if !Path::new(&cmd.input).exists() {
        return Err(anyhow::anyhow!("Input file '{}' does not exist", cmd.input));
    }

    // Load the private key
    let private_key = load_private_key(&cmd.key)
        .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;

    // Get file size for progress tracking
    let file_size = fs::metadata(&cmd.input)?.len();

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

    // Create progress bar
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Decrypting...");

    // Create stream cipher with config
    let config = Config::default();
    let cipher = FileStreamCipher::new(config);

    // Create progress callback
    let pb_clone = pb.clone();
    let progress_callback = Box::new(move |current, _total| {
        pb_clone.set_position(current);
    });

    // Perform streaming decryption
    let bytes_processed = cipher.decrypt_file(
        &cmd.input,
        &cmd.output,
        &private_key,
        Some(progress_callback),
    )?;

    // Finish progress bar
    pb.finish_with_message("Decryption completed!");

    // Display results
    let elapsed = start_time.elapsed();
    display_operation_results(
        "Streaming Decryption",
        bytes_processed,
        elapsed,
        cmd.verbose,
    );

    println!(
        "{} Successfully decrypted {} to {}",
        "✓".green().bold(),
        cmd.input.cyan(),
        cmd.output.cyan()
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
