//! Batch command implementations.

use crate::commands::CommandResult;
use clap::Args;
use colored::*;
use fluxencrypt::{
    config::Config,
    keys::parsing::KeyParser,
    stream::batch::{BatchConfig, BatchProcessor},
};
use glob::glob;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Args)]
pub struct BatchEncryptCommand {
    /// Input directory or glob pattern for files to encrypt
    #[arg(short, long)]
    input_dir: String,

    /// Output directory for encrypted files
    #[arg(short, long)]
    output_dir: String,

    /// Public key file path
    #[arg(short, long)]
    key: String,

    /// File pattern to match (e.g., "*.txt", "*.json")
    #[arg(short, long)]
    pattern: Option<String>,

    /// Process directories recursively
    #[arg(short, long)]
    recursive: bool,

    /// Continue processing on error
    #[arg(long)]
    continue_on_error: bool,

    /// Maximum number of parallel operations
    #[arg(long)]
    max_parallel: Option<usize>,

    /// Output file pattern (use {name} for original filename)
    #[arg(long)]
    output_pattern: Option<String>,

    /// Don't preserve directory structure in output
    #[arg(long)]
    flatten: bool,
}

#[derive(Args)]
pub struct BatchDecryptCommand {
    /// Input directory or glob pattern for files to decrypt
    #[arg(short, long)]
    input_dir: String,

    /// Output directory for decrypted files
    #[arg(short, long)]
    output_dir: String,

    /// Private key file path
    #[arg(short, long)]
    key: String,

    /// File pattern to match (e.g., "*.enc")
    #[arg(short, long)]
    pattern: Option<String>,

    /// Process directories recursively
    #[arg(short, long)]
    recursive: bool,

    /// Continue processing on error
    #[arg(long)]
    continue_on_error: bool,

    /// Maximum number of parallel operations
    #[arg(long)]
    max_parallel: Option<usize>,

    /// Output file pattern (use {name} for original filename)
    #[arg(long)]
    output_pattern: Option<String>,

    /// Don't preserve directory structure in output
    #[arg(long)]
    flatten: bool,
}

pub fn execute_encrypt(cmd: BatchEncryptCommand) -> CommandResult {
    println!("{} Starting batch encryption...", "⚡".yellow().bold());

    let start_time = Instant::now();

    // Load the public key
    let public_key = load_public_key(&cmd.key)
        .map_err(|e| anyhow::anyhow!("Failed to load public key: {}", e))?;

    // Find input files
    let input_files = find_input_files(&cmd.input_dir, cmd.pattern.as_deref(), cmd.recursive)?;

    if input_files.is_empty() {
        println!("{} No files found matching criteria", "⚠".yellow());
        return Ok(());
    }

    println!(
        "{} Found {} files to encrypt",
        "📁".blue(),
        input_files.len().to_string().cyan()
    );

    // Create batch processor
    let config = Config::default();
    let processor = if cfg!(feature = "parallel") {
        BatchProcessor::new(config)
    } else {
        BatchProcessor::sequential(config)
    };

    // Configure batch settings
    let batch_config = BatchConfig {
        continue_on_error: cmd.continue_on_error,
        max_parallel: cmd.max_parallel,
        output_pattern: cmd.output_pattern,
        preserve_structure: !cmd.flatten,
    };

    // Create progress bar
    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new(input_files.len() as u64));
    main_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    main_pb.set_message("Encrypting files");

    // Create progress callback
    let pb_clone = main_pb.clone();
    let progress_callback: Box<dyn Fn(u64, u64) + Send + Sync> =
        Box::new(move |current: u64, _total: u64| {
            pb_clone.set_position(current);
        });

    // Process files
    let result = processor.encrypt_files(
        &input_files,
        cmd.output_dir.as_str().into(),
        &public_key,
        &batch_config,
        Some(progress_callback),
    )?;

    // Finish progress bar
    main_pb.finish_with_message("Encryption completed");

    // Display results
    let elapsed = start_time.elapsed();
    display_batch_results("Encryption", &result, elapsed);

    Ok(())
}

pub fn execute_decrypt(cmd: BatchDecryptCommand) -> CommandResult {
    println!("{} Starting batch decryption...", "⚡".yellow().bold());

    let start_time = Instant::now();

    // Load the private key
    let private_key = load_private_key(&cmd.key)
        .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;

    // Find input files
    let input_files = find_input_files(&cmd.input_dir, cmd.pattern.as_deref(), cmd.recursive)?;

    if input_files.is_empty() {
        println!("{} No files found matching criteria", "⚠".yellow());
        return Ok(());
    }

    println!(
        "{} Found {} files to decrypt",
        "📁".blue(),
        input_files.len().to_string().cyan()
    );

    // Create batch processor
    let config = Config::default();
    let processor = if cfg!(feature = "parallel") {
        BatchProcessor::new(config)
    } else {
        BatchProcessor::sequential(config)
    };

    // Configure batch settings
    let batch_config = BatchConfig {
        continue_on_error: cmd.continue_on_error,
        max_parallel: cmd.max_parallel,
        output_pattern: cmd.output_pattern,
        preserve_structure: !cmd.flatten,
    };

    // Create progress bar
    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new(input_files.len() as u64));
    main_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    main_pb.set_message("Decrypting files");

    // Create progress callback
    let pb_clone = main_pb.clone();
    let progress_callback: Box<dyn Fn(u64, u64) + Send + Sync> =
        Box::new(move |current: u64, _total: u64| {
            pb_clone.set_position(current);
        });

    // Process files
    let result = processor.decrypt_files(
        &input_files,
        cmd.output_dir.as_str().into(),
        &private_key,
        &batch_config,
        Some(progress_callback),
    )?;

    // Finish progress bar
    main_pb.finish_with_message("Decryption completed");

    // Display results
    let elapsed = start_time.elapsed();
    display_batch_results("Decryption", &result, elapsed);

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

fn find_input_files(
    input_path: &str,
    pattern: Option<&str>,
    recursive: bool,
) -> anyhow::Result<Vec<PathBuf>> {
    let path = Path::new(input_path);

    if path.is_file() {
        // Single file
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        // Directory - use walkdir or std::fs
        let config = Config::default();
        let processor = BatchProcessor::new(config);
        return processor
            .find_files(path, pattern, recursive)
            .map_err(|e| anyhow::anyhow!("Failed to find files: {}", e));
    }

    // Treat as glob pattern
    let mut files = Vec::new();
    for entry in glob(input_path)? {
        match entry {
            Ok(path) if path.is_file() => {
                if let Some(pattern) = pattern {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.contains(pattern) {
                            files.push(path);
                        }
                    }
                } else {
                    files.push(path);
                }
            }
            Ok(_) => {} // Skip directories in glob results
            Err(e) => {
                eprintln!(
                    "{} Warning: Failed to process glob entry: {}",
                    "⚠".yellow(),
                    e
                );
            }
        }
    }

    Ok(files)
}

fn display_batch_results(
    operation: &str,
    result: &fluxencrypt::stream::batch::BatchResult,
    elapsed: std::time::Duration,
) {
    println!("\n{} {} Results:", "📊".blue().bold(), operation);
    println!(
        "  {} Files processed: {}",
        "✓".green(),
        result.processed_count.to_string().cyan()
    );
    println!(
        "  {} Total bytes: {}",
        "📦".blue(),
        format_bytes(result.total_bytes).cyan()
    );
    println!(
        "  {} Duration: {:.2}s",
        "⏱".yellow(),
        elapsed.as_secs_f64().to_string().cyan()
    );

    if result.total_bytes > 0 && elapsed.as_secs_f64() > 0.0 {
        let throughput = result.total_bytes as f64 / elapsed.as_secs_f64();
        println!(
            "  {} Throughput: {}/s",
            "🚀".magenta(),
            format_bytes(throughput as u64).cyan()
        );
    }

    if !result.failed_files.is_empty() {
        println!(
            "\n{} Failed files ({}):",
            "❌".red().bold(),
            result.failed_files.len()
        );
        for (path, error) in &result.failed_files {
            println!(
                "  {} {}: {}",
                "•".red(),
                path.display().to_string().yellow(),
                error.red()
            );
        }
    }

    if result.processed_count > 0 {
        println!(
            "\n{} {} completed successfully!",
            "🎉".green().bold(),
            operation
        );
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
