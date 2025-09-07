//! Batch command implementations.

use crate::commands::CommandResult;

// Type alias for complex progress callback type
type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;
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

    // Load key and find files
    let public_key = load_public_key(&cmd.key)
        .map_err(|e| anyhow::anyhow!("Failed to load public key: {}", e))?;
    let input_files = prepare_input_files(&cmd.input_dir, cmd.pattern.as_deref(), cmd.recursive)?;

    // Create processor and configuration
    let (processor, batch_config) = create_batch_processor_and_config(&cmd);

    // Setup progress tracking
    let (main_pb, progress_callback) =
        setup_progress_bar(&input_files, "Encrypting files".to_string())?;

    // Process files
    let result = processor.encrypt_files(
        &input_files,
        cmd.output_dir.as_str().into(),
        &public_key,
        &batch_config,
        Some(progress_callback),
    )?;

    main_pb.finish_with_message("Encryption completed");
    display_batch_results("Encryption", &result, start_time.elapsed());
    Ok(())
}

pub fn execute_decrypt(cmd: BatchDecryptCommand) -> CommandResult {
    println!("{} Starting batch decryption...", "⚡".yellow().bold());
    let start_time = Instant::now();

    // Load key and find files
    let private_key = load_private_key(&cmd.key)
        .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;
    let input_files =
        prepare_decrypt_input_files(&cmd.input_dir, cmd.pattern.as_deref(), cmd.recursive)?;

    // Create processor and configuration
    let (processor, batch_config) = create_decrypt_batch_processor_and_config(&cmd);

    // Setup progress tracking
    let (main_pb, progress_callback) =
        setup_progress_bar(&input_files, "Decrypting files".to_string())?;

    // Process files
    let result = processor.decrypt_files(
        &input_files,
        cmd.output_dir.as_str().into(),
        &private_key,
        &batch_config,
        Some(progress_callback),
    )?;

    main_pb.finish_with_message("Decryption completed");
    display_batch_results("Decryption", &result, start_time.elapsed());
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
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        return find_files_in_directory(path, pattern, recursive);
    }

    // Treat as glob pattern
    find_files_with_glob(input_path, pattern)
}

/// Find files in a directory using batch processor
fn find_files_in_directory(
    path: &Path,
    pattern: Option<&str>,
    recursive: bool,
) -> anyhow::Result<Vec<PathBuf>> {
    let config = Config::default();
    let processor = BatchProcessor::new(config);
    processor
        .find_files(path, pattern, recursive)
        .map_err(|e| anyhow::anyhow!("Failed to find files: {}", e))
}

/// Find files using glob pattern
fn find_files_with_glob(input_path: &str, pattern: Option<&str>) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in glob(input_path)? {
        if let Ok(path) = entry {
            if path.is_file() && matches_pattern(&path, pattern) {
                files.push(path);
            }
        } else if let Err(e) = entry {
            eprintln!(
                "{} Warning: Failed to process glob entry: {}",
                "⚠".yellow(),
                e
            );
        }
    }
    Ok(files)
}

/// Check if file matches the given pattern
fn matches_pattern(path: &Path, pattern: Option<&str>) -> bool {
    match pattern {
        Some(pattern) => path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.contains(pattern)),
        None => true,
    }
}

fn display_batch_results(
    operation: &str,
    result: &fluxencrypt::stream::batch::BatchResult,
    elapsed: std::time::Duration,
) {
    display_summary_stats(operation, result, elapsed);
    display_throughput_if_applicable(result, elapsed);
    display_failed_files_if_any(&result.failed_files);
    display_completion_message_if_successful(operation, result.processed_count);
}

/// Display summary statistics for batch operation
fn display_summary_stats(
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
}

/// Display throughput information if data was processed
fn display_throughput_if_applicable(
    result: &fluxencrypt::stream::batch::BatchResult,
    elapsed: std::time::Duration,
) {
    if result.total_bytes > 0 && elapsed.as_secs_f64() > 0.0 {
        let throughput = result.total_bytes as f64 / elapsed.as_secs_f64();
        println!(
            "  {} Throughput: {}/s",
            "🚀".magenta(),
            format_bytes(throughput as u64).cyan()
        );
    }
}

/// Display failed files if any failures occurred
fn display_failed_files_if_any(failed_files: &[(PathBuf, String)]) {
    if !failed_files.is_empty() {
        println!(
            "\n{} Failed files ({}):",
            "❌".red().bold(),
            failed_files.len()
        );
        for (path, error) in failed_files {
            println!(
                "  {} {}: {}",
                "•".red(),
                path.display().to_string().yellow(),
                error.red()
            );
        }
    }
}

/// Display completion message if operation was successful
fn display_completion_message_if_successful(operation: &str, processed_count: usize) {
    if processed_count > 0 {
        println!(
            "\n{} {} completed successfully!",
            "🎉".green().bold(),
            operation
        );
    }
}

/// Prepare input files with validation and early return for empty results
fn prepare_input_files(
    input_dir: &str,
    pattern: Option<&str>,
    recursive: bool,
) -> anyhow::Result<Vec<PathBuf>> {
    let input_files = find_input_files(input_dir, pattern, recursive)?;

    if input_files.is_empty() {
        println!("{} No files found matching criteria", "⚠".yellow());
        return Ok(vec![]);
    }

    println!(
        "{} Found {} files to encrypt",
        "📁".blue(),
        input_files.len().to_string().cyan()
    );

    Ok(input_files)
}

/// Prepare input files for decryption with validation
fn prepare_decrypt_input_files(
    input_dir: &str,
    pattern: Option<&str>,
    recursive: bool,
) -> anyhow::Result<Vec<PathBuf>> {
    let input_files = find_input_files(input_dir, pattern, recursive)?;

    if input_files.is_empty() {
        println!("{} No files found matching criteria", "⚠".yellow());
        return Ok(vec![]);
    }

    println!(
        "{} Found {} files to decrypt",
        "📁".blue(),
        input_files.len().to_string().cyan()
    );

    Ok(input_files)
}

/// Create batch processor and configuration from command arguments
fn create_batch_processor_and_config(cmd: &BatchEncryptCommand) -> (BatchProcessor, BatchConfig) {
    let config = Config::default();
    let processor = if cfg!(feature = "parallel") {
        BatchProcessor::new(config)
    } else {
        BatchProcessor::sequential(config)
    };

    let batch_config = BatchConfig {
        continue_on_error: cmd.continue_on_error,
        max_parallel: cmd.max_parallel,
        output_pattern: cmd.output_pattern.clone(),
        preserve_structure: !cmd.flatten,
    };

    (processor, batch_config)
}

/// Create batch processor and configuration from decrypt command arguments
fn create_decrypt_batch_processor_and_config(
    cmd: &BatchDecryptCommand,
) -> (BatchProcessor, BatchConfig) {
    let config = Config::default();
    let processor = if cfg!(feature = "parallel") {
        BatchProcessor::new(config)
    } else {
        BatchProcessor::sequential(config)
    };

    let batch_config = BatchConfig {
        continue_on_error: cmd.continue_on_error,
        max_parallel: cmd.max_parallel,
        output_pattern: cmd.output_pattern.clone(),
        preserve_structure: !cmd.flatten,
    };

    (processor, batch_config)
}

/// Setup progress bar and callback for file processing
fn setup_progress_bar(
    input_files: &[PathBuf],
    message: String,
) -> anyhow::Result<(ProgressBar, ProgressCallback)> {
    let multi_progress = MultiProgress::new();
    let main_pb = multi_progress.add(ProgressBar::new(input_files.len() as u64));

    main_pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    main_pb.set_message(message);

    let pb_clone = main_pb.clone();
    let progress_callback: Box<dyn Fn(u64, u64) + Send + Sync> =
        Box::new(move |current: u64, _total: u64| {
            pb_clone.set_position(current);
        });

    Ok((main_pb, progress_callback))
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
