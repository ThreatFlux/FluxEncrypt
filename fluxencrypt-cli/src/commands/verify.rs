//! Verify command implementation.

use crate::commands::CommandResult;
use clap::Args;
use colored::*;
use fluxencrypt::{cryptum, keys::parsing::KeyParser};
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Args)]
pub struct VerifyCommand {
    /// Encrypted file to verify
    #[arg(short, long)]
    file: String,

    /// Private key file path (required for decryption verification)
    #[arg(short, long)]
    key: Option<String>,

    /// Check only file structure without decryption
    #[arg(long)]
    structure_only: bool,

    /// Show detailed verification information
    #[arg(long)]
    verbose: bool,
}

pub fn execute(cmd: VerifyCommand) -> CommandResult {
    println!("{} Starting file verification...", "🔍".blue().bold());

    let start_time = Instant::now();
    let (file_size, encrypted_data) = read_and_validate_file(&cmd)?;

    let _structure_valid = perform_structure_verification(&encrypted_data, cmd.verbose)?;

    if cmd.structure_only {
        let elapsed = start_time.elapsed();
        display_verification_results("Structure Verification", file_size, elapsed, true, false);
        return Ok(());
    }

    perform_decryption_verification(&cmd, &encrypted_data, file_size, start_time)?;

    println!(
        "{} Verification completed successfully!",
        "🎉".green().bold()
    );
    Ok(())
}

fn verify_file_structure(encrypted_data: &[u8], verbose: bool) -> anyhow::Result<bool> {
    if !check_file_size(encrypted_data, verbose)? {
        return Ok(false);
    }

    check_file_size_limits(encrypted_data, verbose);

    if !check_entropy(encrypted_data, verbose)? {
        return Ok(false);
    }

    check_null_bytes(encrypted_data, verbose);
    check_patterns(encrypted_data, verbose);

    Ok(true)
}

fn check_file_size(encrypted_data: &[u8], verbose: bool) -> anyhow::Result<bool> {
    if encrypted_data.len() < 32 {
        if verbose {
            println!(
                "  {} File too small to be a valid encrypted file",
                "⚠".yellow()
            );
        }
        return Ok(false);
    }
    Ok(true)
}

fn check_file_size_limits(encrypted_data: &[u8], verbose: bool) {
    #[cfg(target_pointer_width = "32")]
    const MAX_REASONABLE_SIZE: usize = 4_000_000_000;
    #[cfg(target_pointer_width = "64")]
    const MAX_REASONABLE_SIZE: usize = 100_000_000_000;

    if encrypted_data.len() > MAX_REASONABLE_SIZE && verbose {
        println!("  {} File suspiciously large", "⚠".yellow());
    }
}

fn check_entropy(encrypted_data: &[u8], verbose: bool) -> anyhow::Result<bool> {
    let entropy = calculate_entropy(encrypted_data);

    if verbose {
        println!(
            "  {} File entropy: {:.2} bits",
            "🎲".blue(),
            entropy.to_string().cyan()
        );
    }

    if entropy < 7.0 {
        if verbose {
            println!(
                "  {} Low entropy detected - may not be properly encrypted",
                "⚠".yellow()
            );
        }
        return Ok(false);
    }

    Ok(true)
}

fn check_null_bytes(encrypted_data: &[u8], verbose: bool) {
    let null_count = encrypted_data.iter().filter(|&&b| b == 0).count();
    let null_percentage = (null_count as f64 / encrypted_data.len() as f64) * 100.0;

    if verbose {
        println!(
            "  {} Null bytes: {} ({:.2}%)",
            "0️⃣".blue(),
            null_count.to_string().cyan(),
            null_percentage.to_string().cyan()
        );

        if null_percentage > 5.0 {
            println!("  {} High null byte percentage detected", "⚠".yellow());
        }
    }
}

fn check_patterns(encrypted_data: &[u8], verbose: bool) {
    let has_patterns = check_for_patterns(encrypted_data, verbose);
    if has_patterns && verbose {
        println!("  {} Repeating patterns detected", "⚠".yellow());
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn check_for_patterns(data: &[u8], verbose: bool) -> bool {
    // Simple pattern detection - look for repeating 4-byte sequences
    const PATTERN_SIZE: usize = 4;
    const SAMPLE_SIZE: usize = 1024; // Check first 1KB only for performance

    let sample_size = std::cmp::min(data.len(), SAMPLE_SIZE);
    if sample_size < PATTERN_SIZE * 2 {
        return false;
    }

    let mut pattern_counts = std::collections::HashMap::new();

    for i in 0..=(sample_size - PATTERN_SIZE) {
        if let Some(pattern) = data.get(i..i + PATTERN_SIZE) {
            *pattern_counts.entry(pattern).or_insert(0) += 1;
        }
    }

    // Look for patterns that repeat more than expected
    let max_repeats = pattern_counts.values().max().unwrap_or(&0);

    if verbose && *max_repeats > 2 {
        println!(
            "  {} Max pattern repetitions: {}",
            "🔄".blue(),
            max_repeats.to_string().cyan()
        );
    }

    *max_repeats > 3
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

fn display_verification_results(
    operation: &str,
    file_size: u64,
    elapsed: std::time::Duration,
    structure_valid: bool,
    decryption_valid: bool,
) {
    println!("\n{} {} Results:", "📊".blue().bold(), operation);
    println!(
        "  {} File size: {}",
        "📦".blue(),
        format_bytes(file_size).cyan()
    );
    println!(
        "  {} Duration: {:.2}s",
        "⏱".yellow(),
        elapsed.as_secs_f64().to_string().cyan()
    );
    println!(
        "  {} Structure valid: {}",
        "🏗".blue(),
        if structure_valid {
            "Yes".green()
        } else {
            "No".red()
        }
    );

    if decryption_valid {
        println!("  {} Decryption valid: {}", "🔓".yellow(), "Yes".green());
    } else if operation == "Full Verification" || operation == "Verification Failed" {
        println!("  {} Decryption valid: {}", "🔓".yellow(), "No".red());
    }
}

fn read_and_validate_file(cmd: &VerifyCommand) -> anyhow::Result<(u64, Vec<u8>)> {
    if !Path::new(&cmd.file).exists() {
        return Err(anyhow::anyhow!("File '{}' does not exist", cmd.file));
    }

    let metadata = fs::metadata(&cmd.file)?;
    let file_size = metadata.len();

    if cmd.verbose {
        println!("{} File: {}", "📁".blue(), cmd.file.cyan());
        println!("{} Size: {}", "📊".blue(), format_bytes(file_size).cyan());
    }

    println!("{} Reading encrypted file...", "📖".yellow());
    let encrypted_data =
        fs::read(&cmd.file).map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

    if encrypted_data.is_empty() {
        println!("{} File is empty", "⚠".yellow());
        return Err(anyhow::anyhow!("File is empty"));
    }

    Ok((file_size, encrypted_data))
}

fn perform_structure_verification(encrypted_data: &[u8], verbose: bool) -> anyhow::Result<bool> {
    println!("{} Verifying file structure...", "🔧".cyan());

    let structure_valid = verify_file_structure(encrypted_data, verbose)?;

    if structure_valid {
        println!("{} File structure is valid", "✓".green());
    } else {
        println!("{} File structure is invalid", "❌".red());
        return Err(anyhow::anyhow!("Invalid file structure"));
    }

    Ok(structure_valid)
}

fn perform_decryption_verification(
    cmd: &VerifyCommand,
    encrypted_data: &[u8],
    file_size: u64,
    start_time: Instant,
) -> CommandResult {
    if let Some(key_path) = &cmd.key {
        verify_with_decryption(key_path, encrypted_data, file_size, start_time, cmd.verbose)
    } else {
        handle_no_key_provided(file_size, start_time)
    }
}

fn verify_with_decryption(
    key_path: &str,
    encrypted_data: &[u8],
    file_size: u64,
    start_time: Instant,
    verbose: bool,
) -> CommandResult {
    println!("{} Performing decryption verification...", "🔓".yellow());

    let private_key = load_private_key(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;

    let cryptum =
        cryptum().map_err(|e| anyhow::anyhow!("Failed to create cryptum instance: {}", e))?;

    match cryptum.decrypt(&private_key, encrypted_data) {
        Ok(decrypted_data) => handle_successful_decryption(
            &decrypted_data,
            encrypted_data,
            file_size,
            start_time,
            verbose,
        ),
        Err(e) => handle_failed_decryption(e, file_size, start_time),
    }
}

fn handle_successful_decryption(
    decrypted_data: &[u8],
    encrypted_data: &[u8],
    file_size: u64,
    start_time: Instant,
    verbose: bool,
) -> CommandResult {
    println!("{} Decryption verification successful", "✓".green());

    if verbose {
        display_decryption_stats(decrypted_data, encrypted_data);
    }

    let elapsed = start_time.elapsed();
    display_verification_results("Full Verification", file_size, elapsed, true, true);
    Ok(())
}

fn handle_failed_decryption(
    error: fluxencrypt::FluxError,
    file_size: u64,
    start_time: Instant,
) -> CommandResult {
    println!("{} Decryption verification failed: {}", "❌".red(), error);
    let elapsed = start_time.elapsed();
    display_verification_results("Verification Failed", file_size, elapsed, true, false);
    Err(anyhow::anyhow!("File verification failed: {}", error))
}

fn handle_no_key_provided(file_size: u64, start_time: Instant) -> CommandResult {
    println!(
        "{} Skipping decryption verification (no private key provided)",
        "⚠".yellow()
    );
    let elapsed = start_time.elapsed();
    display_verification_results("Partial Verification", file_size, elapsed, true, false);
    Ok(())
}

fn display_decryption_stats(decrypted_data: &[u8], encrypted_data: &[u8]) {
    println!(
        "  {} Decrypted size: {}",
        "📦".blue(),
        format_bytes(decrypted_data.len() as u64).cyan()
    );
    println!(
        "  {} Compression ratio: {:.1}%",
        "🗜".purple(),
        (decrypted_data.len() as f64 / encrypted_data.len() as f64 * 100.0)
            .to_string()
            .cyan()
    );
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
