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
}

pub fn execute(cmd: DecryptCommand) -> CommandResult {
    // Validate arguments
    if cmd.input.is_some() && cmd.data.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --input and --data"));
    }

    // Load the private key
    let private_key = crate::utils::load_private_key(cmd.key.as_deref(), cmd.password.as_deref())
        .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;

    // Create the cryptum instance
    let cryptum =
        cryptum().map_err(|e| anyhow::anyhow!("Failed to create cryptum instance: {}", e))?;

    // Determine the input source and handle decryption
    if let Some(input_file) = cmd.input {
        // File input mode
        if let Some(output_file) = cmd.output {
            // File to file decryption
            decrypt_file(&cryptum, &input_file, &output_file, &private_key)?;

            println!(
                "{} Successfully decrypted {} to {}",
                "✓".green().bold(),
                input_file.cyan(),
                output_file.cyan()
            );
        } else {
            // File to stdout decryption
            decrypt_file_to_stdout(&cryptum, &input_file, &private_key)?;
        }
    } else if let Some(data) = cmd.data {
        // Direct data mode (base64 encoded)
        let encrypted_data = base64::prelude::BASE64_STANDARD
            .decode(&data)
            .map_err(|e| anyhow::anyhow!("Failed to decode base64 data: {}", e))?;

        let decrypted_data = cryptum
            .decrypt(&private_key, &encrypted_data)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        if let Some(output_file) = cmd.output {
            // Write to file
            fs::write(&output_file, &decrypted_data)
                .map_err(|e| anyhow::anyhow!("Failed to write to output file: {}", e))?;

            println!(
                "{} Successfully decrypted data to {}",
                "✓".green().bold(),
                output_file.cyan()
            );
        } else {
            // Write to stdout
            io::stdout()
                .write_all(&decrypted_data)
                .map_err(|e| anyhow::anyhow!("Failed to write to stdout: {}", e))?;
        }
    } else {
        // Stdin mode (expect base64 encoded data)
        let mut stdin_data = String::new();
        io::stdin()
            .read_to_string(&mut stdin_data)
            .map_err(|e| anyhow::anyhow!("Failed to read from stdin: {}", e))?;

        if stdin_data.trim().is_empty() {
            return Err(anyhow::anyhow!("No input data provided"));
        }

        let encrypted_data = base64::prelude::BASE64_STANDARD
            .decode(stdin_data.trim())
            .map_err(|e| anyhow::anyhow!("Failed to decode base64 data from stdin: {}", e))?;

        let decrypted_data = cryptum
            .decrypt(&private_key, &encrypted_data)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        if let Some(output_file) = cmd.output {
            // Write to file
            fs::write(&output_file, &decrypted_data)
                .map_err(|e| anyhow::anyhow!("Failed to write to output file: {}", e))?;

            println!(
                "{} Successfully decrypted stdin data to {}",
                "✓".green().bold(),
                output_file.cyan()
            );
        } else {
            // Write to stdout
            io::stdout()
                .write_all(&decrypted_data)
                .map_err(|e| anyhow::anyhow!("Failed to write to stdout: {}", e))?;
        }
    }

    Ok(())
}

fn decrypt_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
) -> CommandResult {
    // Check if input file exists
    if !Path::new(input_path).exists() {
        return Err(anyhow::anyhow!(
            "Input file '{}' does not exist",
            input_path
        ));
    }

    // Get file size for progress bar and determine decryption method
    let file_size = fs::metadata(input_path)?.len();

    // For small files (<=1MB), use simple hybrid decryption to avoid streaming issues
    if file_size <= 1_000_000 {
        let ciphertext = fs::read(input_path)
            .map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?;

        let plaintext = cryptum
            .decrypt(private_key, &ciphertext)
            .map_err(|e| anyhow::anyhow!("File decryption failed: {}", e))?;

        fs::write(output_path, &plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;

        log::info!(
            "Decrypted {} bytes from {} to {} (hybrid mode)",
            plaintext.len(),
            input_path,
            output_path
        );
        return Ok(());
    }

    // For large files (>1MB), use streaming decryption with progress bar
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Create progress callback
    let pb_clone = pb.clone();
    let progress_callback = Box::new(move |current, _total| {
        pb_clone.set_position(current);
    });

    // Perform the streaming decryption
    let bytes_processed = cryptum
        .decrypt_file_with_progress(input_path, output_path, private_key, progress_callback)
        .map_err(|e| anyhow::anyhow!("File decryption failed: {}", e))?;

    // Finish progress bar
    pb.finish_with_message("Decryption complete");

    log::info!(
        "Decrypted {} bytes from {} to {} (streaming mode)",
        bytes_processed,
        input_path,
        output_path
    );

    Ok(())
}

fn decrypt_file_to_stdout(
    cryptum: &Cryptum,
    input_path: &str,
    private_key: &fluxencrypt::keys::PrivateKey,
) -> CommandResult {
    // Check if input file exists
    if !Path::new(input_path).exists() {
        return Err(anyhow::anyhow!(
            "Input file '{}' does not exist",
            input_path
        ));
    }

    // For stdout mode, always use simple hybrid decryption
    let encrypted_data =
        fs::read(input_path).map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?;

    let decrypted_data = cryptum
        .decrypt(private_key, &encrypted_data)
        .map_err(|e| anyhow::anyhow!("File decryption failed: {}", e))?;

    // Write to stdout
    io::stdout()
        .write_all(&decrypted_data)
        .map_err(|e| anyhow::anyhow!("Failed to write to stdout: {}", e))?;

    Ok(())
}
