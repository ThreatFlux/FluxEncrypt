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
}

pub fn execute(cmd: EncryptCommand) -> CommandResult {
    // Validate arguments
    if cmd.input.is_some() && cmd.data.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --input and --data"));
    }

    if cmd.input.is_some() && cmd.env.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --input and --env"));
    }

    if cmd.data.is_some() && cmd.env.is_some() {
        return Err(anyhow::anyhow!("Cannot specify both --data and --env"));
    }

    // Load the public key
    let public_key = crate::utils::load_public_key(cmd.key.as_deref())
        .map_err(|e| anyhow::anyhow!("Failed to load public key: {}", e))?;

    // Create the cryptum instance
    let cryptum =
        cryptum().map_err(|e| anyhow::anyhow!("Failed to create cryptum instance: {}", e))?;

    // Determine the input source and handle encryption
    if let Some(input_file) = cmd.input {
        // File input mode
        let output_file = cmd
            .output
            .ok_or_else(|| anyhow::anyhow!("Output file is required when encrypting files"))?;

        encrypt_file(&cryptum, &input_file, &output_file, &public_key)?;

        println!(
            "{} Successfully encrypted {} to {}",
            "✓".green().bold(),
            input_file.cyan(),
            output_file.cyan()
        );
    } else if let Some(data) = cmd.data {
        // Direct data mode
        let encrypted_data = cryptum
            .encrypt(&public_key, data.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        if let Some(output_file) = cmd.output {
            // Write to file
            fs::write(&output_file, &encrypted_data)
                .map_err(|e| anyhow::anyhow!("Failed to write to output file: {}", e))?;

            println!(
                "{} Successfully encrypted data to {}",
                "✓".green().bold(),
                output_file.cyan()
            );
        } else {
            // Write to stdout (base64 encoded for readability)
            let encoded = base64::prelude::BASE64_STANDARD.encode(&encrypted_data);
            println!("{}", encoded);
        }
    } else if let Some(env_file) = cmd.env {
        // Environment file mode
        let env_data = fs::read_to_string(&env_file)
            .map_err(|e| anyhow::anyhow!("Failed to read environment file: {}", e))?;

        let encrypted_data = cryptum
            .encrypt(&public_key, env_data.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        if let Some(output_file) = cmd.output {
            // Write to file
            fs::write(&output_file, &encrypted_data)
                .map_err(|e| anyhow::anyhow!("Failed to write to output file: {}", e))?;

            println!(
                "{} Successfully encrypted environment file {} to {}",
                "✓".green().bold(),
                env_file.cyan(),
                output_file.cyan()
            );
        } else {
            // Write to stdout (base64 encoded)
            let encoded = base64::prelude::BASE64_STANDARD.encode(&encrypted_data);
            println!("{}", encoded);
        }
    } else {
        // Stdin mode
        let mut stdin_data = Vec::new();
        io::stdin()
            .read_to_end(&mut stdin_data)
            .map_err(|e| anyhow::anyhow!("Failed to read from stdin: {}", e))?;

        if stdin_data.is_empty() {
            return Err(anyhow::anyhow!("No input data provided"));
        }

        let encrypted_data = cryptum
            .encrypt(&public_key, &stdin_data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        if let Some(output_file) = cmd.output {
            // Write to file
            fs::write(&output_file, &encrypted_data)
                .map_err(|e| anyhow::anyhow!("Failed to write to output file: {}", e))?;

            println!(
                "{} Successfully encrypted stdin data to {}",
                "✓".green().bold(),
                output_file.cyan()
            );
        } else {
            // Write to stdout (base64 encoded)
            let encoded = base64::prelude::BASE64_STANDARD.encode(&encrypted_data);
            println!("{}", encoded);
        }
    }

    Ok(())
}

fn encrypt_file(
    cryptum: &Cryptum,
    input_path: &str,
    output_path: &str,
    public_key: &fluxencrypt::keys::PublicKey,
) -> CommandResult {
    // Check if input file exists
    if !Path::new(input_path).exists() {
        return Err(anyhow::anyhow!(
            "Input file '{}' does not exist",
            input_path
        ));
    }

    // Get file size for progress bar and determine encryption method
    let file_size = fs::metadata(input_path)?.len();

    // For small files (<=1MB), use simple hybrid encryption to avoid streaming issues
    if file_size <= 1_000_000 {
        let plaintext = fs::read(input_path)
            .map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?;

        let ciphertext = cryptum
            .encrypt(public_key, &plaintext)
            .map_err(|e| anyhow::anyhow!("File encryption failed: {}", e))?;

        fs::write(output_path, &ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;

        log::info!(
            "Encrypted {} bytes from {} to {} (hybrid mode)",
            plaintext.len(),
            input_path,
            output_path
        );
        return Ok(());
    }

    // For large files (>1MB), use streaming encryption with progress bar
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

    // Perform the streaming encryption
    let bytes_processed = cryptum
        .encrypt_file_with_progress(input_path, output_path, public_key, progress_callback)
        .map_err(|e| anyhow::anyhow!("File encryption failed: {}", e))?;

    // Finish progress bar
    pb.finish_with_message("Encryption complete");

    log::info!(
        "Encrypted {} bytes from {} to {} (streaming mode)",
        bytes_processed,
        input_path,
        output_path
    );

    Ok(())
}
