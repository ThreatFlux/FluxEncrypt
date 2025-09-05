//! Key generation command implementation.

use crate::commands::CommandResult;
use crate::utils::{confirm_overwrite, create_output_directory};
use clap::Args;
use colored::*;
use dialoguer::{Confirm, Input, Select};
use fluxencrypt::config::RsaKeySize;
use fluxencrypt::keys::{
    storage::{KeyStorage, StorageOptions},
    KeyPair,
};
use std::path::PathBuf;

/// Generate a new RSA key pair
#[derive(Args)]
pub struct KeygenCommand {
    /// Output directory for the key files
    #[arg(
        short,
        long,
        default_value = ".",
        help = "Output directory for generated keys"
    )]
    output_dir: PathBuf,

    /// Base name for key files (without extension)
    #[arg(
        short = 'n',
        long,
        default_value = "fluxencrypt_key",
        help = "Base name for key files"
    )]
    name: String,

    /// RSA key size in bits
    #[arg(short = 's', long, value_parser = parse_key_size, help = "RSA key size (2048, 3072, or 4096)")]
    key_size: Option<RsaKeySize>,

    /// Overwrite existing key files without prompting
    #[arg(long, help = "Overwrite existing files without confirmation")]
    force: bool,

    /// Interactive mode for guided key generation
    #[arg(short, long, help = "Interactive mode with prompts")]
    interactive: bool,

    /// Password to encrypt the private key
    #[arg(short, long, help = "Password to encrypt the private key")]
    password: Option<String>,

    /// Show the generated public key
    #[arg(long, help = "Display the generated public key")]
    show_public: bool,
}

/// Parse key size argument
fn parse_key_size(s: &str) -> Result<RsaKeySize, String> {
    match s {
        "2048" => Ok(RsaKeySize::Rsa2048),
        "3072" => Ok(RsaKeySize::Rsa3072),
        "4096" => Ok(RsaKeySize::Rsa4096),
        _ => Err(format!(
            "Invalid key size: {}. Must be 2048, 3072, or 4096",
            s
        )),
    }
}

pub fn execute(cmd: KeygenCommand) -> CommandResult {
    let KeygenCommand {
        output_dir,
        name,
        key_size,
        force,
        interactive,
        password,
        show_public,
    } = cmd;

    // Interactive mode setup
    let (final_name, final_key_size, final_password) = if interactive {
        run_interactive_keygen(&name, key_size)?
    } else {
        (name, key_size.unwrap_or(RsaKeySize::Rsa2048), password)
    };

    // Create output directory
    create_output_directory(&output_dir)?;

    // Build file paths
    let public_key_path = output_dir.join(format!("{}.pub", final_name));
    let private_key_path = output_dir.join(format!("{}.pem", final_name));

    // Check for existing files
    if !force {
        if public_key_path.exists() && !confirm_overwrite(&public_key_path)? {
            println!("{}", "Key generation cancelled.".yellow());
            return Ok(());
        }
        if private_key_path.exists() && !confirm_overwrite(&private_key_path)? {
            println!("{}", "Key generation cancelled.".yellow());
            return Ok(());
        }
    }

    // Generate the key pair
    println!(
        "{}",
        format!(
            "Generating {}-bit RSA key pair...",
            usize::from(final_key_size)
        )
        .cyan()
    );

    let keypair = KeyPair::generate(final_key_size.into())
        .map_err(|e| anyhow::anyhow!("Failed to generate key pair: {}", e))?;

    println!("{}", "✓ Key pair generated successfully".green());

    // Prepare storage options
    let options = StorageOptions {
        overwrite: force,
        password: final_password,
        ..Default::default()
    };

    // Save the keys
    let storage = if options.password.is_some() {
        KeyStorage::with_encryption()
    } else {
        KeyStorage::new()
    };

    println!("{}", "Saving key files...".cyan());

    storage
        .save_keypair(&keypair, &public_key_path, &private_key_path, &options)
        .map_err(|e| anyhow::anyhow!("Failed to save keys: {}", e))?;

    // Success message
    println!("{}", "✓ Key pair saved successfully".green());
    println!("  {} {}", "Public key:".bold(), public_key_path.display());
    println!("  {} {}", "Private key:".bold(), private_key_path.display());

    if options.password.is_some() {
        println!(
            "  {} {}",
            "Private key encryption:".bold(),
            "Enabled".green()
        );
    } else {
        println!(
            "  {} {}",
            "Private key encryption:".bold(),
            "Disabled".yellow()
        );
        println!(
            "  {} Consider using a password for additional security",
            "Tip:".yellow().bold()
        );
    }

    // Show public key if requested
    if show_public {
        match keypair.public_key().to_pem() {
            Ok(pem) => {
                println!("\n{}", "Public Key:".bold().underline());
                println!("{}", pem);
            }
            Err(e) => {
                log::warn!("Could not display public key: {}", e);
            }
        }
    }

    println!(
        "\n{}",
        "Key generation completed successfully!".green().bold()
    );

    Ok(())
}

/// Run interactive key generation with prompts
fn run_interactive_keygen(
    default_name: &str,
    default_key_size: Option<RsaKeySize>,
) -> anyhow::Result<(String, RsaKeySize, Option<String>)> {
    println!("{}", "=== Interactive Key Generation ===".cyan().bold());

    // Get key name
    let name: String = Input::new()
        .with_prompt("Key name")
        .default(default_name.to_string())
        .interact()?;

    // Get key size
    let key_size_options = vec![
        "2048 bits (recommended)",
        "3072 bits",
        "4096 bits (maximum security)",
    ];
    let default_selection = match default_key_size.unwrap_or(RsaKeySize::Rsa2048) {
        RsaKeySize::Rsa2048 => 0,
        RsaKeySize::Rsa3072 => 1,
        RsaKeySize::Rsa4096 => 2,
    };

    let key_size_selection = Select::new()
        .with_prompt("RSA key size")
        .items(&key_size_options)
        .default(default_selection)
        .interact()?;

    let key_size = match key_size_selection {
        0 => RsaKeySize::Rsa2048,
        1 => RsaKeySize::Rsa3072,
        2 => RsaKeySize::Rsa4096,
        _ => unreachable!(),
    };

    // Ask about password protection
    let use_password = Confirm::new()
        .with_prompt("Encrypt private key with password?")
        .default(false)
        .interact()?;

    let password = if use_password {
        let password: String = dialoguer::Password::new()
            .with_prompt("Private key password")
            .with_confirmation("Confirm password", "Passwords don't match")
            .interact()?;
        Some(password)
    } else {
        None
    };

    // Summary
    println!("\n{}", "=== Generation Summary ===".cyan().bold());
    println!("Key name: {}", name.bold());
    println!(
        "Key size: {} bits",
        usize::from(key_size).to_string().bold()
    );
    println!(
        "Password protected: {}",
        if password.is_some() {
            "Yes".green()
        } else {
            "No".yellow()
        }
    );

    if !Confirm::new()
        .with_prompt("Generate key pair with these settings?")
        .default(true)
        .interact()?
    {
        return Err(anyhow::anyhow!("Key generation cancelled by user"));
    }

    Ok((name, key_size, password))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_size() {
        assert!(matches!(parse_key_size("2048"), Ok(RsaKeySize::Rsa2048)));
        assert!(matches!(parse_key_size("3072"), Ok(RsaKeySize::Rsa3072)));
        assert!(matches!(parse_key_size("4096"), Ok(RsaKeySize::Rsa4096)));
        assert!(parse_key_size("1024").is_err());
    }
}
