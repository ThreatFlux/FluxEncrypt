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
use std::path::{Path, PathBuf};

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
    #[arg(short = 's', long, value_parser = parse_key_size, default_value = "4096", help = "RSA key size (2048, 3072, or 4096)")]
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

    /// Output keys in base64 format
    #[arg(long, help = "Save keys in base64 encoded format")]
    base64: bool,
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
        base64,
    } = cmd;

    // Get final parameters (interactive or default)
    let (final_name, final_key_size, final_password) =
        get_final_parameters(&name, key_size, password, interactive)?;

    // Setup file paths
    let (public_key_path, private_key_path) = setup_file_paths(&output_dir, &final_name)?;

    // Check existing files
    check_existing_files(&public_key_path, &private_key_path, force)?;

    // Generate key pair
    let keypair = generate_keypair(final_key_size)?;

    // Save keys
    save_keys(
        &keypair,
        &public_key_path,
        &private_key_path,
        final_password.clone(),
        force,
        base64,
    )?;

    // Display results
    display_results(
        &public_key_path,
        &private_key_path,
        final_password,
        show_public,
        &keypair,
    )?;

    Ok(())
}

/// Run interactive key generation with prompts
fn run_interactive_keygen(
    default_name: &str,
    default_key_size: Option<RsaKeySize>,
) -> anyhow::Result<(String, RsaKeySize, Option<String>)> {
    println!("{}", "=== Interactive Key Generation ===".cyan().bold());

    let name = prompt_key_name(default_name)?;
    let key_size = prompt_key_size(default_key_size)?;
    let password = prompt_password()?;

    display_summary(&name, key_size, &password)?;
    confirm_generation()?;

    Ok((name, key_size, password))
}

/// Prompt for key name
fn prompt_key_name(default_name: &str) -> anyhow::Result<String> {
    let name: String = Input::new()
        .with_prompt("Key name")
        .default(default_name.to_string())
        .interact()?;
    Ok(name)
}

/// Prompt for key size selection
fn prompt_key_size(default_key_size: Option<RsaKeySize>) -> anyhow::Result<RsaKeySize> {
    let key_size_options = vec![
        "2048 bits (recommended)",
        "3072 bits",
        "4096 bits (maximum security)",
    ];
    let default_selection = match default_key_size.unwrap_or(RsaKeySize::Rsa4096) {
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

    Ok(key_size)
}

/// Prompt for password protection
fn prompt_password() -> anyhow::Result<Option<String>> {
    let use_password = Confirm::new()
        .with_prompt("Encrypt private key with password?")
        .default(false)
        .interact()?;

    if use_password {
        let password: String = dialoguer::Password::new()
            .with_prompt("Private key password")
            .with_confirmation("Confirm password", "Passwords don't match")
            .interact()?;
        Ok(Some(password))
    } else {
        Ok(None)
    }
}

/// Display generation summary
fn display_summary(
    name: &str,
    key_size: RsaKeySize,
    password: &Option<String>,
) -> anyhow::Result<()> {
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
    Ok(())
}

/// Confirm final generation
fn confirm_generation() -> anyhow::Result<()> {
    if !Confirm::new()
        .with_prompt("Generate key pair with these settings?")
        .default(true)
        .interact()?
    {
        return Err(anyhow::anyhow!("Key generation cancelled by user"));
    }
    Ok(())
}

/// Get final parameters based on interactive mode or defaults
fn get_final_parameters(
    name: &str,
    key_size: Option<RsaKeySize>,
    password: Option<String>,
    interactive: bool,
) -> anyhow::Result<(String, RsaKeySize, Option<String>)> {
    if interactive {
        run_interactive_keygen(name, key_size)
    } else {
        Ok((
            name.to_string(),
            key_size.unwrap_or(RsaKeySize::Rsa4096),
            password,
        ))
    }
}

/// Setup file paths and create output directory
fn setup_file_paths(
    output_dir: &std::path::Path,
    name: &str,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    create_output_directory(output_dir)?;
    let public_key_path = output_dir.join(format!("{}.pub", name));
    let private_key_path = output_dir.join(format!("{}.pem", name));
    Ok((public_key_path, private_key_path))
}

/// Check if files exist and confirm overwrite if needed
fn check_existing_files(
    public_key_path: &Path,
    private_key_path: &Path,
    force: bool,
) -> anyhow::Result<()> {
    if force {
        return Ok(());
    }

    if public_key_path.exists() && !confirm_overwrite(public_key_path)? {
        println!("{}", "Key generation cancelled.".yellow());
        return Err(anyhow::anyhow!("Operation cancelled by user"));
    }
    if private_key_path.exists() && !confirm_overwrite(private_key_path)? {
        println!("{}", "Key generation cancelled.".yellow());
        return Err(anyhow::anyhow!("Operation cancelled by user"));
    }

    Ok(())
}

/// Generate the RSA key pair
fn generate_keypair(key_size: RsaKeySize) -> anyhow::Result<KeyPair> {
    println!(
        "{}",
        format!("Generating {}-bit RSA key pair...", usize::from(key_size)).cyan()
    );

    let keypair = KeyPair::generate(key_size.into())
        .map_err(|e| anyhow::anyhow!("Failed to generate key pair: {}", e))?;

    println!("{}", "✓ Key pair generated successfully".green());
    Ok(keypair)
}

/// Save keys in either base64 or PEM format
fn save_keys(
    keypair: &KeyPair,
    public_key_path: &Path,
    private_key_path: &Path,
    password: Option<String>,
    force: bool,
    base64: bool,
) -> anyhow::Result<()> {
    let options = StorageOptions {
        overwrite: force,
        password: password.clone(),
        ..Default::default()
    };

    if base64 {
        save_keys_base64(keypair, public_key_path, private_key_path, &options)?;
    } else {
        save_keys_pem(keypair, public_key_path, private_key_path, &options)?;
    }

    Ok(())
}

/// Save keys in base64 format
fn save_keys_base64(
    keypair: &KeyPair,
    public_key_path: &Path,
    private_key_path: &Path,
    options: &StorageOptions,
) -> anyhow::Result<()> {
    println!("{}", "Saving keys in base64 format...".cyan());

    let public_pem = keypair
        .public_key()
        .to_pem()
        .map_err(|e| anyhow::anyhow!("Failed to encode public key: {}", e))?;
    let private_pem = if let Some(ref pwd) = options.password {
        keypair
            .private_key()
            .to_encrypted_pem(pwd)
            .map_err(|e| anyhow::anyhow!("Failed to encode private key: {}", e))?
    } else {
        keypair
            .private_key()
            .to_pem()
            .map_err(|e| anyhow::anyhow!("Failed to encode private key: {}", e))?
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let public_b64 = STANDARD.encode(&public_pem);
    let private_b64 = STANDARD.encode(&private_pem);

    std::fs::write(public_key_path, public_b64)
        .map_err(|e| anyhow::anyhow!("Failed to save public key: {}", e))?;
    std::fs::write(private_key_path, private_b64)
        .map_err(|e| anyhow::anyhow!("Failed to save private key: {}", e))?;

    Ok(())
}

/// Save keys in PEM format
fn save_keys_pem(
    keypair: &KeyPair,
    public_key_path: &Path,
    private_key_path: &Path,
    options: &StorageOptions,
) -> anyhow::Result<()> {
    let storage = if options.password.is_some() {
        KeyStorage::with_encryption()
    } else {
        KeyStorage::new()
    };

    println!("{}", "Saving key files...".cyan());

    storage
        .save_keypair(keypair, public_key_path, private_key_path, options)
        .map_err(|e| anyhow::anyhow!("Failed to save keys: {}", e))?;

    Ok(())
}

/// Display success messages and results
fn display_results(
    public_key_path: &Path,
    private_key_path: &Path,
    password: Option<String>,
    show_public: bool,
    keypair: &KeyPair,
) -> anyhow::Result<()> {
    println!("{}", "✓ Key pair saved successfully".green());
    println!("  {} {}", "Public key:".bold(), public_key_path.display());
    println!("  {} {}", "Private key:".bold(), private_key_path.display());

    display_encryption_status(password.is_some());

    if show_public {
        display_public_key(keypair);
    }

    println!(
        "\n{}",
        "Key generation completed successfully!".green().bold()
    );

    Ok(())
}

/// Display encryption status message
fn display_encryption_status(has_password: bool) {
    if has_password {
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
}

/// Display the public key if requested
fn display_public_key(keypair: &KeyPair) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_parse_key_size() {
        assert!(matches!(parse_key_size("2048"), Ok(RsaKeySize::Rsa2048)));
        assert!(matches!(parse_key_size("3072"), Ok(RsaKeySize::Rsa3072)));
        assert!(matches!(parse_key_size("4096"), Ok(RsaKeySize::Rsa4096)));
        assert!(parse_key_size("1024").is_err());
    }

    #[test]
    fn test_default_key_size_is_4096() {
        // The default value in the struct should be "4096"
        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            keygen: KeygenCommand,
        }

        let cli = TestCli::parse_from(["test"]);
        // Default should parse to 4096
        assert_eq!(cli.keygen.key_size, Some(RsaKeySize::Rsa4096));
    }

    #[test]
    fn test_base64_flag() {
        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            keygen: KeygenCommand,
        }

        // Test without base64 flag
        let cli = TestCli::parse_from(["test"]);
        assert!(!cli.keygen.base64);

        // Test with base64 flag
        let cli = TestCli::parse_from(["test", "--base64"]);
        assert!(cli.keygen.base64);
    }
}
