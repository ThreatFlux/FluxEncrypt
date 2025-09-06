//! Config command implementation.

use crate::commands::CommandResult;
use clap::{Args, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Configuration key to set
        key: String,
        /// Configuration value
        value: String,
    },
    /// Get a configuration value
    Get {
        /// Configuration key to get
        key: String,
    },
    /// Reset configuration to defaults
    Reset,
    /// Initialize configuration file
    Init,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FluxEncryptConfig {
    /// Default public key path
    pub default_public_key: Option<String>,
    /// Default private key path
    pub default_private_key: Option<String>,
    /// Default output directory for batch operations
    pub default_output_dir: Option<String>,
    /// Default chunk size for streaming operations
    pub default_chunk_size: Option<usize>,
    /// Whether to use parallel processing by default
    pub use_parallel: Option<bool>,
    /// Whether to continue on error in batch operations
    pub continue_on_error: Option<bool>,
    /// Default file pattern for batch operations
    pub default_pattern: Option<String>,
    /// Whether to preserve directory structure
    pub preserve_structure: Option<bool>,
    /// Whether to show verbose output by default
    pub verbose: Option<bool>,
}

impl Default for FluxEncryptConfig {
    fn default() -> Self {
        Self {
            default_public_key: None,
            default_private_key: None,
            default_output_dir: None,
            default_chunk_size: Some(1_048_576), // 1MB
            use_parallel: Some(true),
            continue_on_error: Some(true),
            default_pattern: None,
            preserve_structure: Some(true),
            verbose: Some(false),
        }
    }
}

pub fn execute(cmd: ConfigCommand) -> CommandResult {
    match cmd.action {
        ConfigAction::Show => show_config(),
        ConfigAction::Set { key, value } => set_config(&key, &value),
        ConfigAction::Get { key } => get_config(&key),
        ConfigAction::Reset => reset_config(),
        ConfigAction::Init => init_config(),
    }
}

fn show_config() -> CommandResult {
    println!("{} FluxEncrypt Configuration:", "⚙️".blue().bold());

    let config_path = get_config_path();

    if !config_path.exists() {
        println!(
            "{} No configuration file found at {}",
            "⚠".yellow(),
            config_path.display().to_string().dimmed()
        );
        println!(
            "{} Run 'fluxencrypt-cli config init' to create one",
            "💡".cyan()
        );
        return Ok(());
    }

    let config = load_config()?;

    println!(
        "{} Configuration file: {}",
        "📁".blue(),
        config_path.display().to_string().cyan()
    );
    println!();

    display_config_section(
        "Key Paths",
        &[
            ("Default public key", &config.default_public_key),
            ("Default private key", &config.default_private_key),
        ],
    );

    display_config_section(
        "Directories",
        &[
            ("Default output directory", &config.default_output_dir),
            ("Default file pattern", &config.default_pattern),
        ],
    );

    display_config_section("Processing Options", &[]);
    if let Some(chunk_size) = config.default_chunk_size {
        println!(
            "  {} Default chunk size: {}",
            "🔢".blue(),
            format_bytes(chunk_size as u64).cyan()
        );
    }
    if let Some(use_parallel) = config.use_parallel {
        println!(
            "  {} Use parallel processing: {}",
            "🚀".purple(),
            format_bool(use_parallel)
        );
    }
    if let Some(continue_on_error) = config.continue_on_error {
        println!(
            "  {} Continue on error: {}",
            "🔄".yellow(),
            format_bool(continue_on_error)
        );
    }
    if let Some(preserve_structure) = config.preserve_structure {
        println!(
            "  {} Preserve directory structure: {}",
            "📂".blue(),
            format_bool(preserve_structure)
        );
    }
    if let Some(verbose) = config.verbose {
        println!("  {} Verbose output: {}", "📝".cyan(), format_bool(verbose));
    }

    Ok(())
}

fn set_config(key: &str, value: &str) -> CommandResult {
    let mut config = load_config().unwrap_or_default();

    match key {
        "default_public_key" | "public_key" => {
            let path = Path::new(value);
            if !path.exists() {
                println!(
                    "{} Warning: Public key file does not exist: {}",
                    "⚠".yellow(),
                    value.red()
                );
            }
            config.default_public_key = Some(value.to_string());
        }
        "default_private_key" | "private_key" => {
            let path = Path::new(value);
            if !path.exists() {
                println!(
                    "{} Warning: Private key file does not exist: {}",
                    "⚠".yellow(),
                    value.red()
                );
            }
            config.default_private_key = Some(value.to_string());
        }
        "default_output_dir" | "output_dir" => {
            config.default_output_dir = Some(value.to_string());
        }
        "default_chunk_size" | "chunk_size" => {
            let chunk_size: usize = value
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid chunk size: {}", value))?;
            if chunk_size < 1024 {
                return Err(anyhow::anyhow!("Chunk size must be at least 1024 bytes"));
            }
            config.default_chunk_size = Some(chunk_size);
        }
        "use_parallel" | "parallel" => {
            let use_parallel = parse_bool(value)?;
            config.use_parallel = Some(use_parallel);
        }
        "continue_on_error" => {
            let continue_on_error = parse_bool(value)?;
            config.continue_on_error = Some(continue_on_error);
        }
        "default_pattern" | "pattern" => {
            config.default_pattern = Some(value.to_string());
        }
        "preserve_structure" => {
            let preserve_structure = parse_bool(value)?;
            config.preserve_structure = Some(preserve_structure);
        }
        "verbose" => {
            let verbose = parse_bool(value)?;
            config.verbose = Some(verbose);
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown configuration key: {}", key));
        }
    }

    save_config(&config)?;

    println!(
        "{} Set {} = {}",
        "✓".green().bold(),
        key.cyan(),
        value.yellow()
    );

    Ok(())
}

fn get_config(key: &str) -> CommandResult {
    let config = load_config().unwrap_or_default();

    let value = match key {
        "default_public_key" | "public_key" => config.default_public_key.as_deref(),
        "default_private_key" | "private_key" => config.default_private_key.as_deref(),
        "default_output_dir" | "output_dir" => config.default_output_dir.as_deref(),
        "default_pattern" | "pattern" => config.default_pattern.as_deref(),
        "default_chunk_size" | "chunk_size" => {
            if let Some(size) = config.default_chunk_size {
                println!("{}", size);
                return Ok(());
            } else {
                None
            }
        }
        "use_parallel" | "parallel" => {
            if let Some(parallel) = config.use_parallel {
                println!("{}", parallel);
                return Ok(());
            } else {
                None
            }
        }
        "continue_on_error" => {
            if let Some(continue_on_error) = config.continue_on_error {
                println!("{}", continue_on_error);
                return Ok(());
            } else {
                None
            }
        }
        "preserve_structure" => {
            if let Some(preserve) = config.preserve_structure {
                println!("{}", preserve);
                return Ok(());
            } else {
                None
            }
        }
        "verbose" => {
            if let Some(verbose) = config.verbose {
                println!("{}", verbose);
                return Ok(());
            } else {
                None
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown configuration key: {}", key));
        }
    };

    if let Some(value) = value {
        println!("{}", value);
    } else {
        println!(
            "{} Configuration key '{}' is not set",
            "⚠".yellow(),
            key.red()
        );
    }

    Ok(())
}

fn reset_config() -> CommandResult {
    let config_path = get_config_path();

    if config_path.exists() {
        fs::remove_file(&config_path)
            .map_err(|e| anyhow::anyhow!("Failed to remove config file: {}", e))?;
        println!("{} Configuration reset to defaults", "✓".green().bold());
    } else {
        println!("{} No configuration file to reset", "⚠".yellow());
    }

    Ok(())
}

fn init_config() -> CommandResult {
    let config_path = get_config_path();

    // Create config directory if it doesn't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("Failed to create config directory: {}", e))?;
    }

    if config_path.exists() {
        println!(
            "{} Configuration file already exists at {}",
            "⚠".yellow(),
            config_path.display().to_string().cyan()
        );
        return Ok(());
    }

    let config = FluxEncryptConfig::default();
    save_config(&config)?;

    println!(
        "{} Initialized configuration file at {}",
        "✓".green().bold(),
        config_path.display().to_string().cyan()
    );
    println!(
        "{} Run 'fluxencrypt-cli config show' to view settings",
        "💡".cyan()
    );

    Ok(())
}

fn load_config() -> anyhow::Result<FluxEncryptConfig> {
    let config_path = get_config_path();

    if !config_path.exists() {
        return Ok(FluxEncryptConfig::default());
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;

    serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))
}

fn save_config(config: &FluxEncryptConfig) -> anyhow::Result<()> {
    let config_path = get_config_path();

    // Create config directory if it doesn't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("Failed to create config directory: {}", e))?;
    }

    let content = serde_json::to_string_pretty(config)
        .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;

    fs::write(&config_path, content)
        .map_err(|e| anyhow::anyhow!("Failed to write config file: {}", e))?;

    Ok(())
}

fn get_config_path() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("fluxencrypt").join("config.json")
    } else {
        PathBuf::from(".fluxencrypt-config.json")
    }
}

fn display_config_section(title: &str, items: &[(&str, &Option<String>)]) {
    if !items.is_empty() || title != "Processing Options" {
        println!("{} {}:", "📋".blue(), title.bold());
        for (name, value) in items {
            match value {
                Some(val) => println!("  {} {}: {}", "•".blue(), name, val.cyan()),
                None => println!(
                    "  {} {}: {}",
                    "•".dimmed(),
                    name.dimmed(),
                    "not set".dimmed()
                ),
            }
        }
        println!();
    }
}

fn format_bool(value: bool) -> colored::ColoredString {
    if value {
        "true".green()
    } else {
        "false".red()
    }
}

fn parse_bool(value: &str) -> anyhow::Result<bool> {
    match value.to_lowercase().as_str() {
        "true" | "yes" | "1" | "on" | "enable" | "enabled" => Ok(true),
        "false" | "no" | "0" | "off" | "disable" | "disabled" => Ok(false),
        _ => Err(anyhow::anyhow!("Invalid boolean value: {}", value)),
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
