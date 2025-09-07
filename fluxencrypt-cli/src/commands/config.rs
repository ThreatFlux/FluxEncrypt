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
        display_no_config_message(&config_path);
        return Ok(());
    }

    let config = load_config()?;
    display_config_file_path(&config_path);
    display_all_config_sections(&config);

    Ok(())
}

fn display_no_config_message(config_path: &Path) {
    println!(
        "{} No configuration file found at {}",
        "⚠".yellow(),
        config_path.display().to_string().dimmed()
    );
    println!(
        "{} Run 'fluxencrypt-cli config init' to create one",
        "💡".cyan()
    );
}

fn display_config_file_path(config_path: &Path) {
    println!(
        "{} Configuration file: {}",
        "📁".blue(),
        config_path.display().to_string().cyan()
    );
    println!();
}

fn display_all_config_sections(config: &FluxEncryptConfig) {
    display_key_paths_section(config);
    display_directories_section(config);
    display_processing_options_section(config);
}

fn display_key_paths_section(config: &FluxEncryptConfig) {
    display_config_section(
        "Key Paths",
        &[
            ("Default public key", &config.default_public_key),
            ("Default private key", &config.default_private_key),
        ],
    );
}

fn display_directories_section(config: &FluxEncryptConfig) {
    display_config_section(
        "Directories",
        &[
            ("Default output directory", &config.default_output_dir),
            ("Default file pattern", &config.default_pattern),
        ],
    );
}

fn display_processing_options_section(config: &FluxEncryptConfig) {
    display_config_section("Processing Options", &[]);

    display_chunk_size_option(config.default_chunk_size);
    display_boolean_option(
        "🚀",
        "Use parallel processing",
        config.use_parallel,
        "purple",
    );
    display_boolean_option(
        "🔄",
        "Continue on error",
        config.continue_on_error,
        "yellow",
    );
    display_boolean_option(
        "📂",
        "Preserve directory structure",
        config.preserve_structure,
        "blue",
    );
    display_boolean_option("📝", "Verbose output", config.verbose, "cyan");
}

fn display_chunk_size_option(chunk_size: Option<usize>) {
    if let Some(size) = chunk_size {
        println!(
            "  {} Default chunk size: {}",
            "🔢".blue(),
            format_bytes(size as u64).cyan()
        );
    }
}

fn display_boolean_option(icon: &str, label: &str, value: Option<bool>, color: &str) {
    if let Some(val) = value {
        let formatted_value = format_bool(val);
        let colored_icon = match color {
            "purple" => icon.purple(),
            "yellow" => icon.yellow(),
            "blue" => icon.blue(),
            "cyan" => icon.cyan(),
            _ => icon.normal(),
        };
        println!("  {} {}: {}", colored_icon, label, formatted_value);
    }
}

fn set_config(key: &str, value: &str) -> CommandResult {
    let mut config = load_config().unwrap_or_default();

    update_config_value(&mut config, key, value)?;
    save_config(&config)?;
    display_config_set_success(key, value);

    Ok(())
}

fn update_config_value(config: &mut FluxEncryptConfig, key: &str, value: &str) -> CommandResult {
    match key {
        "default_public_key" | "public_key" => {
            validate_key_file_path(value, "Public");
            config.default_public_key = Some(value.to_string());
        }
        "default_private_key" | "private_key" => {
            validate_key_file_path(value, "Private");
            config.default_private_key = Some(value.to_string());
        }
        "default_output_dir" | "output_dir" => {
            config.default_output_dir = Some(value.to_string());
        }
        "default_chunk_size" | "chunk_size" => {
            config.default_chunk_size = Some(parse_and_validate_chunk_size(value)?);
        }
        "use_parallel" | "parallel" => {
            config.use_parallel = Some(parse_bool(value)?);
        }
        "continue_on_error" => {
            config.continue_on_error = Some(parse_bool(value)?);
        }
        "default_pattern" | "pattern" => {
            config.default_pattern = Some(value.to_string());
        }
        "preserve_structure" => {
            config.preserve_structure = Some(parse_bool(value)?);
        }
        "verbose" => {
            config.verbose = Some(parse_bool(value)?);
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown configuration key: {}", key));
        }
    }
    Ok(())
}

fn validate_key_file_path(path_str: &str, key_type: &str) {
    let path = Path::new(path_str);
    if !path.exists() {
        println!(
            "{} Warning: {} key file does not exist: {}",
            "⚠".yellow(),
            key_type,
            path_str.red()
        );
    }
}

fn parse_and_validate_chunk_size(value: &str) -> anyhow::Result<usize> {
    let chunk_size: usize = value
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid chunk size: {}", value))?;

    if chunk_size < 1024 {
        return Err(anyhow::anyhow!("Chunk size must be at least 1024 bytes"));
    }

    Ok(chunk_size)
}

fn display_config_set_success(key: &str, value: &str) {
    println!(
        "{} Set {} = {}",
        "✓".green().bold(),
        key.cyan(),
        value.yellow()
    );
}

fn get_config(key: &str) -> CommandResult {
    let config = load_config().unwrap_or_default();

    match key {
        "default_public_key" | "public_key" => {
            print_string_config_value(&config.default_public_key, key)
        }
        "default_private_key" | "private_key" => {
            print_string_config_value(&config.default_private_key, key)
        }
        "default_output_dir" | "output_dir" => {
            print_string_config_value(&config.default_output_dir, key)
        }
        "default_pattern" | "pattern" => print_string_config_value(&config.default_pattern, key),
        "default_chunk_size" | "chunk_size" => {
            print_numeric_config_value(config.default_chunk_size, key)
        }
        "use_parallel" | "parallel" => print_bool_config_value(config.use_parallel, key),
        "continue_on_error" => print_bool_config_value(config.continue_on_error, key),
        "preserve_structure" => print_bool_config_value(config.preserve_structure, key),
        "verbose" => print_bool_config_value(config.verbose, key),
        _ => Err(anyhow::anyhow!("Unknown configuration key: {}", key)),
    }
}

fn print_string_config_value(value: &Option<String>, key: &str) -> CommandResult {
    match value {
        Some(val) => println!("{}", val),
        None => print_config_not_set_message(key),
    }
    Ok(())
}

fn print_numeric_config_value<T: std::fmt::Display>(value: Option<T>, key: &str) -> CommandResult {
    match value {
        Some(val) => println!("{}", val),
        None => print_config_not_set_message(key),
    }
    Ok(())
}

fn print_bool_config_value(value: Option<bool>, key: &str) -> CommandResult {
    match value {
        Some(val) => println!("{}", val),
        None => print_config_not_set_message(key),
    }
    Ok(())
}

fn print_config_not_set_message(key: &str) {
    println!(
        "{} Configuration key '{}' is not set",
        "⚠".yellow(),
        key.red()
    );
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
