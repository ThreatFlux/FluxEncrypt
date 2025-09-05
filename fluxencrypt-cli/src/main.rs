//! FluxEncrypt CLI - Command line interface for the FluxEncrypt SDK
//!
//! This binary provides a complete command-line interface for all FluxEncrypt
//! operations including key generation, file encryption/decryption, and batch
//! processing.

use clap::{Parser, Subcommand};
use colored::*;
use std::process;

mod commands;
mod utils;

use commands::*;

/// FluxEncrypt CLI - Secure encryption for files and data
#[derive(Parser)]
#[command(name = "fluxencrypt")]
#[command(version, about, long_about = None)]
#[command(author = "Wyatt Roersma, Claude Code, Codex - ThreatFlux Organization")]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Quiet mode (suppress output)
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new RSA key pair
    Keygen(keygen::KeygenCommand),

    /// Encrypt a file or data
    Encrypt(encrypt::EncryptCommand),

    /// Decrypt a file or data
    Decrypt(decrypt::DecryptCommand),

    /// Encrypt multiple files in batch
    BatchEncrypt(batch::BatchEncryptCommand),

    /// Decrypt multiple files in batch
    BatchDecrypt(batch::BatchDecryptCommand),

    /// Stream encrypt large files
    StreamEncrypt(stream::StreamEncryptCommand),

    /// Stream decrypt large files
    StreamDecrypt(stream::StreamDecryptCommand),

    /// Manage configuration
    Config(config::ConfigCommand),

    /// Show information about keys or encrypted files
    Info(info::InfoCommand),

    /// Verify encrypted file integrity
    Verify(verify::VerifyCommand),

    /// Benchmark encryption/decryption performance
    Benchmark(benchmark::BenchmarkCommand),
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    init_logging(cli.verbose, cli.quiet);

    // Print banner unless in quiet mode
    if !cli.quiet {
        print_banner();
    }

    // Execute the command
    let result = match cli.command {
        Commands::Keygen(cmd) => keygen::execute(cmd),
        Commands::Encrypt(cmd) => encrypt::execute(cmd),
        Commands::Decrypt(cmd) => decrypt::execute(cmd),
        Commands::BatchEncrypt(cmd) => batch::execute_encrypt(cmd),
        Commands::BatchDecrypt(cmd) => batch::execute_decrypt(cmd),
        Commands::StreamEncrypt(cmd) => stream::execute_encrypt(cmd),
        Commands::StreamDecrypt(cmd) => stream::execute_decrypt(cmd),
        Commands::Config(cmd) => config::execute(cmd),
        Commands::Info(cmd) => info::execute(cmd),
        Commands::Verify(cmd) => verify::execute(cmd),
        Commands::Benchmark(cmd) => benchmark::execute(cmd),
    };

    // Handle the result
    if let Err(e) = result {
        if !cli.quiet {
            eprintln!("{} {}", "Error:".red().bold(), e);
        }
        process::exit(1);
    }
}

/// Initialize logging based on verbosity settings
fn init_logging(verbose: bool, quiet: bool) {
    if quiet {
        return; // No logging in quiet mode
    }

    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(level)
        .format_timestamp_secs()
        .init();
}

/// Print the application banner
fn print_banner() {
    println!(
        "{}",
        "
███████╗██╗     ██╗   ██╗██╗  ██╗███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██╔════╝██║     ██║   ██║╚██╗██╔╝██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
█████╗  ██║     ██║   ██║ ╚███╔╝ █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
██╔══╝  ██║     ██║   ██║ ██╔██╗ ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
██║     ███████╗╚██████╔╝██╔╝ ██╗███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   
╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
"
        .cyan()
        .bold()
    );

    println!(
        "{}",
        format!("FluxEncrypt CLI v{}", env!("CARGO_PKG_VERSION")).bright_white()
    );
    println!("{}", "Secure encryption for files and data".bright_black());
    println!(
        "{}",
        format!(
            "Authors: {} | Organization: {}",
            "Wyatt Roersma, Claude Code, Codex", "ThreatFlux"
        )
        .bright_black()
    );
    println!();
}
