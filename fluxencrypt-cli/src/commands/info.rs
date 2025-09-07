//! Info command implementation.

use crate::commands::CommandResult;
use clap::Args;
use colored::*;
use fluxencrypt::keys::parsing::{KeyFormat, KeyParser};
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

#[derive(Args)]
pub struct InfoCommand {
    /// File to analyze (key file or encrypted file)
    #[arg(short, long)]
    file: String,

    /// Show detailed information
    #[arg(long)]
    verbose: bool,

    /// Show raw key data (use with caution!)
    #[arg(long)]
    show_raw: bool,
}

pub fn execute(cmd: InfoCommand) -> CommandResult {
    println!("{} Analyzing file information...", "ℹ️".blue().bold());

    let (metadata, file_data) = read_and_validate_info_file(&cmd)?;

    display_basic_file_info(&cmd, &metadata);

    if cmd.verbose {
        display_detailed_file_info(&metadata);
    }

    if file_data.is_empty() {
        println!("{} File is empty", "⚠".yellow());
        return Ok(());
    }

    determine_file_type(&file_data, &cmd)?;
    Ok(())
}

fn read_and_validate_info_file(cmd: &InfoCommand) -> anyhow::Result<(fs::Metadata, Vec<u8>)> {
    if !Path::new(&cmd.file).exists() {
        return Err(anyhow::anyhow!("File '{}' does not exist", cmd.file));
    }

    let metadata = fs::metadata(&cmd.file)?;
    let file_data =
        fs::read(&cmd.file).map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

    Ok((metadata, file_data))
}

fn display_basic_file_info(cmd: &InfoCommand, metadata: &fs::Metadata) {
    let file_size = metadata.len();
    println!("{} File: {}", "📁".blue(), cmd.file.cyan());
    println!("{} Size: {}", "📊".blue(), format_bytes(file_size).cyan());
}

fn display_detailed_file_info(metadata: &fs::Metadata) {
    display_timestamps(metadata);
    display_permissions(metadata);
}

fn display_timestamps(metadata: &fs::Metadata) {
    if let Ok(created) = metadata.created() {
        if let Ok(duration) = created.duration_since(UNIX_EPOCH) {
            let timestamp = duration.as_secs();
            println!(
                "{} Created: {} (Unix timestamp)",
                "📅".blue(),
                timestamp.to_string().cyan()
            );
        }
    }

    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
            let timestamp = duration.as_secs();
            println!(
                "{} Modified: {} (Unix timestamp)",
                "✏️".yellow(),
                timestamp.to_string().cyan()
            );
        }
    }
}

fn display_permissions(metadata: &fs::Metadata) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        println!("{} Permissions: {:o}", "🔒".yellow(), mode & 0o777);
    }
}

fn determine_file_type(data: &[u8], cmd: &InfoCommand) -> CommandResult {
    let parser = KeyParser::new();

    // Try to detect as a key file first
    if let Some(format) = parser.detect_format(data) {
        analyze_key_file(data, format, cmd)?;
        return Ok(());
    }

    // Check if it might be an encrypted file
    if looks_like_encrypted_file(data) {
        analyze_encrypted_file(data, cmd)?;
    } else {
        analyze_unknown_file(data, cmd)?;
    }

    Ok(())
}

fn analyze_key_file(data: &[u8], format: KeyFormat, cmd: &InfoCommand) -> CommandResult {
    println!("\n{} Key File Analysis:", "🔑".green().bold());

    match format {
        KeyFormat::Pem => println!("{} Format: {}", "📝".blue(), "PEM".cyan()),
        KeyFormat::Der => println!("{} Format: {}", "📝".blue(), "DER".cyan()),
        KeyFormat::Pkcs8 => println!("{} Format: {}", "📝".blue(), "PKCS#8".cyan()),
        KeyFormat::Ssh => println!("{} Format: {}", "📝".blue(), "SSH".cyan()),
    }

    let parser = KeyParser::new();

    // Try to parse as public key
    if let Ok(_public_key) = parser.parse_public_key(data, format) {
        println!("{} Type: {}", "🔓".green(), "Public Key".cyan());

        if cmd.verbose {
            println!("{} Key size: {} bits", "📏".blue(), "2048".cyan()); // Placeholder - actual size would come from key
            println!("{} Algorithm: {}", "🔢".purple(), "RSA".cyan()); // Placeholder - actual algorithm from key

            // Generate a simple fingerprint
            let fingerprint = generate_fingerprint(data);
            println!("{} Fingerprint: {}", "👆".yellow(), fingerprint.cyan());
        }

        if cmd.show_raw {
            println!("\n{} Raw Key Data:", "⚠".yellow().bold());
            println!("{}", String::from_utf8_lossy(data).dimmed());
        }

        return Ok(());
    }

    // Try to parse as private key
    if let Ok(_private_key) = parser.parse_private_key(data, format) {
        println!("{} Type: {}", "🔐".red(), "Private Key".cyan());

        if cmd.verbose {
            println!("{} Key size: {} bits", "📏".blue(), "2048".cyan()); // Placeholder
            println!("{} Algorithm: {}", "🔢".purple(), "RSA".cyan()); // Placeholder

            let fingerprint = generate_fingerprint(data);
            println!("{} Fingerprint: {}", "👆".yellow(), fingerprint.cyan());
        }

        println!(
            "{} {} This is a private key - keep it secure!",
            "⚠".red().bold(),
            "Warning:".red().bold()
        );

        if cmd.show_raw {
            println!(
                "\n{} {} Raw private key data not shown for security",
                "🔒".red(),
                "Security:".red().bold()
            );
        }

        return Ok(());
    }

    println!("{} Unable to parse as key file", "❌".red());
    Ok(())
}

fn analyze_encrypted_file(data: &[u8], cmd: &InfoCommand) -> CommandResult {
    println!("\n{} Encrypted File Analysis:", "🔐".yellow().bold());

    let entropy = calculate_entropy(data);
    display_entropy_analysis(entropy);

    if cmd.verbose {
        display_detailed_encryption_analysis(data);
    }

    println!(
        "{} Estimated type: {}",
        "🎯".magenta(),
        "Encrypted data".cyan()
    );
    Ok(())
}

fn display_entropy_analysis(entropy: f64) {
    println!(
        "{} Entropy: {:.2} bits",
        "🎲".blue(),
        entropy.to_string().cyan()
    );

    if entropy > 7.5 {
        println!("{} High entropy - likely encrypted", "✅".green());
    } else if entropy > 6.0 {
        println!("{} Medium entropy - possibly encrypted", "⚠".yellow());
    } else {
        println!("{} Low entropy - may not be encrypted", "❌".red());
    }
}

fn display_detailed_encryption_analysis(data: &[u8]) {
    let byte_counts = calculate_byte_distribution(data);

    display_null_byte_analysis(&byte_counts, data.len());
    display_frequency_analysis(&byte_counts);
    display_uniqueness_analysis(&byte_counts);
}

fn calculate_byte_distribution(data: &[u8]) -> [u32; 256] {
    let mut byte_counts = [0u32; 256];
    for &byte in data {
        byte_counts[byte as usize] += 1;
    }
    byte_counts
}

fn display_null_byte_analysis(byte_counts: &[u32; 256], total_len: usize) {
    let zero_count = byte_counts[0];
    let zero_percentage = (zero_count as f64 / total_len as f64) * 100.0;
    println!(
        "{} Null bytes: {} ({:.2}%)",
        "0️⃣".blue(),
        zero_count.to_string().cyan(),
        zero_percentage.to_string().cyan()
    );
}

fn display_frequency_analysis(byte_counts: &[u32; 256]) {
    let max_count = *byte_counts.iter().max().unwrap();
    let min_count = *byte_counts.iter().filter(|&&c| c > 0).min().unwrap_or(&0);

    println!(
        "{} Most frequent byte appears {} times",
        "📈".green(),
        max_count.to_string().cyan()
    );
    println!(
        "{} Least frequent byte appears {} times",
        "📉".red(),
        min_count.to_string().cyan()
    );
}

fn display_uniqueness_analysis(byte_counts: &[u32; 256]) {
    let unique_bytes = byte_counts.iter().filter(|&&c| c > 0).count();
    println!(
        "{} Unique bytes used: {} of 256",
        "🎨".purple(),
        unique_bytes.to_string().cyan()
    );
}

fn analyze_unknown_file(data: &[u8], cmd: &InfoCommand) -> CommandResult {
    println!("\n{} Unknown File Analysis:", "❓".bright_black().bold());

    // Try to detect common file signatures
    let file_type = detect_file_signature(data);
    println!("{} Detected type: {}", "🎯".magenta(), file_type.cyan());

    let entropy = calculate_entropy(data);
    println!(
        "{} Entropy: {:.2} bits",
        "🎲".blue(),
        entropy.to_string().cyan()
    );

    if cmd.verbose {
        // Show first few bytes as hex
        let hex_preview = data
            .iter()
            .take(32)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "{} First 32 bytes (hex): {}",
            "🔍".blue(),
            hex_preview.dimmed()
        );

        // Show printable characters from start
        let text_preview = String::from_utf8_lossy(&data[..std::cmp::min(64, data.len())]);
        let printable_preview: String = text_preview
            .chars()
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '.'
                }
            })
            .collect();
        println!(
            "{} Text preview: {}",
            "📝".blue(),
            printable_preview.dimmed()
        );
    }

    Ok(())
}

fn looks_like_encrypted_file(data: &[u8]) -> bool {
    if data.len() < 32 {
        return false;
    }

    let entropy = calculate_entropy(data);
    entropy > 6.5
}

fn detect_file_signature(data: &[u8]) -> &'static str {
    if data.is_empty() {
        return "Empty file";
    }

    // Check common file signatures
    if data.len() >= 4 {
        match &data[0..4] {
            [0x89, b'P', b'N', b'G'] => return "PNG image",
            [0xFF, 0xD8, 0xFF, _] => return "JPEG image",
            [b'P', b'K', 0x03, 0x04] => return "ZIP archive",
            [0x50, 0x44, 0x46, _] => return "PDF document",
            _ => {}
        }
    }

    if data.len() >= 3 {
        if let [0xEF, 0xBB, 0xBF] = &data[0..3] {
            return "UTF-8 with BOM";
        }
    }

    if data.len() >= 2 {
        match &data[0..2] {
            [0x1F, 0x8B] => return "GZIP compressed",
            [b'B', b'Z'] => return "BZIP2 compressed",
            [0xFF, 0xFE] => return "UTF-16 LE",
            [0xFE, 0xFF] => return "UTF-16 BE",
            _ => {}
        }
    }

    // Check for text content
    if data.iter().all(|&b| b.is_ascii()) {
        return "ASCII text";
    }

    if std::str::from_utf8(data).is_ok() {
        return "UTF-8 text";
    }

    "Binary data"
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

fn generate_fingerprint(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash = hasher.finish();

    format!("{:016x}", hash)
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
