//! Benchmark command implementation.

use crate::commands::CommandResult;
use clap::Args;
use colored::*;
use fluxencrypt::{
    config::{Config, RsaKeySize},
    cryptum,
    keys::KeyPair,
    stream::FileStreamCipher,
};
use std::fs;
use std::io::Write;
use std::time::{Duration, Instant};

#[derive(Args)]
pub struct BenchmarkCommand {
    /// Number of iterations for each test
    #[arg(short, long, default_value = "5")]
    iterations: u32,

    /// Data sizes to test (in KB)
    #[arg(short, long, value_delimiter = ',', default_values = &["1", "10", "100", "1000"])]
    sizes: Vec<usize>,

    /// Key sizes to test
    #[arg(short, long, value_delimiter = ',', default_values = &["2048", "3072", "4096"])]
    key_sizes: Vec<u16>,

    /// Only run encryption benchmarks
    #[arg(long)]
    encrypt_only: bool,

    /// Only run decryption benchmarks
    #[arg(long)]
    decrypt_only: bool,

    /// Test streaming vs hybrid mode
    #[arg(long)]
    compare_modes: bool,

    /// Show detailed statistics
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug)]
struct BenchmarkResult {
    operation: String,
    key_size: u16,
    data_size_kb: usize,
    mean_duration: Duration,
    min_duration: Duration,
    max_duration: Duration,
    throughput_mbps: f64,
}

pub fn execute(cmd: BenchmarkCommand) -> CommandResult {
    println!(
        "{} Starting FluxEncrypt Benchmark Suite...",
        "🚀".blue().bold()
    );
    println!();

    if cmd.encrypt_only && cmd.decrypt_only {
        return Err(anyhow::anyhow!(
            "Cannot specify both --encrypt-only and --decrypt-only"
        ));
    }

    let mut results = Vec::new();

    // Generate test keys for different sizes
    println!("{} Generating test keys...", "🔑".yellow());
    let mut key_pairs = std::collections::HashMap::new();

    for &key_size in &cmd.key_sizes {
        let key_size_enum = match key_size {
            2048 => RsaKeySize::Rsa2048,
            3072 => RsaKeySize::Rsa3072,
            4096 => RsaKeySize::Rsa4096,
            _ => {
                eprintln!(
                    "{} Unsupported key size: {} (using 2048)",
                    "⚠".yellow(),
                    key_size
                );
                RsaKeySize::Rsa2048
            }
        };

        let keypair = KeyPair::generate(key_size_enum.into())?;
        let private_key = keypair.private_key().clone();
        let public_key = keypair.public_key().clone();
        key_pairs.insert(key_size, (private_key, public_key));

        if cmd.verbose {
            println!("  {} Generated {}-bit key pair", "✓".green(), key_size);
        }
    }

    println!("{} Running benchmarks...", "⏱".cyan());
    println!(
        "  {} Iterations per test: {}",
        "🔄".blue(),
        cmd.iterations.to_string().cyan()
    );
    println!(
        "  {} Data sizes: {} KB",
        "📊".blue(),
        cmd.sizes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .cyan()
    );
    println!(
        "  {} Key sizes: {} bits",
        "🔑".yellow(),
        cmd.key_sizes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .cyan()
    );
    println!();

    // Run benchmarks
    for &key_size in &cmd.key_sizes {
        let (private_key, public_key) = key_pairs.get(&key_size).unwrap();

        println!("{} Testing {}-bit keys:", "🧪".magenta().bold(), key_size);

        for &size_kb in &cmd.sizes {
            let data_size = size_kb * 1024;

            // Generate test data
            let test_data = generate_test_data(data_size);

            // Test encryption
            if !cmd.decrypt_only {
                let result = benchmark_encryption(
                    &test_data,
                    public_key,
                    key_size,
                    size_kb,
                    cmd.iterations,
                    cmd.verbose,
                )?;
                results.push(result);

                if cmd.compare_modes && size_kb >= 1000 {
                    let result = benchmark_streaming_encryption(
                        &test_data,
                        public_key,
                        key_size,
                        size_kb,
                        cmd.iterations,
                        cmd.verbose,
                    )?;
                    results.push(result);
                }
            }

            // Test decryption (need to encrypt first)
            if !cmd.encrypt_only {
                let cryptum = cryptum()?;
                let encrypted_data = cryptum.encrypt(public_key, &test_data)?;

                let result = benchmark_decryption(
                    &encrypted_data,
                    private_key,
                    key_size,
                    size_kb,
                    cmd.iterations,
                    cmd.verbose,
                )?;
                results.push(result);
            }
        }

        println!();
    }

    // Display results
    display_benchmark_results(&results, cmd.verbose);

    Ok(())
}

fn benchmark_encryption(
    data: &[u8],
    public_key: &fluxencrypt::keys::PublicKey,
    key_size: u16,
    data_size_kb: usize,
    iterations: u32,
    verbose: bool,
) -> anyhow::Result<BenchmarkResult> {
    let cryptum = cryptum()?;
    let mut durations = Vec::new();

    if verbose {
        print!("  {} Encrypting {} KB... ", "🔒".green(), data_size_kb);
        std::io::stdout().flush().unwrap();
    }

    for i in 0..iterations {
        let start = Instant::now();
        let _encrypted = cryptum.encrypt(public_key, data)?;
        let duration = start.elapsed();
        durations.push(duration);

        if verbose && i == 0 {
            print!("{:.2}ms ", duration.as_millis());
            std::io::stdout().flush().unwrap();
        }
    }

    if verbose {
        println!("✓");
    }

    let mean_duration = Duration::from_nanos(
        (durations.iter().map(|d| d.as_nanos()).sum::<u128>() / iterations as u128) as u64,
    );
    let min_duration = *durations.iter().min().unwrap();
    let max_duration = *durations.iter().max().unwrap();

    let throughput_mbps = (data_size_kb as f64 / 1024.0) / mean_duration.as_secs_f64();

    Ok(BenchmarkResult {
        operation: "Hybrid Encrypt".to_string(),
        key_size,
        data_size_kb,
        mean_duration,
        min_duration,
        max_duration,
        throughput_mbps,
    })
}

fn benchmark_streaming_encryption(
    data: &[u8],
    public_key: &fluxencrypt::keys::PublicKey,
    key_size: u16,
    data_size_kb: usize,
    iterations: u32,
    verbose: bool,
) -> anyhow::Result<BenchmarkResult> {
    let config = Config::default();
    let cipher = FileStreamCipher::new(config);
    let mut durations = Vec::new();

    if verbose {
        print!(
            "  {} Stream encrypting {} KB... ",
            "🌊".blue(),
            data_size_kb
        );
        std::io::stdout().flush().unwrap();
    }

    for i in 0..iterations {
        // Create temporary files
        let temp_dir = std::env::temp_dir();
        let input_path = temp_dir.join(format!("bench_input_{}", i));
        let output_path = temp_dir.join(format!("bench_output_{}", i));

        fs::write(&input_path, data)?;

        let start = Instant::now();
        let _bytes = cipher.encrypt_file(
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            public_key,
            None,
        )?;

        // Cleanup
        let _ = fs::remove_file(input_path);
        let _ = fs::remove_file(output_path);
        let duration = start.elapsed();
        durations.push(duration);

        if verbose && i == 0 {
            print!("{:.2}ms ", duration.as_millis());
            std::io::stdout().flush().unwrap();
        }
    }

    if verbose {
        println!("✓");
    }

    let mean_duration = Duration::from_nanos(
        (durations.iter().map(|d| d.as_nanos()).sum::<u128>() / iterations as u128) as u64,
    );
    let min_duration = *durations.iter().min().unwrap();
    let max_duration = *durations.iter().max().unwrap();

    let throughput_mbps = (data_size_kb as f64 / 1024.0) / mean_duration.as_secs_f64();

    Ok(BenchmarkResult {
        operation: "Stream Encrypt".to_string(),
        key_size,
        data_size_kb,
        mean_duration,
        min_duration,
        max_duration,
        throughput_mbps,
    })
}

fn benchmark_decryption(
    encrypted_data: &[u8],
    private_key: &fluxencrypt::keys::PrivateKey,
    key_size: u16,
    data_size_kb: usize,
    iterations: u32,
    verbose: bool,
) -> anyhow::Result<BenchmarkResult> {
    let cryptum = cryptum()?;
    let mut durations = Vec::new();

    if verbose {
        print!("  {} Decrypting {} KB... ", "🔓".yellow(), data_size_kb);
        std::io::stdout().flush().unwrap();
    }

    for i in 0..iterations {
        let start = Instant::now();
        let _decrypted = cryptum.decrypt(private_key, encrypted_data)?;
        let duration = start.elapsed();
        durations.push(duration);

        if verbose && i == 0 {
            print!("{:.2}ms ", duration.as_millis());
            std::io::stdout().flush().unwrap();
        }
    }

    if verbose {
        println!("✓");
    }

    let mean_duration = Duration::from_nanos(
        (durations.iter().map(|d| d.as_nanos()).sum::<u128>() / iterations as u128) as u64,
    );
    let min_duration = *durations.iter().min().unwrap();
    let max_duration = *durations.iter().max().unwrap();

    let throughput_mbps = (data_size_kb as f64 / 1024.0) / mean_duration.as_secs_f64();

    Ok(BenchmarkResult {
        operation: "Decrypt".to_string(),
        key_size,
        data_size_kb,
        mean_duration,
        min_duration,
        max_duration,
        throughput_mbps,
    })
}

fn generate_test_data(size: usize) -> Vec<u8> {
    // Generate pseudo-random data for testing
    let mut data = Vec::with_capacity(size);
    let mut state = 12345u64;

    for _ in 0..size {
        // Simple LCG for reproducible "random" data
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        data.push((state >> 16) as u8);
    }

    data
}

fn display_benchmark_results(results: &[BenchmarkResult], verbose: bool) {
    println!("{} Benchmark Results:", "📊".blue().bold());
    println!();

    // Group by operation and key size
    let mut grouped_results = std::collections::HashMap::new();

    for result in results {
        let key = (&result.operation, result.key_size);
        grouped_results
            .entry(key)
            .or_insert_with(Vec::new)
            .push(result);
    }

    for ((operation, key_size), group) in grouped_results {
        println!(
            "{} {} ({}-bit key):",
            "🔧".cyan().bold(),
            operation,
            key_size
        );
        println!();

        // Print table header
        if verbose {
            println!(
                "  {:<8} {:<12} {:<12} {:<12} {:<12}",
                "Size".bold(),
                "Mean".bold(),
                "Min".bold(),
                "Max".bold(),
                "Throughput".bold()
            );
            println!(
                "  {:<8} {:<12} {:<12} {:<12} {:<12}",
                "----".dimmed(),
                "----".dimmed(),
                "---".dimmed(),
                "---".dimmed(),
                "----------".dimmed()
            );
        } else {
            println!(
                "  {:<8} {:<12} {:<12}",
                "Size".bold(),
                "Duration".bold(),
                "Throughput".bold()
            );
            println!(
                "  {:<8} {:<12} {:<12}",
                "----".dimmed(),
                "--------".dimmed(),
                "----------".dimmed()
            );
        }

        // Sort by data size
        let mut sorted_group = group.clone();
        sorted_group.sort_by_key(|r| r.data_size_kb);

        for result in sorted_group {
            if verbose {
                println!(
                    "  {:<8} {:<12} {:<12} {:<12} {:<12}",
                    format!("{} KB", result.data_size_kb).cyan(),
                    format!("{:.1}ms", result.mean_duration.as_millis()).yellow(),
                    format!("{:.1}ms", result.min_duration.as_millis()).green(),
                    format!("{:.1}ms", result.max_duration.as_millis()).red(),
                    format!("{:.1} MB/s", result.throughput_mbps).magenta(),
                );
            } else {
                println!(
                    "  {:<8} {:<12} {:<12}",
                    format!("{} KB", result.data_size_kb).cyan(),
                    format!("{:.1}ms", result.mean_duration.as_millis()).yellow(),
                    format!("{:.1} MB/s", result.throughput_mbps).magenta(),
                );
            }
        }

        println!();
    }

    // Summary statistics
    if !results.is_empty() {
        let total_ops = results.len();
        let avg_throughput =
            results.iter().map(|r| r.throughput_mbps).sum::<f64>() / total_ops as f64;

        println!("{} Summary:", "📈".green().bold());
        println!(
            "  {} Total operations: {}",
            "🔢".blue(),
            total_ops.to_string().cyan()
        );
        println!(
            "  {} Average throughput: {:.1} MB/s",
            "📊".purple(),
            avg_throughput.to_string().cyan()
        );

        if let Some(fastest) = results
            .iter()
            .max_by(|a, b| a.throughput_mbps.partial_cmp(&b.throughput_mbps).unwrap())
        {
            println!(
                "  {} Fastest operation: {} {} KB ({:.1} MB/s)",
                "🚀".green(),
                fastest.operation.green(),
                fastest.data_size_kb.to_string().cyan(),
                fastest.throughput_mbps.to_string().cyan()
            );
        }
    }
}
