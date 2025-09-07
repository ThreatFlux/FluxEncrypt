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
    validate_command_args(&cmd)?;
    print_benchmark_header(&cmd);

    let key_pairs = generate_test_keys(&cmd.key_sizes, cmd.verbose)?;
    let results = run_all_benchmarks(&cmd, &key_pairs)?;

    display_benchmark_results(&results, cmd.verbose);
    Ok(())
}

/// Validate command line arguments
fn validate_command_args(cmd: &BenchmarkCommand) -> CommandResult {
    if cmd.encrypt_only && cmd.decrypt_only {
        return Err(anyhow::anyhow!(
            "Cannot specify both --encrypt-only and --decrypt-only"
        ));
    }
    Ok(())
}

/// Print benchmark header information
fn print_benchmark_header(cmd: &BenchmarkCommand) {
    println!(
        "{} Starting FluxEncrypt Benchmark Suite...",
        "🚀".blue().bold()
    );
    println!();

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
}

/// Generate test key pairs for different sizes
fn generate_test_keys(
    key_sizes: &[u16],
    verbose: bool,
) -> anyhow::Result<
    std::collections::HashMap<u16, (fluxencrypt::keys::PrivateKey, fluxencrypt::keys::PublicKey)>,
> {
    println!("{} Generating test keys...", "🔑".yellow());
    let mut key_pairs = std::collections::HashMap::new();

    for &key_size in key_sizes {
        let key_size_enum = parse_key_size(key_size);
        let keypair = KeyPair::generate(key_size_enum.into())?;
        let private_key = keypair.private_key().clone();
        let public_key = keypair.public_key().clone();
        key_pairs.insert(key_size, (private_key, public_key));

        if verbose {
            println!("  {} Generated {}-bit key pair", "✓".green(), key_size);
        }
    }

    Ok(key_pairs)
}

/// Parse key size with fallback
fn parse_key_size(key_size: u16) -> RsaKeySize {
    match key_size {
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
    }
}

/// Run all benchmark tests
fn run_all_benchmarks(
    cmd: &BenchmarkCommand,
    key_pairs: &std::collections::HashMap<
        u16,
        (fluxencrypt::keys::PrivateKey, fluxencrypt::keys::PublicKey),
    >,
) -> anyhow::Result<Vec<BenchmarkResult>> {
    let mut results = Vec::new();

    for &key_size in &cmd.key_sizes {
        let (private_key, public_key) = key_pairs.get(&key_size).unwrap();
        println!("{} Testing {}-bit keys:", "🧪".magenta().bold(), key_size);

        for &size_kb in &cmd.sizes {
            let test_data = generate_test_data(size_kb * 1024);

            run_encryption_benchmarks(
                cmd,
                &test_data,
                public_key,
                key_size,
                size_kb,
                &mut results,
            )?;

            run_decryption_benchmarks(
                cmd,
                &test_data,
                public_key,
                private_key,
                key_size,
                size_kb,
                &mut results,
            )?;
        }

        println!();
    }

    Ok(results)
}

/// Run encryption benchmarks for a data size
fn run_encryption_benchmarks(
    cmd: &BenchmarkCommand,
    test_data: &[u8],
    public_key: &fluxencrypt::keys::PublicKey,
    key_size: u16,
    size_kb: usize,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    if cmd.decrypt_only {
        return Ok(());
    }

    let result = benchmark_encryption(
        test_data,
        public_key,
        key_size,
        size_kb,
        cmd.iterations,
        cmd.verbose,
    )?;
    results.push(result);

    if cmd.compare_modes && size_kb >= 1000 {
        let result = benchmark_streaming_encryption(
            test_data,
            public_key,
            key_size,
            size_kb,
            cmd.iterations,
            cmd.verbose,
        )?;
        results.push(result);
    }

    Ok(())
}

/// Run decryption benchmarks for a data size
fn run_decryption_benchmarks(
    cmd: &BenchmarkCommand,
    test_data: &[u8],
    public_key: &fluxencrypt::keys::PublicKey,
    private_key: &fluxencrypt::keys::PrivateKey,
    key_size: u16,
    size_kb: usize,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    if cmd.encrypt_only {
        return Ok(());
    }

    let cryptum = cryptum()?;
    let encrypted_data = cryptum.encrypt(public_key, test_data)?;

    let result = benchmark_decryption(
        &encrypted_data,
        private_key,
        key_size,
        size_kb,
        cmd.iterations,
        cmd.verbose,
    )?;
    results.push(result);

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

    print_streaming_header(verbose, data_size_kb);

    for i in 0..iterations {
        let duration = run_streaming_iteration(data, public_key, &cipher, i)?;
        durations.push(duration);

        if verbose && i == 0 {
            print_first_iteration_time(duration);
        }
    }

    if verbose {
        println!("✓");
    }

    let stats = calculate_duration_stats(&durations, iterations);
    let throughput_mbps = calculate_throughput(data_size_kb, stats.mean_duration);

    Ok(BenchmarkResult {
        operation: "Stream Encrypt".to_string(),
        key_size,
        data_size_kb,
        mean_duration: stats.mean_duration,
        min_duration: stats.min_duration,
        max_duration: stats.max_duration,
        throughput_mbps,
    })
}

/// Print streaming encryption header
fn print_streaming_header(verbose: bool, data_size_kb: usize) {
    if verbose {
        print!(
            "  {} Stream encrypting {} KB... ",
            "🌊".blue(),
            data_size_kb
        );
        std::io::stdout().flush().unwrap();
    }
}

/// Run a single streaming encryption iteration
fn run_streaming_iteration(
    data: &[u8],
    public_key: &fluxencrypt::keys::PublicKey,
    cipher: &FileStreamCipher,
    iteration: u32,
) -> anyhow::Result<Duration> {
    let temp_files = create_secure_temp_files(iteration)?;

    fs::write(&temp_files.input_path, data)?;

    let start = Instant::now();
    let _bytes = cipher.encrypt_file(
        temp_files.input_path.to_str().unwrap(),
        temp_files.output_path.to_str().unwrap(),
        public_key,
        None,
    )?;

    cleanup_temp_files(&temp_files);
    Ok(start.elapsed())
}

/// Create secure temporary files
struct TempFiles {
    input_path: std::path::PathBuf,
    output_path: std::path::PathBuf,
}

fn create_secure_temp_files(iteration: u32) -> anyhow::Result<TempFiles> {
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Create a secure temporary directory with process ID and timestamp to avoid collisions
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = process::id();
    let unique_id = format!(
        "{}_{}_{}_{}",
        "fluxencrypt_bench", pid, timestamp, iteration
    );

    let temp_dir = std::env::temp_dir().join(unique_id);
    fs::create_dir_all(&temp_dir)?;

    let input_path = temp_dir.join("input.dat");
    let output_path = temp_dir.join("output.enc");

    Ok(TempFiles {
        input_path,
        output_path,
    })
}

/// Clean up temporary files and directory
fn cleanup_temp_files(temp_files: &TempFiles) {
    let _ = fs::remove_file(&temp_files.input_path);
    let _ = fs::remove_file(&temp_files.output_path);

    // Try to remove the temporary directory
    if let Some(parent) = temp_files.input_path.parent() {
        let _ = fs::remove_dir(parent);
    }
}

/// Print first iteration timing info
fn print_first_iteration_time(duration: Duration) {
    print!("{:.2}ms ", duration.as_millis());
    std::io::stdout().flush().unwrap();
}

/// Duration statistics
struct DurationStats {
    mean_duration: Duration,
    min_duration: Duration,
    max_duration: Duration,
}

/// Calculate duration statistics
fn calculate_duration_stats(durations: &[Duration], iterations: u32) -> DurationStats {
    let mean_duration = Duration::from_nanos(
        (durations.iter().map(|d| d.as_nanos()).sum::<u128>() / iterations as u128) as u64,
    );
    let min_duration = *durations.iter().min().unwrap();
    let max_duration = *durations.iter().max().unwrap();

    DurationStats {
        mean_duration,
        min_duration,
        max_duration,
    }
}

/// Calculate throughput in MB/s
fn calculate_throughput(data_size_kb: usize, mean_duration: Duration) -> f64 {
    (data_size_kb as f64 / 1024.0) / mean_duration.as_secs_f64()
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

    let grouped_results = group_results_by_operation_and_key_size(results);

    for ((operation, key_size), group) in grouped_results {
        display_operation_results(operation, key_size, &group, verbose);
    }

    display_summary_statistics(results);
}

/// Group results by operation and key size
fn group_results_by_operation_and_key_size(
    results: &[BenchmarkResult],
) -> std::collections::HashMap<(&String, u16), Vec<&BenchmarkResult>> {
    let mut grouped_results = std::collections::HashMap::new();

    for result in results {
        let key = (&result.operation, result.key_size);
        grouped_results
            .entry(key)
            .or_insert_with(Vec::new)
            .push(result);
    }

    grouped_results
}

/// Display results for a specific operation and key size
fn display_operation_results(
    operation: &str,
    key_size: u16,
    group: &[&BenchmarkResult],
    verbose: bool,
) {
    println!(
        "{} {} ({}-bit key):",
        "🔧".cyan().bold(),
        operation,
        key_size
    );
    println!();

    print_table_header(verbose);
    print_operation_data(group, verbose);
    println!();
}

/// Print table header based on verbosity
fn print_table_header(verbose: bool) {
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
}

/// Print data for an operation group
fn print_operation_data(group: &[&BenchmarkResult], verbose: bool) {
    let mut sorted_group = group.to_vec();
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
}

/// Display summary statistics
fn display_summary_statistics(results: &[BenchmarkResult]) {
    if results.is_empty() {
        return;
    }

    let total_ops = results.len();
    let avg_throughput = calculate_average_throughput(results, total_ops);
    let fastest_operation = find_fastest_operation(results);

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

    if let Some(fastest) = fastest_operation {
        println!(
            "  {} Fastest operation: {} {} KB ({:.1} MB/s)",
            "🚀".green(),
            fastest.operation.green(),
            fastest.data_size_kb.to_string().cyan(),
            fastest.throughput_mbps.to_string().cyan()
        );
    }
}

/// Calculate average throughput
fn calculate_average_throughput(results: &[BenchmarkResult], total_ops: usize) -> f64 {
    results.iter().map(|r| r.throughput_mbps).sum::<f64>() / total_ops as f64
}

/// Find the fastest operation
fn find_fastest_operation(results: &[BenchmarkResult]) -> Option<&BenchmarkResult> {
    results
        .iter()
        .max_by(|a, b| a.throughput_mbps.partial_cmp(&b.throughput_mbps).unwrap())
}
