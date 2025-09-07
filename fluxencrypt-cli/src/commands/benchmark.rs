//! Benchmark command implementation with modular, secure, and optimized design.

use crate::commands::CommandResult;
use clap::Args;
use colored::*;
use fluxencrypt::{
    config::{Config, RsaKeySize},
    cryptum,
    keys::{KeyPair, PrivateKey, PublicKey},
    stream::FileStreamCipher,
};
use std::collections::HashMap;
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

/// Secure temporary file management
struct SecureTempFiles {
    input_path: std::path::PathBuf,
    output_path: std::path::PathBuf,
}

impl SecureTempFiles {
    fn new(iteration: u32) -> anyhow::Result<Self> {
        use std::process;
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let pid = process::id();
        let unique_id = format!("fluxencrypt_bench_{}_{}_{}", pid, timestamp, iteration);

        // Use a more secure approach to create temporary directory
        let temp_dir = Self::create_secure_temp_dir(&unique_id)?;

        Ok(Self {
            input_path: temp_dir.join("input.dat"),
            output_path: temp_dir.join("output.enc"),
        })
    }

    /// Creates a secure temporary directory with proper permissions and ownership
    fn create_secure_temp_dir(unique_id: &str) -> anyhow::Result<std::path::PathBuf> {
        // Try to use XDG runtime directory first (Linux/Unix), fallback to system temp
        let base_dir = std::env::var("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .or_else(|_: std::env::VarError| {
                // Fallback to creating our own secure directory
                #[cfg(unix)]
                {
                    Ok::<std::path::PathBuf, std::env::VarError>(std::path::PathBuf::from("/tmp"))
                }
                #[cfg(not(unix))]
                {
                    Ok::<std::path::PathBuf, std::env::VarError>(std::env::temp_dir())
                }
            })?;

        let temp_dir = base_dir.join(unique_id);

        // Create directory with secure permissions from the start
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&temp_dir)?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(&temp_dir)?;
        }

        Ok(temp_dir)
    }
}

impl Drop for SecureTempFiles {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.input_path);
        let _ = fs::remove_file(&self.output_path);
        if let Some(parent) = self.input_path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
}

pub fn execute(cmd: BenchmarkCommand) -> CommandResult {
    validate_args(&cmd)?;
    print_header(&cmd);

    let key_pairs = generate_keys(&cmd.key_sizes, cmd.verbose)?;
    let results = run_benchmarks(&cmd, &key_pairs)?;

    display_results(&results, cmd.verbose);
    Ok(())
}

fn validate_args(cmd: &BenchmarkCommand) -> CommandResult {
    if cmd.encrypt_only && cmd.decrypt_only {
        return Err(anyhow::anyhow!(
            "Cannot specify both --encrypt-only and --decrypt-only"
        ));
    }
    Ok(())
}

fn print_header(cmd: &BenchmarkCommand) {
    println!(
        "{} Starting FluxEncrypt Benchmark Suite...",
        "🚀".blue().bold()
    );
    println!("\n{} Configuration:", "⏱".cyan());
    println!(
        "  {} Iterations: {}",
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
        "  {} Key sizes: {} bits\n",
        "🔑".yellow(),
        cmd.key_sizes
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
            .cyan()
    );
}

fn generate_keys(
    key_sizes: &[u16],
    verbose: bool,
) -> anyhow::Result<HashMap<u16, (PrivateKey, PublicKey)>> {
    println!("{} Generating test keys...", "🔑".yellow());
    let mut key_pairs = HashMap::new();

    for &key_size in key_sizes {
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
        key_pairs.insert(
            key_size,
            (keypair.private_key().clone(), keypair.public_key().clone()),
        );

        if verbose {
            println!("  {} Generated {}-bit key pair", "✓".green(), key_size);
        }
    }
    Ok(key_pairs)
}

fn run_benchmarks(
    cmd: &BenchmarkCommand,
    key_pairs: &HashMap<u16, (PrivateKey, PublicKey)>,
) -> anyhow::Result<Vec<BenchmarkResult>> {
    let mut results = Vec::new();

    for &key_size in &cmd.key_sizes {
        let (private_key, public_key) = key_pairs.get(&key_size).unwrap();
        println!("{} Testing {}-bit keys:", "🧪".magenta().bold(), key_size);

        run_key_size_benchmarks(cmd, private_key, public_key, key_size, &mut results)?;
        println!();
    }
    Ok(results)
}

fn run_key_size_benchmarks(
    cmd: &BenchmarkCommand,
    private_key: &PrivateKey,
    public_key: &PublicKey,
    key_size: u16,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    for &size_kb in &cmd.sizes {
        let test_data = generate_test_data(size_kb * 1024);

        run_encryption_benchmarks(cmd, &test_data, public_key, key_size, size_kb, results)?;
        run_decryption_benchmarks(
            cmd,
            &test_data,
            private_key,
            public_key,
            key_size,
            size_kb,
            results,
        )?;
    }
    Ok(())
}

fn run_encryption_benchmarks(
    cmd: &BenchmarkCommand,
    test_data: &[u8],
    public_key: &PublicKey,
    key_size: u16,
    size_kb: usize,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    if cmd.decrypt_only {
        return Ok(());
    }

    results.push(benchmark_hybrid_encrypt(
        test_data,
        public_key,
        key_size,
        size_kb,
        cmd.iterations,
        cmd.verbose,
    )?);

    if should_run_stream_encrypt(cmd, size_kb) {
        results.push(benchmark_stream_encrypt(
            test_data,
            public_key,
            key_size,
            size_kb,
            cmd.iterations,
            cmd.verbose,
        )?);
    }

    Ok(())
}

fn run_decryption_benchmarks(
    cmd: &BenchmarkCommand,
    test_data: &[u8],
    private_key: &PrivateKey,
    public_key: &PublicKey,
    key_size: u16,
    size_kb: usize,
    results: &mut Vec<BenchmarkResult>,
) -> anyhow::Result<()> {
    if cmd.encrypt_only {
        return Ok(());
    }

    let cryptum = cryptum()?;
    let encrypted_data = cryptum.encrypt(public_key, test_data)?;
    results.push(benchmark_decrypt(
        &encrypted_data,
        private_key,
        key_size,
        size_kb,
        cmd.iterations,
        cmd.verbose,
    )?);

    Ok(())
}

fn should_run_stream_encrypt(cmd: &BenchmarkCommand, size_kb: usize) -> bool {
    cmd.compare_modes && size_kb >= 1000
}

fn benchmark_hybrid_encrypt(
    data: &[u8],
    public_key: &PublicKey,
    key_size: u16,
    data_size_kb: usize,
    iterations: u32,
    verbose: bool,
) -> anyhow::Result<BenchmarkResult> {
    let cryptum = cryptum()?;
    let durations = time_iterations(
        iterations,
        verbose,
        "🔒",
        "Encrypting",
        data_size_kb,
        || Ok(cryptum.encrypt(public_key, data).map(|_| ())?),
    )?;

    Ok(create_result(
        "Hybrid Encrypt",
        key_size,
        data_size_kb,
        durations,
    ))
}

fn benchmark_stream_encrypt(
    data: &[u8],
    public_key: &PublicKey,
    key_size: u16,
    data_size_kb: usize,
    iterations: u32,
    verbose: bool,
) -> anyhow::Result<BenchmarkResult> {
    let cipher = FileStreamCipher::new(Config::default());
    let durations = time_iterations(
        iterations,
        verbose,
        "🌊",
        "Stream encrypting",
        data_size_kb,
        || {
            let temp_files = SecureTempFiles::new(0)?;
            fs::write(&temp_files.input_path, data)?;
            cipher
                .encrypt_file(
                    temp_files.input_path.to_str().unwrap(),
                    temp_files.output_path.to_str().unwrap(),
                    public_key,
                    None,
                )
                .map_err(|e| anyhow::anyhow!(e))?;
            Ok(())
        },
    )?;

    Ok(create_result(
        "Stream Encrypt",
        key_size,
        data_size_kb,
        durations,
    ))
}

fn benchmark_decrypt(
    encrypted_data: &[u8],
    private_key: &PrivateKey,
    key_size: u16,
    data_size_kb: usize,
    iterations: u32,
    verbose: bool,
) -> anyhow::Result<BenchmarkResult> {
    let cryptum = cryptum()?;
    let durations = time_iterations(
        iterations,
        verbose,
        "🔓",
        "Decrypting",
        data_size_kb,
        || Ok(cryptum.decrypt(private_key, encrypted_data).map(|_| ())?),
    )?;

    Ok(create_result("Decrypt", key_size, data_size_kb, durations))
}

fn time_iterations<F, R>(
    iterations: u32,
    verbose: bool,
    icon: &str,
    operation: &str,
    data_size_kb: usize,
    mut f: F,
) -> anyhow::Result<Vec<Duration>>
where
    F: FnMut() -> anyhow::Result<R>,
{
    let mut durations = Vec::new();

    if verbose {
        print!("  {} {} {} KB... ", icon.green(), operation, data_size_kb);
        std::io::stdout().flush().unwrap();
    }

    for i in 0..iterations {
        let start = Instant::now();
        f()?;
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
    Ok(durations)
}

fn create_result(
    operation: &str,
    key_size: u16,
    data_size_kb: usize,
    durations: Vec<Duration>,
) -> BenchmarkResult {
    let mean_duration = Duration::from_nanos(
        (durations.iter().map(|d| d.as_nanos()).sum::<u128>() / durations.len() as u128) as u64,
    );
    let min_duration = *durations.iter().min().unwrap();
    let max_duration = *durations.iter().max().unwrap();
    let throughput_mbps = (data_size_kb as f64 / 1024.0) / mean_duration.as_secs_f64();

    BenchmarkResult {
        operation: operation.to_string(),
        key_size,
        data_size_kb,
        mean_duration,
        min_duration,
        max_duration,
        throughput_mbps,
    }
}

fn generate_test_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut state = 12345u64;

    for _ in 0..size {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        data.push((state >> 16) as u8);
    }
    data
}

fn display_results(results: &[BenchmarkResult], verbose: bool) {
    println!("{} Benchmark Results:", "📊".blue().bold());
    let grouped = group_results_by_operation_and_key_size(results);

    display_grouped_results(&grouped, verbose);
    display_summary(results);
}

fn group_results_by_operation_and_key_size(
    results: &[BenchmarkResult],
) -> HashMap<(&String, u16), Vec<&BenchmarkResult>> {
    results.iter().fold(HashMap::new(), |mut acc, result| {
        acc.entry((&result.operation, result.key_size))
            .or_default()
            .push(result);
        acc
    })
}

fn display_grouped_results(
    grouped: &HashMap<(&String, u16), Vec<&BenchmarkResult>>,
    verbose: bool,
) {
    for ((operation, key_size), group) in grouped {
        display_operation_group(operation, *key_size, group, verbose);
    }
}

fn display_operation_group(
    operation: &str,
    key_size: u16,
    group: &[&BenchmarkResult],
    verbose: bool,
) {
    println!(
        "\n{} {} ({}-bit key):",
        "🔧".cyan().bold(),
        operation,
        key_size
    );

    print_table_header(verbose);

    let mut sorted_group = group.to_vec();
    sorted_group.sort_by_key(|r| r.data_size_kb);

    for result in sorted_group {
        print_result_row(result, verbose);
    }
}

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
    } else {
        println!(
            "  {:<8} {:<12} {:<12}",
            "Size".bold(),
            "Duration".bold(),
            "Throughput".bold()
        );
    }
}

fn print_result_row(result: &BenchmarkResult, verbose: bool) {
    if verbose {
        println!(
            "  {:<8} {:<12} {:<12} {:<12} {:<12}",
            format!("{} KB", result.data_size_kb).cyan(),
            format!("{:.1}ms", result.mean_duration.as_millis()).yellow(),
            format!("{:.1}ms", result.min_duration.as_millis()).green(),
            format!("{:.1}ms", result.max_duration.as_millis()).red(),
            format!("{:.1} MB/s", result.throughput_mbps).magenta()
        );
    } else {
        println!(
            "  {:<8} {:<12} {:<12}",
            format!("{} KB", result.data_size_kb).cyan(),
            format!("{:.1}ms", result.mean_duration.as_millis()).yellow(),
            format!("{:.1} MB/s", result.throughput_mbps).magenta()
        );
    }
}

fn display_summary(results: &[BenchmarkResult]) {
    if results.is_empty() {
        return;
    }

    let avg_throughput = calculate_average_throughput(results);
    let fastest = find_fastest_operation(results);

    println!("\n{} Summary:", "📈".green().bold());
    println!(
        "  {} Total operations: {}",
        "🔢".blue(),
        results.len().to_string().cyan()
    );
    println!(
        "  {} Average throughput: {:.1} MB/s",
        "📊".purple(),
        avg_throughput.to_string().cyan()
    );

    if let Some(fastest) = fastest {
        print_fastest_operation(fastest);
    }
}

fn calculate_average_throughput(results: &[BenchmarkResult]) -> f64 {
    results.iter().map(|r| r.throughput_mbps).sum::<f64>() / results.len() as f64
}

fn find_fastest_operation(results: &[BenchmarkResult]) -> Option<&BenchmarkResult> {
    results
        .iter()
        .max_by(|a, b| a.throughput_mbps.partial_cmp(&b.throughput_mbps).unwrap())
}

fn print_fastest_operation(fastest: &BenchmarkResult) {
    println!(
        "  {} Fastest operation: {} {} KB ({:.1} MB/s)",
        "🚀".green(),
        fastest.operation.green(),
        fastest.data_size_kb.to_string().cyan(),
        fastest.throughput_mbps.to_string().cyan()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxencrypt::keys::KeyPair;
    use std::fs;

    #[test]
    fn test_secure_temp_files_creation() {
        let temp_files = SecureTempFiles::new(0).unwrap();

        // Verify paths exist and are unique
        assert!(temp_files.input_path.parent().unwrap().exists());
        assert!(temp_files.output_path.parent().unwrap().exists());

        // Verify paths are different
        assert_ne!(temp_files.input_path, temp_files.output_path);

        // Verify directory names contain security-related elements
        let dir_name = temp_files
            .input_path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(dir_name.contains("fluxencrypt_bench"));
    }

    #[test]
    fn test_secure_temp_files_cleanup() {
        let temp_files = SecureTempFiles::new(1).unwrap();
        let temp_dir = temp_files.input_path.parent().unwrap().to_path_buf();

        // Create some test files
        fs::write(&temp_files.input_path, b"test data").unwrap();
        fs::write(&temp_files.output_path, b"output data").unwrap();

        assert!(temp_files.input_path.exists());
        assert!(temp_files.output_path.exists());
        assert!(temp_dir.exists());

        // Drop should trigger cleanup
        drop(temp_files);

        // Files should be removed (directory might still exist temporarily)
        assert!(!temp_dir.join("input.dat").exists());
        assert!(!temp_dir.join("output.enc").exists());
    }

    #[test]
    fn test_benchmark_command_validation() {
        let valid_cmd = BenchmarkCommand {
            iterations: 1,
            sizes: vec![1],
            key_sizes: vec![2048],
            encrypt_only: false,
            decrypt_only: false,
            compare_modes: false,
            verbose: false,
        };
        assert!(validate_args(&valid_cmd).is_ok());

        let invalid_cmd = BenchmarkCommand {
            iterations: 1,
            sizes: vec![1],
            key_sizes: vec![2048],
            encrypt_only: true,
            decrypt_only: true,
            compare_modes: false,
            verbose: false,
        };
        assert!(validate_args(&invalid_cmd).is_err());
    }

    #[test]
    fn test_generate_test_data() {
        let data1 = generate_test_data(1024);
        let data2 = generate_test_data(1024);

        assert_eq!(data1.len(), 1024);
        assert_eq!(data2.len(), 1024);

        // Should be deterministic
        assert_eq!(data1, data2);

        // Should not be all zeros
        assert!(data1.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_generate_keys() {
        let key_sizes = vec![2048];
        let keys = generate_keys(&key_sizes, false).unwrap();

        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key(&2048));

        let (private_key, public_key) = keys.get(&2048).unwrap();

        // Verify keys can encrypt/decrypt
        let cryptum = fluxencrypt::cryptum().unwrap();
        let test_data = b"test message";
        let encrypted = cryptum.encrypt(public_key, test_data).unwrap();
        let decrypted = cryptum.decrypt(private_key, &encrypted).unwrap();
        assert_eq!(test_data, &decrypted[..]);
    }

    #[test]
    fn test_create_result() {
        let durations = vec![
            Duration::from_millis(100),
            Duration::from_millis(150),
            Duration::from_millis(200),
        ];

        let result = create_result("Test Operation", 2048, 100, durations);

        assert_eq!(result.operation, "Test Operation");
        assert_eq!(result.key_size, 2048);
        assert_eq!(result.data_size_kb, 100);
        assert_eq!(result.min_duration, Duration::from_millis(100));
        assert_eq!(result.max_duration, Duration::from_millis(200));
        assert!(result.throughput_mbps > 0.0);
    }

    #[test]
    fn test_benchmark_hybrid_encrypt() {
        let keypair = KeyPair::generate(fluxencrypt::config::RsaKeySize::Rsa2048.into()).unwrap();
        let test_data = generate_test_data(1024);

        let result =
            benchmark_hybrid_encrypt(&test_data, keypair.public_key(), 2048, 1, 1, false).unwrap();

        assert_eq!(result.operation, "Hybrid Encrypt");
        assert_eq!(result.key_size, 2048);
        assert_eq!(result.data_size_kb, 1);
        assert!(result.mean_duration > Duration::from_nanos(0));
        assert!(result.throughput_mbps > 0.0);
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_temp_files_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_files = SecureTempFiles::new(2).unwrap();
        let temp_dir = temp_files.input_path.parent().unwrap();

        let perms = fs::metadata(temp_dir).unwrap().permissions();
        let mode = perms.mode();

        // Should have 0o700 permissions (owner read/write/execute only)
        assert_eq!(mode & 0o777, 0o700);
    }
}
