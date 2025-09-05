//! Comprehensive benchmark suite for FluxEncrypt encryption operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fluxencrypt::encryption::aes_gcm::{AesGcmCipher, AesKey};
use fluxencrypt::keys::KeyPair;
use fluxencrypt::stream::FileStreamCipher;
use fluxencrypt::{
    config::{CipherSuite, RsaKeySize},
    Config, Cryptum, HybridCipher,
};
use std::fs;
use tempfile::tempdir;

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    for &key_size in &[
        RsaKeySize::Rsa2048,
        RsaKeySize::Rsa3072,
        RsaKeySize::Rsa4096,
    ] {
        group.bench_with_input(
            BenchmarkId::new("rsa", format!("{}", usize::from(key_size))),
            &key_size,
            |b, &size| b.iter(|| KeyPair::generate(size.into())),
        );
    }

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let keypair = KeyPair::generate(2048).expect("Failed to generate keypair");

    let mut group = c.benchmark_group("encryption");

    // Test different data sizes
    for size in [1024, 8192, 65536, 1048576].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("hybrid", size), &data, |b, data| {
            let cipher = HybridCipher::new(Config::default());
            b.iter(|| cipher.encrypt(black_box(keypair.public_key()), black_box(data)))
        });
    }

    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let keypair = KeyPair::generate(2048).expect("Failed to generate keypair");
    let cipher = HybridCipher::new(Config::default());

    let mut group = c.benchmark_group("decryption");

    // Pre-encrypt data of different sizes
    let sizes = [1024, 8192, 65536, 1048576];
    let encrypted_data: Vec<_> = sizes
        .iter()
        .map(|&size| {
            let data = vec![0u8; size];
            let encrypted = cipher
                .encrypt(keypair.public_key(), &data)
                .expect("Failed to encrypt test data");
            (size, encrypted)
        })
        .collect();

    for (size, ciphertext) in encrypted_data {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("hybrid", size),
            &ciphertext,
            |b, ciphertext| {
                b.iter(|| cipher.decrypt(black_box(keypair.private_key()), black_box(ciphertext)))
            },
        );
    }

    group.finish();
}

fn bench_cipher_suites(c: &mut Criterion) {
    let keypair = KeyPair::generate(2048).expect("Failed to generate keypair");
    let data = vec![0u8; 8192];

    let mut group = c.benchmark_group("cipher_suites");
    group.throughput(Throughput::Bytes(data.len() as u64));

    for &cipher_suite in &[CipherSuite::Aes128Gcm, CipherSuite::Aes256Gcm] {
        let config = Config::builder()
            .cipher_suite(cipher_suite)
            .build()
            .expect("Failed to build config");

        let cipher = HybridCipher::new(config);

        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{:?}", cipher_suite)),
            &data,
            |b, data| b.iter(|| cipher.encrypt(black_box(keypair.public_key()), black_box(data))),
        );
    }

    group.finish();
}

fn bench_config_variations(c: &mut Criterion) {
    let keypair = KeyPair::generate(2048).expect("Failed to generate keypair");
    let data = vec![0u8; 8192];

    let mut group = c.benchmark_group("configurations");
    group.throughput(Throughput::Bytes(data.len() as u64));

    // Test different configurations
    let configs = vec![
        ("default", Config::default()),
        (
            "small_chunks",
            Config::builder().stream_chunk_size(4096).build().unwrap(),
        ),
        (
            "large_chunks",
            Config::builder().stream_chunk_size(131072).build().unwrap(),
        ),
        (
            "no_hw_accel",
            Config::builder()
                .hardware_acceleration(false)
                .build()
                .unwrap(),
        ),
    ];

    for (name, config) in configs {
        let cipher = HybridCipher::new(config);

        group.bench_with_input(BenchmarkId::new("encrypt", name), &data, |b, data| {
            b.iter(|| cipher.encrypt(black_box(keypair.public_key()), black_box(data)))
        });
    }

    group.finish();
}

fn bench_aes_gcm_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm");

    let cipher_aes128 = AesGcmCipher::new(CipherSuite::Aes128Gcm);
    let cipher_aes256 = AesGcmCipher::new(CipherSuite::Aes256Gcm);
    let key_aes128 = AesKey::generate(CipherSuite::Aes128Gcm).unwrap();
    let key_aes256 = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();

    // Benchmark different data sizes for AES operations
    for &size in &[1024, 8192, 65536, 1048576] {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // AES-128 encryption
        group.bench_with_input(
            BenchmarkId::new("aes128_encrypt", size),
            &data,
            |b, data| {
                b.iter(|| cipher_aes128.encrypt(black_box(&key_aes128), black_box(data), None))
            },
        );

        // AES-256 encryption
        group.bench_with_input(
            BenchmarkId::new("aes256_encrypt", size),
            &data,
            |b, data| {
                b.iter(|| cipher_aes256.encrypt(black_box(&key_aes256), black_box(data), None))
            },
        );

        // Pre-encrypt for decryption benchmarks
        let (nonce_128, ciphertext_128) = cipher_aes128.encrypt(&key_aes128, &data, None).unwrap();
        let (nonce_256, ciphertext_256) = cipher_aes256.encrypt(&key_aes256, &data, None).unwrap();

        // AES-128 decryption
        group.bench_with_input(
            BenchmarkId::new("aes128_decrypt", size),
            &(nonce_128, ciphertext_128),
            |b, (nonce, ciphertext)| {
                b.iter(|| {
                    cipher_aes128.decrypt(
                        black_box(&key_aes128),
                        black_box(nonce),
                        black_box(ciphertext),
                        None,
                    )
                })
            },
        );

        // AES-256 decryption
        group.bench_with_input(
            BenchmarkId::new("aes256_decrypt", size),
            &(nonce_256, ciphertext_256),
            |b, (nonce, ciphertext)| {
                b.iter(|| {
                    cipher_aes256.decrypt(
                        black_box(&key_aes256),
                        black_box(nonce),
                        black_box(ciphertext),
                        None,
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_aes_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_key_generation");

    group.bench_function("aes128", |b| {
        b.iter(|| AesKey::generate(black_box(CipherSuite::Aes128Gcm)))
    });

    group.bench_function("aes256", |b| {
        b.iter(|| AesKey::generate(black_box(CipherSuite::Aes256Gcm)))
    });

    group.finish();
}

fn bench_file_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_operations");

    let keypair = KeyPair::generate(2048).unwrap();
    let config = Config::default();
    let file_cipher = FileStreamCipher::new(config);

    // Create test files of different sizes
    let temp_dir = tempdir().unwrap();
    let test_sizes = vec![1024, 8192, 65536, 1048576]; // 1KB to 1MB

    for &size in &test_sizes {
        let test_data = vec![0x42u8; size];
        let input_file = temp_dir.path().join(format!("test_input_{}.bin", size));
        let encrypted_file = temp_dir.path().join(format!("test_encrypted_{}.enc", size));
        let decrypted_file = temp_dir.path().join(format!("test_decrypted_{}.bin", size));

        fs::write(&input_file, &test_data).unwrap();

        group.throughput(Throughput::Bytes(size as u64));

        // File encryption benchmark
        group.bench_with_input(
            BenchmarkId::new("file_encrypt", size),
            &(&input_file, &encrypted_file),
            |b, (input, output)| {
                b.iter(|| {
                    if output.exists() {
                        fs::remove_file(output).unwrap();
                    }
                    file_cipher.encrypt_file(
                        black_box(input),
                        black_box(output),
                        black_box(keypair.public_key()),
                        None,
                    )
                })
            },
        );

        // Pre-encrypt for decryption benchmark
        if encrypted_file.exists() {
            fs::remove_file(&encrypted_file).unwrap();
        }
        file_cipher
            .encrypt_file(&input_file, &encrypted_file, keypair.public_key(), None)
            .unwrap();

        // File decryption benchmark
        group.bench_with_input(
            BenchmarkId::new("file_decrypt", size),
            &(&encrypted_file, &decrypted_file),
            |b, (input, output)| {
                b.iter(|| {
                    if output.exists() {
                        fs::remove_file(output).unwrap();
                    }
                    file_cipher.decrypt_file(
                        black_box(input),
                        black_box(output),
                        black_box(keypair.private_key()),
                        None,
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_cryptum_api(c: &mut Criterion) {
    let mut group = c.benchmark_group("cryptum_api");

    let cryptum = Cryptum::with_defaults().unwrap();
    let keypair = cryptum.generate_keypair(2048).unwrap();

    // Benchmark different data sizes with Cryptum API
    for &size in &[1024, 8192, 65536, 1048576] {
        let data = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Cryptum encryption
        group.bench_with_input(
            BenchmarkId::new("cryptum_encrypt", size),
            &data,
            |b, data| b.iter(|| cryptum.encrypt(black_box(keypair.public_key()), black_box(data))),
        );

        // Pre-encrypt for decryption benchmark
        let ciphertext = cryptum.encrypt(keypair.public_key(), &data).unwrap();

        // Cryptum decryption
        group.bench_with_input(
            BenchmarkId::new("cryptum_decrypt", size),
            &ciphertext,
            |b, ciphertext| {
                b.iter(|| cryptum.decrypt(black_box(keypair.private_key()), black_box(ciphertext)))
            },
        );
    }

    group.finish();
}

fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_operations");

    use std::sync::Arc;
    use std::thread;

    let keypair = Arc::new(KeyPair::generate(2048).unwrap());
    let cipher = Arc::new(HybridCipher::default());
    let data = vec![0x42u8; 8192];

    // Benchmark concurrent encryption operations
    group.bench_function("concurrent_encrypt_4_threads", |b| {
        b.iter(|| {
            let mut handles = vec![];

            for _ in 0..4 {
                let keypair_clone = keypair.clone();
                let cipher_clone = cipher.clone();
                let data_clone = data.clone();

                let handle = thread::spawn(move || {
                    cipher_clone.encrypt(keypair_clone.public_key(), &data_clone)
                });
                handles.push(handle);
            }

            for handle in handles {
                black_box(handle.join().unwrap().unwrap());
            }
        })
    });

    group.finish();
}

fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");

    let keypair = KeyPair::generate(2048).unwrap();
    let cipher = HybridCipher::default();

    // Test different memory patterns
    let patterns = vec![
        ("zeros", vec![0u8; 65536]),
        ("ones", vec![0xFFu8; 65536]),
        (
            "sequential",
            (0..65536).map(|i| (i % 256) as u8).collect::<Vec<u8>>(),
        ),
        ("random_pattern", {
            let mut data = Vec::with_capacity(65536);
            let mut seed = 12345u32;
            for _ in 0..65536 {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                data.push((seed >> 16) as u8);
            }
            data
        }),
    ];

    for (pattern_name, data) in patterns {
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", pattern_name),
            &data,
            |b, data| b.iter(|| cipher.encrypt(black_box(keypair.public_key()), black_box(data))),
        );
    }

    group.finish();
}

fn bench_configuration_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("configuration_overhead");

    let _keypair = KeyPair::generate(2048).unwrap();

    // Benchmark configuration creation
    group.bench_function("config_default", |b| b.iter(Config::default));

    group.bench_function("config_builder", |b| {
        b.iter(|| {
            Config::builder()
                .cipher_suite(CipherSuite::Aes256Gcm)
                .rsa_key_size(RsaKeySize::Rsa3072)
                .memory_limit_mb(512)
                .build()
        })
    });

    group.bench_function("cipher_creation", |b| {
        let config = Config::default();
        b.iter(|| HybridCipher::new(black_box(config.clone())))
    });

    group.bench_function("cryptum_creation", |b| b.iter(Cryptum::with_defaults));

    group.finish();
}

fn bench_edge_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("edge_cases");

    let cipher = AesGcmCipher::new(CipherSuite::Aes256Gcm);
    let key = AesKey::generate(CipherSuite::Aes256Gcm).unwrap();

    // Benchmark edge cases
    group.bench_function("empty_data", |b| {
        let data = vec![];
        b.iter(|| cipher.encrypt(black_box(&key), black_box(&data), None))
    });

    group.bench_function("single_byte", |b| {
        let data = vec![0x42];
        b.iter(|| cipher.encrypt(black_box(&key), black_box(&data), None))
    });

    group.bench_function("large_aad", |b| {
        let data = vec![0x42; 1024];
        let aad = vec![0xAA; 8192];
        b.iter(|| cipher.encrypt(black_box(&key), black_box(&data), Some(black_box(&aad))))
    });

    // Pre-encrypt for decryption benchmarks
    let (empty_nonce, empty_ciphertext) = cipher.encrypt(&key, &[], None).unwrap();
    let (single_nonce, single_ciphertext) = cipher.encrypt(&key, &[0x42], None).unwrap();

    group.bench_function("empty_data_decrypt", |b| {
        b.iter(|| {
            cipher.decrypt(
                black_box(&key),
                black_box(&empty_nonce),
                black_box(&empty_ciphertext),
                None,
            )
        })
    });

    group.bench_function("single_byte_decrypt", |b| {
        b.iter(|| {
            cipher.decrypt(
                black_box(&key),
                black_box(&single_nonce),
                black_box(&single_ciphertext),
                None,
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_encryption,
    bench_decryption,
    bench_cipher_suites,
    bench_config_variations,
    bench_aes_gcm_operations,
    bench_aes_key_generation,
    bench_file_operations,
    bench_cryptum_api,
    bench_concurrent_operations,
    bench_memory_patterns,
    bench_configuration_overhead,
    bench_edge_cases
);
criterion_main!(benches);
