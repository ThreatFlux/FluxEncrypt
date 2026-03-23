window.BENCHMARK_DATA = {
  "lastUpdate": 1774296601262,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "wyatt.roersma@countermeasuresec.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "42a40d00e7a8cdeb4a75db4802a305e8c3925461",
          "message": "Merge pull request #8: build: upgrade to Rust 1.94.0 / edition 2024 + latest crates\n\nbuild: upgrade to Rust 1.94.0 / edition 2024 + latest crates",
          "timestamp": "2026-03-23T15:49:55-04:00",
          "tree_id": "ba756c9c0666cfdbd9a31b248ed1d9727678d8e4",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/42a40d00e7a8cdeb4a75db4802a305e8c3925461"
        },
        "date": 1774296599782,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 165042049,
            "range": "± 87364754",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 761433333,
            "range": "± 524589265",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2034602606,
            "range": "± 1640726274",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 204079,
            "range": "± 362",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 205602,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 217217,
            "range": "± 661",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 313990,
            "range": "± 1982",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1662887,
            "range": "± 3714",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1657841,
            "range": "± 5899",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1680274,
            "range": "± 9628",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1852923,
            "range": "± 23788",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 206627,
            "range": "± 294",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 210189,
            "range": "± 371",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 205663,
            "range": "± 331",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 205793,
            "range": "± 632",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 211997,
            "range": "± 465",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 207114,
            "range": "± 474",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 829,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 859,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 399,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 428,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1785,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 1925,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1305,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1465,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 9939,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 10927,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10734,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11814,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 72907,
            "range": "± 1296",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 81016,
            "range": "± 115",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 95314,
            "range": "± 196",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 101187,
            "range": "± 298",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 339,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 342,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 230133,
            "range": "± 864",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1678172,
            "range": "± 6649",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 234530,
            "range": "± 551",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1684935,
            "range": "± 10464",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 264460,
            "range": "± 1525",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1736644,
            "range": "± 11945",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 1994113,
            "range": "± 4438",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 13803865,
            "range": "± 51947",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 206437,
            "range": "± 821",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1652531,
            "range": "± 3114",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 210489,
            "range": "± 2321",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1659921,
            "range": "± 5259",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 216718,
            "range": "± 367",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1673950,
            "range": "± 5293",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 317581,
            "range": "± 543",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1827013,
            "range": "± 21183",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 499290,
            "range": "± 3778",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 217577,
            "range": "± 464",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 225341,
            "range": "± 635",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 217636,
            "range": "± 521",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 220081,
            "range": "± 545",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/config_default",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/config_builder",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/cipher_creation",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/cryptum_creation",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 583,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 618,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5073,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 228,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 262,
            "range": "± 2",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}