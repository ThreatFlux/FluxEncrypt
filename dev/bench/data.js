window.BENCHMARK_DATA = {
  "lastUpdate": 1757270108908,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "5f2f71c0a2eee23bd499bd230e358ca5d06c5c5c",
          "message": "fix: Resolve code complexity and security issues\n\n- Refactor large methods to reduce complexity below 50 lines\n- Reduce cyclomatic complexity in encrypt.rs and benchmark.rs\n- Fix security issue: replace temp_dir with secure directory approach\n- Break down benchmark display_results into focused helper functions\n- Refactor test files to improve maintainability\n- Fix benchmark data size to respect 512KB encryption limit\n- All tests pass, no clippy warnings, clean build\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-07T14:14:15-04:00",
          "tree_id": "4bb8573b637c76a942bd9fcf28e5cbb6ad1fafb4",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/5f2f71c0a2eee23bd499bd230e358ca5d06c5c5c"
        },
        "date": 1757270107758,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 182212664,
            "range": "± 101389366",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 791983670,
            "range": "± 505814949",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2199688048,
            "range": "± 1757308862",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 208457,
            "range": "± 1909",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 212251,
            "range": "± 378",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 242272,
            "range": "± 414",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 313754,
            "range": "± 980",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1742754,
            "range": "± 16287",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1740855,
            "range": "± 6635",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1753699,
            "range": "± 3515",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1854130,
            "range": "± 233665",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 213192,
            "range": "± 578",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 213763,
            "range": "± 2863",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 210878,
            "range": "± 400",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 210832,
            "range": "± 387",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 210807,
            "range": "± 369",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 210844,
            "range": "± 2315",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 974,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 990,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 426,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 450,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 4688,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 4837,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1487,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1660,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 40799,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 41868,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11083,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11867,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 81463,
            "range": "± 235",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 90103,
            "range": "± 265",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 95221,
            "range": "± 321",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 100632,
            "range": "± 342",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 479,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 485,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 264057,
            "range": "± 735",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1799366,
            "range": "± 4465",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 275325,
            "range": "± 730",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1814080,
            "range": "± 6204",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 361746,
            "range": "± 1387",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1872251,
            "range": "± 3242",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2540454,
            "range": "± 7740",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14606841,
            "range": "± 25917",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 208823,
            "range": "± 306",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1738643,
            "range": "± 5248",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 210163,
            "range": "± 973",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1738142,
            "range": "± 3211",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 252954,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1750925,
            "range": "± 4255",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 320731,
            "range": "± 779",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1852199,
            "range": "± 3453",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 521080,
            "range": "± 4386",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 221007,
            "range": "± 809",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 222565,
            "range": "± 270",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 220907,
            "range": "± 283",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 222423,
            "range": "± 494",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/config_default",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/config_builder",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/cipher_creation",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/cryptum_creation",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 714,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 767,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5507,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 252,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 283,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}