window.BENCHMARK_DATA = {
  "lastUpdate": 1757297679791,
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
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "142455c125fa305d9fe26894eb4816cc40c1b973",
          "message": "Refactor encrypt command input handling",
          "timestamp": "2025-09-07T18:23:23Z",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/pull/1/commits/142455c125fa305d9fe26894eb4816cc40c1b973"
        },
        "date": 1757294102580,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 182153212,
            "range": "± 109063898",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 683777940,
            "range": "± 471432043",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2355845577,
            "range": "± 1523513441",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 206148,
            "range": "± 335",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 210437,
            "range": "± 1830",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 238709,
            "range": "± 493",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 316056,
            "range": "± 891",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1733082,
            "range": "± 3993",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1734304,
            "range": "± 20611",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1746714,
            "range": "± 2459",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1843890,
            "range": "± 15193",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 210466,
            "range": "± 1035",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 210530,
            "range": "± 7490",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 210514,
            "range": "± 1503",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 210328,
            "range": "± 4652",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 210496,
            "range": "± 1479",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 207782,
            "range": "± 525",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 957,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 987,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 426,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 449,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1907,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2052,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1477,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1642,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 30347,
            "range": "± 396",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 31440,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10940,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11814,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 82315,
            "range": "± 391",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 90803,
            "range": "± 1220",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 95835,
            "range": "± 574",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 100627,
            "range": "± 2131",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 480,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 493,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 262745,
            "range": "± 902",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1802907,
            "range": "± 19771",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 274173,
            "range": "± 1259",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1812180,
            "range": "± 4186",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 349470,
            "range": "± 6299",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1873147,
            "range": "± 4865",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2428813,
            "range": "± 8975",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14559535,
            "range": "± 36313",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 207788,
            "range": "± 802",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1737226,
            "range": "± 24556",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 211630,
            "range": "± 329",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1739363,
            "range": "± 18448",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 239896,
            "range": "± 4082",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1752810,
            "range": "± 4466",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 321167,
            "range": "± 1321",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1853017,
            "range": "± 6826",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 533705,
            "range": "± 2911",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 219864,
            "range": "± 903",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 222070,
            "range": "± 377",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 219074,
            "range": "± 334",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 219124,
            "range": "± 536",
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
            "value": 728,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 771,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5484,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 257,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 290,
            "range": "± 1",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "0e9b05bed6981b1182bf1c07bfa0539beb2144a0",
          "message": "Refactor encrypt command input handling",
          "timestamp": "2025-09-07T18:23:23Z",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/pull/1/commits/0e9b05bed6981b1182bf1c07bfa0539beb2144a0"
        },
        "date": 1757297679100,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 171850116,
            "range": "± 130430604",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 713800679,
            "range": "± 477234315",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2093155902,
            "range": "± 1387100666",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 206380,
            "range": "± 641",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 210519,
            "range": "± 1301",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 240106,
            "range": "± 367",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 316781,
            "range": "± 733",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1735201,
            "range": "± 4760",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1737216,
            "range": "± 3746",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1748848,
            "range": "± 4029",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1848076,
            "range": "± 3340",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 211374,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 211899,
            "range": "± 280",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 212117,
            "range": "± 814",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 212187,
            "range": "± 1303",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 211980,
            "range": "± 867",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 208978,
            "range": "± 878",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 976,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 996,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 424,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 427,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2089,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2114,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1518,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1624,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 40792,
            "range": "± 191",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 41875,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11047,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11965,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 83093,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 87591,
            "range": "± 309",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 90492,
            "range": "± 308",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 97478,
            "range": "± 278",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 482,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 493,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 264007,
            "range": "± 2155",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1801448,
            "range": "± 9727",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 274752,
            "range": "± 908",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1804962,
            "range": "± 4904",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 361322,
            "range": "± 2905",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1870558,
            "range": "± 6320",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2521527,
            "range": "± 6156",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14563483,
            "range": "± 33717",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 206531,
            "range": "± 653",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1738001,
            "range": "± 2877",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 210648,
            "range": "± 3549",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1740895,
            "range": "± 3094",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 250366,
            "range": "± 633",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1754640,
            "range": "± 77765",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 320764,
            "range": "± 1201",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1853998,
            "range": "± 3394",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 529757,
            "range": "± 3356",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 219742,
            "range": "± 775",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 221965,
            "range": "± 806",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 220105,
            "range": "± 609",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 219962,
            "range": "± 1166",
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
            "value": 12,
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
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 742,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 786,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5413,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 255,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 290,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}