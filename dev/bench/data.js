window.BENCHMARK_DATA = {
  "lastUpdate": 1767121656208,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "wyatt.roersma@target.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "wyatt.roersma@target.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "b8f516a3bc5f246d988dd6b59dbc3fa510a11751",
          "message": "fix: remove pinned package versions from Dockerfile\n\nDebian trixie (testing) repositories frequently update package versions,\ncausing Docker builds to fail when specific versions are pinned. The\nbase image already provides version consistency, so pinning is unnecessary.\n\nRemoved version pins for:\n- pkgconf (was 1.8.1-4)\n- libssl-dev (was 3.5.1-1)\n- ca-certificates (was 20250419)\n- libssl3t64 (was 3.5.1-1)\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
          "timestamp": "2025-12-30T13:47:04-05:00",
          "tree_id": "31392152934e026cc08fcf54f8501ab8464b39e2",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/b8f516a3bc5f246d988dd6b59dbc3fa510a11751"
        },
        "date": 1767121655467,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 198363914,
            "range": "± 108385396",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 795490797,
            "range": "± 534630773",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2474856864,
            "range": "± 1565257825",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 233145,
            "range": "± 1244",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 237047,
            "range": "± 1048",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 276534,
            "range": "± 817",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 337585,
            "range": "± 1807",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1936373,
            "range": "± 3410",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1932616,
            "range": "± 10767",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1944061,
            "range": "± 4553",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 2038510,
            "range": "± 51709",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 238921,
            "range": "± 1151",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 239089,
            "range": "± 3939",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 235592,
            "range": "± 1612",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 235487,
            "range": "± 2409",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 235530,
            "range": "± 3397",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 235596,
            "range": "± 1955",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 958,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 996,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 420,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 442,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1943,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2087,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 4118,
            "range": "± 128",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1684,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 41800,
            "range": "± 1132",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 41989,
            "range": "± 65",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11145,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 12129,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 88682,
            "range": "± 249",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 90183,
            "range": "± 238",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 96823,
            "range": "± 4331",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 98782,
            "range": "± 254",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 481,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 492,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 290621,
            "range": "± 1363",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1994360,
            "range": "± 4823",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 301312,
            "range": "± 3677",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 2001692,
            "range": "± 8144",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 389390,
            "range": "± 11712",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 2065317,
            "range": "± 11968",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2743829,
            "range": "± 10898",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 16152116,
            "range": "± 36434",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 234318,
            "range": "± 1293",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1934215,
            "range": "± 35862",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 239076,
            "range": "± 1260",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1932414,
            "range": "± 3571",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 279260,
            "range": "± 73447",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1959112,
            "range": "± 24162",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 345977,
            "range": "± 7297",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 2046470,
            "range": "± 11777",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 583835,
            "range": "± 3163",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 247173,
            "range": "± 436",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 248978,
            "range": "± 2711",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 246808,
            "range": "± 6151",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 246944,
            "range": "± 593",
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
            "value": 7,
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
            "value": 738,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 784,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5366,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 261,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 295,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}