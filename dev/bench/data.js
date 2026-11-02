window.BENCHMARK_DATA = {
  "lastUpdate": 1793638966880,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bec2d22158591f5275aeacd6ce4e7d71935034d7",
          "message": "chore(deps): bump aws-lc-rs (#44)\n\nBumps the rust-minor-patch group with 1 update: [aws-lc-rs](https://github.com/aws/aws-lc-rs).\n\n\nUpdates `aws-lc-rs` from 1.18.2 to 1.19.0\n- [Release notes](https://github.com/aws/aws-lc-rs/releases)\n- [Commits](https://github.com/aws/aws-lc-rs/compare/v1.18.2...v1.19.0)\n\n---\nupdated-dependencies:\n- dependency-name: aws-lc-rs\n  dependency-version: 1.19.0\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n  dependency-group: rust-minor-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-02T11:43:04-05:00",
          "tree_id": "07cf6a66582f0ba8e5c7bde5f8c845eafb6de339",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/bec2d22158591f5275aeacd6ce4e7d71935034d7"
        },
        "date": 1793638966020,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 190684627,
            "range": "± 115492696",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 692420750,
            "range": "± 478294545",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2025932615,
            "range": "± 1459439361",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 209590,
            "range": "± 666",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 211036,
            "range": "± 560",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 222781,
            "range": "± 3115",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 315737,
            "range": "± 1218",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1177820,
            "range": "± 7705",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1178382,
            "range": "± 7180",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1189959,
            "range": "± 23574",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1292863,
            "range": "± 19255",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 211463,
            "range": "± 440",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 211472,
            "range": "± 3022",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 211874,
            "range": "± 822",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 211775,
            "range": "± 4018",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 212009,
            "range": "± 3082",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 211942,
            "range": "± 465",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 976,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1012,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 433,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 458,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1912,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2067,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1473,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1578,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 10039,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 11136,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10658,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11586,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 80927,
            "range": "± 1242",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 89589,
            "range": "± 491",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 91459,
            "range": "± 390",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 98456,
            "range": "± 666",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 473,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 483,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 263262,
            "range": "± 1468",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1258269,
            "range": "± 10539",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 274585,
            "range": "± 8429",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1262811,
            "range": "± 12839",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 308545,
            "range": "± 1532",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1294443,
            "range": "± 18530",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2142164,
            "range": "± 9114",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 9936239,
            "range": "± 125352",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 209858,
            "range": "± 2403",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1165910,
            "range": "± 15476",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 211339,
            "range": "± 483",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1168608,
            "range": "± 20088",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 223310,
            "range": "± 693",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1180985,
            "range": "± 16178",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 316559,
            "range": "± 1153",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1286131,
            "range": "± 9698",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 539726,
            "range": "± 5338",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 223588,
            "range": "± 582",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 225122,
            "range": "± 728",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 223856,
            "range": "± 1966",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 223611,
            "range": "± 720",
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
            "value": 12,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 742,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 786,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5333,
            "range": "± 93",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 257,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 287,
            "range": "± 3",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}