window.BENCHMARK_DATA = {
  "lastUpdate": 1786516831373,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "768251b748cc5f9a85d1e89a2c9bb24685d5ead1",
          "message": "Merge pull request #18 from ThreatFlux/fix/flaky-key-component-length-test\n\nfix(test): stop pinning exact byte widths for reduced key components",
          "timestamp": "2026-08-12T02:22:12-04:00",
          "tree_id": "e0f47159972b7c6d32ebb4437303f97febfa2fd5",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/768251b748cc5f9a85d1e89a2c9bb24685d5ead1"
        },
        "date": 1786516828862,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 141125672,
            "range": "± 83298965",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 494883302,
            "range": "± 318172343",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 1257247145,
            "range": "± 1096750950",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 137823,
            "range": "± 6509",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 150225,
            "range": "± 3952",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 160375,
            "range": "± 3825",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 235789,
            "range": "± 9527",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1243856,
            "range": "± 28942",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1219572,
            "range": "± 43195",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1244507,
            "range": "± 31548",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1328235,
            "range": "± 48519",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 148095,
            "range": "± 7870",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 151607,
            "range": "± 3998",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 151169,
            "range": "± 3220",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 151257,
            "range": "± 4270",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 150022,
            "range": "± 4912",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 155079,
            "range": "± 7145",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 874,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 891,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 394,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 418,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1640,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 1783,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1221,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1356,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 9150,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 10320,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10121,
            "range": "± 330",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11131,
            "range": "± 319",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 67349,
            "range": "± 1774",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 75653,
            "range": "± 2228",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 76820,
            "range": "± 2001",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 85841,
            "range": "± 2920",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 370,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 365,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 171646,
            "range": "± 3487",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1269573,
            "range": "± 30245",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 181109,
            "range": "± 3145",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1335425,
            "range": "± 30694",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 203393,
            "range": "± 2235",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1324914,
            "range": "± 30723",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 1427699,
            "range": "± 38920",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 10241532,
            "range": "± 370156",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 149564,
            "range": "± 5121",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1238922,
            "range": "± 42058",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 148926,
            "range": "± 6323",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1252243,
            "range": "± 47034",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 166198,
            "range": "± 5648",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1242240,
            "range": "± 49957",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 245749,
            "range": "± 7908",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1360359,
            "range": "± 33747",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 376395,
            "range": "± 13432",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 159653,
            "range": "± 4863",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 157726,
            "range": "± 6019",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 157776,
            "range": "± 5530",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 155282,
            "range": "± 5288",
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
            "value": 9,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 620,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 663,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 4676,
            "range": "± 301",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 228,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 265,
            "range": "± 10",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}