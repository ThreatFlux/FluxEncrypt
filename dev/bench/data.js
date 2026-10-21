window.BENCHMARK_DATA = {
  "lastUpdate": 1792589410774,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ce41f6084c7490bfe27deb67d4077d1abd205c08",
          "message": "chore: release v0.7.10",
          "timestamp": "2026-10-21T13:08:14Z",
          "tree_id": "9cac3a1da77d2091059baf89116c8a5cb9d5b597",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/ce41f6084c7490bfe27deb67d4077d1abd205c08"
        },
        "date": 1792589409317,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 194374955,
            "range": "± 111746583",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 921686665,
            "range": "± 489834665",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2765769645,
            "range": "± 1860769706",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 237588,
            "range": "± 3334",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 238961,
            "range": "± 4837",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 249838,
            "range": "± 536",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 348109,
            "range": "± 827",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1350098,
            "range": "± 33681",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1351807,
            "range": "± 8953",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1362777,
            "range": "± 38675",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1457684,
            "range": "± 10824",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 242088,
            "range": "± 555",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 240980,
            "range": "± 1055",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 239969,
            "range": "± 675",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 240054,
            "range": "± 891",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 240030,
            "range": "± 2761",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 239907,
            "range": "± 718",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1117,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1150,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 497,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 509,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2174,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2342,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1482,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1653,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 10586,
            "range": "± 354",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 11801,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10951,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11901,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 80157,
            "range": "± 1535",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 89861,
            "range": "± 2686",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 89764,
            "range": "± 197",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 96410,
            "range": "± 180",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 578,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 578,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 288595,
            "range": "± 2338",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1427278,
            "range": "± 20176",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 299278,
            "range": "± 3277",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1439299,
            "range": "± 12201",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 334514,
            "range": "± 1280",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1489046,
            "range": "± 8736",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2364154,
            "range": "± 9903",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 11359917,
            "range": "± 31089",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 238305,
            "range": "± 4250",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1359904,
            "range": "± 24686",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 240015,
            "range": "± 694",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1362274,
            "range": "± 19352",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 250268,
            "range": "± 4916",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1375168,
            "range": "± 20821",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 351511,
            "range": "± 621",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1470288,
            "range": "± 9792",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 588474,
            "range": "± 4577",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 250527,
            "range": "± 2752",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 252235,
            "range": "± 4829",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 252980,
            "range": "± 913",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 250254,
            "range": "± 5835",
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/cryptum_creation",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 882,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 930,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 6306,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 290,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 335,
            "range": "± 6",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}