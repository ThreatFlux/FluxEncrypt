window.BENCHMARK_DATA = {
  "lastUpdate": 1795746863376,
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
          "id": "fb13abb9e01318e187b9360cb22d396700222849",
          "message": "Merge pull request #58 from ThreatFlux/dependabot/nightly_dependencies-51c076db55\n\nchore(deps): Bump the \"nightly-dependencies\" group with 1 update across multiple ecosystems",
          "timestamp": "2026-11-26T21:18:52-05:00",
          "tree_id": "b6bce371d110d5899861253dda6f68ef95fcab05",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/fb13abb9e01318e187b9360cb22d396700222849"
        },
        "date": 1795746862888,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 62304549,
            "range": "± 49870281",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 205830585,
            "range": "± 148329079",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 529926695,
            "range": "± 534631430",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 74528,
            "range": "± 733",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 75791,
            "range": "± 464",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 86428,
            "range": "± 532",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 200593,
            "range": "± 1481",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1239838,
            "range": "± 17191",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1243944,
            "range": "± 22160",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1255992,
            "range": "± 17179",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1354440,
            "range": "± 17238",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 75600,
            "range": "± 467",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 75747,
            "range": "± 1679",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 75873,
            "range": "± 316",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 75846,
            "range": "± 168",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 75824,
            "range": "± 203",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 75859,
            "range": "± 1312",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 954,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 992,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 434,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 459,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2020,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2061,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1475,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1608,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 12547,
            "range": "± 77",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 12698,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10891,
            "range": "± 148",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11831,
            "range": "± 96",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 99770,
            "range": "± 556",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 108355,
            "range": "± 524",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 98394,
            "range": "± 2027",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 106018,
            "range": "± 503",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 478,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 482,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 124053,
            "range": "± 1230",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1321819,
            "range": "± 14312",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 134641,
            "range": "± 675",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1324068,
            "range": "± 7164",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 172063,
            "range": "± 2534",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1350285,
            "range": "± 24107",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 1026545,
            "range": "± 8577",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 10370692,
            "range": "± 144621",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 74495,
            "range": "± 920",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1248106,
            "range": "± 8410",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 75766,
            "range": "± 1266",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1250101,
            "range": "± 29088",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 87892,
            "range": "± 827",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1259129,
            "range": "± 23009",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 195937,
            "range": "± 937",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1356911,
            "range": "± 11123",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 266435,
            "range": "± 9580",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 86680,
            "range": "± 2581",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 88419,
            "range": "± 786",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 86741,
            "range": "± 1722",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 88351,
            "range": "± 357",
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
            "value": 749,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 790,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5297,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 258,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 290,
            "range": "± 1",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}