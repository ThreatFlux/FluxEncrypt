window.BENCHMARK_DATA = {
  "lastUpdate": 1793496618022,
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
          "id": "c5696896d8263f513b25c1f56ef0626fd2a1b8a8",
          "message": "chore: release v0.7.12",
          "timestamp": "2026-11-01T01:09:11Z",
          "tree_id": "34616fbec8ccc979fbfe8e5fb3a6599e27c191fb",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/c5696896d8263f513b25c1f56ef0626fd2a1b8a8"
        },
        "date": 1793496617003,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 208629116,
            "range": "± 133369207",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 786383797,
            "range": "± 457055826",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2376576507,
            "range": "± 1599806369",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 236431,
            "range": "± 954",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 237791,
            "range": "± 3653",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 248642,
            "range": "± 933",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 342195,
            "range": "± 1122",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1306088,
            "range": "± 12457",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1309094,
            "range": "± 17036",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1321341,
            "range": "± 6974",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1415301,
            "range": "± 22075",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 238469,
            "range": "± 2054",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 238470,
            "range": "± 531",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 238344,
            "range": "± 2540",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 238065,
            "range": "± 418",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 238232,
            "range": "± 3399",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 238319,
            "range": "± 923",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1096,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1122,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 477,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 487,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2099,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2251,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1520,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1630,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 10460,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 11683,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10802,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11511,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 79585,
            "range": "± 180",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 89337,
            "range": "± 2746",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 89296,
            "range": "± 1371",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 95616,
            "range": "± 2478",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 588,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 587,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 282479,
            "range": "± 1375",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1372925,
            "range": "± 9641",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 294236,
            "range": "± 5797",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1380759,
            "range": "± 39393",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 331112,
            "range": "± 1669",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1414015,
            "range": "± 22598",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2338615,
            "range": "± 11569",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 10930799,
            "range": "± 288630",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 237419,
            "range": "± 561",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1303172,
            "range": "± 16078",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 238531,
            "range": "± 9879",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1304215,
            "range": "± 26825",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 250173,
            "range": "± 988",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1314903,
            "range": "± 22862",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 343348,
            "range": "± 1229",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1409874,
            "range": "± 18911",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 576121,
            "range": "± 5427",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 250127,
            "range": "± 972",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 252037,
            "range": "± 467",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 250063,
            "range": "± 558",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 250241,
            "range": "± 2876",
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
            "value": 888,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 930,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 6271,
            "range": "± 96",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 290,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 319,
            "range": "± 3",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}