window.BENCHMARK_DATA = {
  "lastUpdate": 1773445519783,
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
          "id": "18667a8343b6b1d705469f4d8a5573b6134b30e9",
          "message": "Merge pull request #6 from ThreatFlux/codex/propose-fix-for-memory-exhaustion-vulnerability",
          "timestamp": "2026-03-13T19:25:17-04:00",
          "tree_id": "b3661b9171534f697243b13b8d7f2d64e1b51e5d",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/18667a8343b6b1d705469f4d8a5573b6134b30e9"
        },
        "date": 1773445519078,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 178101154,
            "range": "± 93662179",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 727897751,
            "range": "± 478054792",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2191598864,
            "range": "± 1586273198",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 204927,
            "range": "± 863",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 205955,
            "range": "± 1008",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 216440,
            "range": "± 928",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 313637,
            "range": "± 543",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1660035,
            "range": "± 5764",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1659927,
            "range": "± 3233",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1682642,
            "range": "± 5832",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1814679,
            "range": "± 91318",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 206675,
            "range": "± 335",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 209119,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 206554,
            "range": "± 1479",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 206221,
            "range": "± 287",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 206353,
            "range": "± 646",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 207661,
            "range": "± 561",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 827,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 860,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 392,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 425,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1766,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 1917,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1352,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1486,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 9711,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 10785,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 13199,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 14170,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 71513,
            "range": "± 362",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 79984,
            "range": "± 193",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 93889,
            "range": "± 451",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 101458,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 343,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 345,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 228025,
            "range": "± 608",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1695512,
            "range": "± 7205",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 233928,
            "range": "± 3001",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1702726,
            "range": "± 11721",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 265105,
            "range": "± 2217",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1733817,
            "range": "± 5542",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2002944,
            "range": "± 30738",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 13895047,
            "range": "± 36070",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 204773,
            "range": "± 655",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1659954,
            "range": "± 14267",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 205987,
            "range": "± 363",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1659646,
            "range": "± 13920",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 216246,
            "range": "± 342",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1672447,
            "range": "± 4520",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 312489,
            "range": "± 1055",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1792358,
            "range": "± 15505",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 499506,
            "range": "± 5180",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 220872,
            "range": "± 317",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 222639,
            "range": "± 455",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 217217,
            "range": "± 718",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 217129,
            "range": "± 435",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/config_default",
            "value": 2,
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
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/cryptum_creation",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 582,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 617,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5084,
            "range": "± 83",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 226,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 258,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}