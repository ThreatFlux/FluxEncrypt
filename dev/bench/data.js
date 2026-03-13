window.BENCHMARK_DATA = {
  "lastUpdate": 1773445521325,
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
      },
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
          "id": "46b17ebe4e0a3adf8b18a6aae793c7e9a2edb930",
          "message": "Merge pull request #3 from ThreatFlux/codex/fix-batch-output-path-escape-issue",
          "timestamp": "2026-03-13T19:24:53-04:00",
          "tree_id": "373930d85a8c9262e30722613c1a0e8d03dfef76",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/46b17ebe4e0a3adf8b18a6aae793c7e9a2edb930"
        },
        "date": 1773445520019,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 205616183,
            "range": "± 139657026",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 785370398,
            "range": "± 629253226",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2010227382,
            "range": "± 2082167875",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 233142,
            "range": "± 1351",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 237208,
            "range": "± 3310",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 268539,
            "range": "± 10418",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 337852,
            "range": "± 1469",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1911705,
            "range": "± 5393",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1914035,
            "range": "± 20391",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1929397,
            "range": "± 4526",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 2028305,
            "range": "± 4442",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 237351,
            "range": "± 340",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 238156,
            "range": "± 5044",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 237255,
            "range": "± 698",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 236560,
            "range": "± 612",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 237358,
            "range": "± 645",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 236578,
            "range": "± 1725",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1302,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1314,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 458,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 480,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2296,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2434,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1497,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1665,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 36950,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 38043,
            "range": "± 71",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11010,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11941,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 79216,
            "range": "± 286",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 87872,
            "range": "± 225",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 90513,
            "range": "± 243",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 97218,
            "range": "± 403",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 720,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 734,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 290495,
            "range": "± 1041",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1980704,
            "range": "± 5657",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 301921,
            "range": "± 4887",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1994233,
            "range": "± 6248",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 382405,
            "range": "± 1930",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 2049448,
            "range": "± 6618",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2696536,
            "range": "± 11878",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 16027689,
            "range": "± 46900",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 233581,
            "range": "± 595",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1913823,
            "range": "± 6668",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 237828,
            "range": "± 739",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1916917,
            "range": "± 5605",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 272703,
            "range": "± 11738",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1925416,
            "range": "± 2843",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 337820,
            "range": "± 1485",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 2032043,
            "range": "± 13788",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 598596,
            "range": "± 2958",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 247671,
            "range": "± 583",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 249353,
            "range": "± 504",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 247471,
            "range": "± 2744",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 247590,
            "range": "± 587",
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
            "value": 1002,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 1057,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5656,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 263,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 296,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}