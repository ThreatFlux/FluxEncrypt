window.BENCHMARK_DATA = {
  "lastUpdate": 1773445603114,
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
          "id": "42f8d799c328aaea4475cd82bdecfd899d470bdb",
          "message": "Merge pull request #5 from ThreatFlux/codex/task-title",
          "timestamp": "2026-03-13T19:25:53-04:00",
          "tree_id": "d959c94f1b82fc6ef7014e6253f99e986e801a3b",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/42f8d799c328aaea4475cd82bdecfd899d470bdb"
        },
        "date": 1773445560256,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 164040506,
            "range": "± 113940116",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 749362862,
            "range": "± 392005985",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2184711868,
            "range": "± 1613550047",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 210726,
            "range": "± 5565",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 215123,
            "range": "± 3950",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 254079,
            "range": "± 1975",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 323445,
            "range": "± 2691",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1758239,
            "range": "± 25437",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1761870,
            "range": "± 4833",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1771793,
            "range": "± 8480",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1871427,
            "range": "± 4166",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 213646,
            "range": "± 449",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 214263,
            "range": "± 449",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 214498,
            "range": "± 1274",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 215355,
            "range": "± 412",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 215257,
            "range": "± 411",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 212095,
            "range": "± 602",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1268,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1304,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 419,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 469,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2304,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2464,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 4140,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1693,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 41275,
            "range": "± 242",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 42337,
            "range": "± 65",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10945,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 12044,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 83789,
            "range": "± 362",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 92375,
            "range": "± 372",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 96901,
            "range": "± 479",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 102183,
            "range": "± 518",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 730,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 741,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 267499,
            "range": "± 915",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1837098,
            "range": "± 18516",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 278958,
            "range": "± 1001",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1839513,
            "range": "± 6684",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 364497,
            "range": "± 1806",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1905736,
            "range": "± 12054",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2578393,
            "range": "± 6814",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14859441,
            "range": "± 106282",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 210516,
            "range": "± 606",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1767342,
            "range": "± 7854",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 214542,
            "range": "± 1670",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1760276,
            "range": "± 3766",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 254066,
            "range": "± 980",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1777666,
            "range": "± 5226",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 323186,
            "range": "± 1039",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1881536,
            "range": "± 5319",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 547799,
            "range": "± 3566",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 222330,
            "range": "± 539",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 223890,
            "range": "± 2325",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 222255,
            "range": "± 787",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 222478,
            "range": "± 736",
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
            "value": 11,
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
            "value": 1024,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 1064,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5677,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 277,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 311,
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
          "id": "8f11e6b8ac94af39e165e7cbbd00988c098e52ba",
          "message": "Merge pull request #4 from ThreatFlux/codex/propose-fix-for-unpinned-syft-install-script",
          "timestamp": "2026-03-13T19:26:12-04:00",
          "tree_id": "b5241bccafa7de32b0a6169fa45d048821747a23",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/8f11e6b8ac94af39e165e7cbbd00988c098e52ba"
        },
        "date": 1773445590522,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 182508608,
            "range": "± 122248274",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 767772164,
            "range": "± 469619461",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2146523356,
            "range": "± 1779298993",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 209824,
            "range": "± 354",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 213755,
            "range": "± 486",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 248735,
            "range": "± 2236",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 314333,
            "range": "± 925",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1754862,
            "range": "± 2801",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1758468,
            "range": "± 7002",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1792846,
            "range": "± 25736",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1882072,
            "range": "± 29502",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 214223,
            "range": "± 730",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 214304,
            "range": "± 523",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 214667,
            "range": "± 344",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 214918,
            "range": "± 1856",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 215043,
            "range": "± 1267",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 212397,
            "range": "± 726",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1265,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1288,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 454,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 472,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2268,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2409,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1559,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1623,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 41488,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 42291,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11210,
            "range": "± 123",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 12184,
            "range": "± 66",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 77983,
            "range": "± 484",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 86517,
            "range": "± 297",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 90366,
            "range": "± 366",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 96464,
            "range": "± 528",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 710,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 730,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 267956,
            "range": "± 2458",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1829609,
            "range": "± 55222",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 276984,
            "range": "± 1125",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1831389,
            "range": "± 6854",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 363755,
            "range": "± 1358",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1898260,
            "range": "± 9413",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2544646,
            "range": "± 18463",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14781136,
            "range": "± 42866",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 209699,
            "range": "± 543",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1787970,
            "range": "± 23790",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 211495,
            "range": "± 926",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1784836,
            "range": "± 5378",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 253292,
            "range": "± 1418",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1794058,
            "range": "± 17350",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 316133,
            "range": "± 1285",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1900657,
            "range": "± 55693",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 547127,
            "range": "± 4197",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 223839,
            "range": "± 1101",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 225568,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 223986,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 223751,
            "range": "± 1654",
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
            "value": 11,
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
            "value": 1006,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 1043,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5673,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 262,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 294,
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
          "id": "2b253308995cb2f189050367d1f31831718100de",
          "message": "Merge pull request #2 from ThreatFlux/codex/fix-base64-keygen-file-permissions",
          "timestamp": "2026-03-13T19:26:23-04:00",
          "tree_id": "bee2cea679a7ce69ba8cc89ded1e3403fd2c659e",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/2b253308995cb2f189050367d1f31831718100de"
        },
        "date": 1773445602671,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 188355962,
            "range": "± 104265723",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 714037357,
            "range": "± 556441245",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 1992724279,
            "range": "± 1480212193",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 217677,
            "range": "± 5316",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 213348,
            "range": "± 4296",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 262205,
            "range": "± 5053",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 313404,
            "range": "± 1004",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1936159,
            "range": "± 49871",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1900889,
            "range": "± 36540",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1820327,
            "range": "± 20101",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1888115,
            "range": "± 11077",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 214177,
            "range": "± 3939",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 219743,
            "range": "± 3904",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 210929,
            "range": "± 555",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 210559,
            "range": "± 945",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 210593,
            "range": "± 395",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 210680,
            "range": "± 504",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1289,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1296,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 440,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 464,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 5022,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 5173,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1589,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1650,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 41096,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 42183,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11079,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 12007,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 79275,
            "range": "± 274",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 91170,
            "range": "± 1229",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 91072,
            "range": "± 3730",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 100483,
            "range": "± 1178",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 728,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 737,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 275189,
            "range": "± 5609",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1822642,
            "range": "± 39792",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 276396,
            "range": "± 1029",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1829356,
            "range": "± 6163",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 362971,
            "range": "± 1302",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1906295,
            "range": "± 15334",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2607073,
            "range": "± 31111",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14850829,
            "range": "± 234829",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 218721,
            "range": "± 6195",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1764805,
            "range": "± 9272",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 214367,
            "range": "± 539",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1763858,
            "range": "± 25979",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 262476,
            "range": "± 8132",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1835761,
            "range": "± 35689",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 316061,
            "range": "± 3332",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1934266,
            "range": "± 44301",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 565371,
            "range": "± 20175",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 232358,
            "range": "± 5794",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 234026,
            "range": "± 3727",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 229437,
            "range": "± 4356",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 230301,
            "range": "± 4312",
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
            "value": 11,
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
            "value": 1004,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 1053,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5830,
            "range": "± 8",
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
            "value": 296,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}