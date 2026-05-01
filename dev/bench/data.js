window.BENCHMARK_DATA = {
  "lastUpdate": 1777647793648,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "wyatt.roersma@countermeasuresec.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3d93268246aab5101f9d89059bbe24e05a064210",
          "message": "Merge pull request #9 from ThreatFlux/codex/dependabot-rollup-20260423\n\n[codex] Update rand security patches",
          "timestamp": "2026-04-23T08:20:37-04:00",
          "tree_id": "35f940251c6a6c253840bfa90bc716c2f825d178",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/3d93268246aab5101f9d89059bbe24e05a064210"
        },
        "date": 1776948092055,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 187453494,
            "range": "± 122510586",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 892291356,
            "range": "± 688218858",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2281144055,
            "range": "± 1634342549",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 238378,
            "range": "± 5027",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 238654,
            "range": "± 665",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 249999,
            "range": "± 3136",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 344543,
            "range": "± 821",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1971793,
            "range": "± 6449",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1971192,
            "range": "± 11884",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1980844,
            "range": "± 4242",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 2077380,
            "range": "± 15098",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 240906,
            "range": "± 554",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 240702,
            "range": "± 568",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 239989,
            "range": "± 679",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 240186,
            "range": "± 2134",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 239726,
            "range": "± 639",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 239051,
            "range": "± 436",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1089,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1121,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 496,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 490,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2085,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2244,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1554,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1658,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 12161,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 13379,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11107,
            "range": "± 107",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11917,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 78766,
            "range": "± 1725",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 88459,
            "range": "± 283",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 91690,
            "range": "± 321",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 97659,
            "range": "± 691",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 577,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 584,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 286652,
            "range": "± 2851",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 2027192,
            "range": "± 7553",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 297501,
            "range": "± 1158",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 2033273,
            "range": "± 37710",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 335333,
            "range": "± 1263",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 2081273,
            "range": "± 6103",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2371061,
            "range": "± 98335",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 16334218,
            "range": "± 337394",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 237996,
            "range": "± 2216",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1972320,
            "range": "± 5211",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 240278,
            "range": "± 1453",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1974945,
            "range": "± 4944",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 252743,
            "range": "± 4005",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1986115,
            "range": "± 3895",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 348687,
            "range": "± 947",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 2074974,
            "range": "± 12471",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 586806,
            "range": "± 58467",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 252420,
            "range": "± 440",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 254293,
            "range": "± 9336",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 252080,
            "range": "± 561",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 253556,
            "range": "± 1275",
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 875,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 914,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 6280,
            "range": "± 113",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 293,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 331,
            "range": "± 10",
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
          "id": "c8f05722e209c72795e403977d411931bdaaf776",
          "message": "chore: use rust-cicd-template base image",
          "timestamp": "2026-04-23T12:20:42Z",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/pull/10/commits/c8f05722e209c72795e403977d411931bdaaf776"
        },
        "date": 1777647793232,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 203321309,
            "range": "± 162024169",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 774262813,
            "range": "± 630428352",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2724071086,
            "range": "± 1733552181",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 238137,
            "range": "± 7659",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 239082,
            "range": "± 3104",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 251020,
            "range": "± 724",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 344217,
            "range": "± 9381",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1967125,
            "range": "± 3520",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1979639,
            "range": "± 7352",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1990204,
            "range": "± 4102",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 2072255,
            "range": "± 3222",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 238756,
            "range": "± 968",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 239052,
            "range": "± 651",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 239229,
            "range": "± 597",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 238614,
            "range": "± 609",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 239271,
            "range": "± 1358",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 238741,
            "range": "± 953",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 1091,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 1127,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 497,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 509,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2071,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2230,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1561,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1651,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 10968,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 12137,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11331,
            "range": "± 222",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 12139,
            "range": "± 240",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 78784,
            "range": "± 209",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 88519,
            "range": "± 273",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 91605,
            "range": "± 329",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 97518,
            "range": "± 543",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 576,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 584,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 289042,
            "range": "± 10856",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 2028840,
            "range": "± 10172",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 296870,
            "range": "± 2099",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 2034695,
            "range": "± 8054",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 335775,
            "range": "± 1132",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 2079325,
            "range": "± 39531",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2360574,
            "range": "± 9086",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 16359482,
            "range": "± 58951",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 238517,
            "range": "± 683",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1962611,
            "range": "± 3942",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 239541,
            "range": "± 2884",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1964768,
            "range": "± 49204",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 251857,
            "range": "± 1259",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1980450,
            "range": "± 6508",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 348537,
            "range": "± 821",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 2067878,
            "range": "± 4518",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 583894,
            "range": "± 5791",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 250714,
            "range": "± 1558",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 254847,
            "range": "± 726",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 250450,
            "range": "± 1773",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 251899,
            "range": "± 2694",
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 877,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 924,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 6300,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 290,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 332,
            "range": "± 2",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}