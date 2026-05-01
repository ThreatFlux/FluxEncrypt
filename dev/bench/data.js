window.BENCHMARK_DATA = {
  "lastUpdate": 1777651959664,
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
          "id": "3309176c13c278061b4a1bf3cd8de861d7273d0a",
          "message": "chore: use rust-cicd-template base image",
          "timestamp": "2026-04-23T12:20:42Z",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/pull/10/commits/3309176c13c278061b4a1bf3cd8de861d7273d0a"
        },
        "date": 1777647845046,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 186772250,
            "range": "± 113154570",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 764640775,
            "range": "± 513808779",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2326155725,
            "range": "± 1879526208",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 237175,
            "range": "± 1984",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 241601,
            "range": "± 484",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 270855,
            "range": "± 998",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 350430,
            "range": "± 1187",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1951960,
            "range": "± 5698",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1958130,
            "range": "± 25401",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1970031,
            "range": "± 4170",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 2071903,
            "range": "± 6039",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 240686,
            "range": "± 523",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 240906,
            "range": "± 914",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 238607,
            "range": "± 33600",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 238565,
            "range": "± 1205",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 238509,
            "range": "± 1039",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 238404,
            "range": "± 751",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 946,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 985,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 441,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 443,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 4513,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 4659,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1500,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1647,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 40853,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 41948,
            "range": "± 3488",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 11116,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 12024,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 92384,
            "range": "± 445",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 91951,
            "range": "± 745",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 97229,
            "range": "± 502",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 101882,
            "range": "± 364",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 456,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 474,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 295451,
            "range": "± 1709",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 2030609,
            "range": "± 134658",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 305592,
            "range": "± 3965",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 2027367,
            "range": "± 5054",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 372481,
            "range": "± 1856",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 2063031,
            "range": "± 71713",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2602725,
            "range": "± 9902",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 16183277,
            "range": "± 40426",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 236621,
            "range": "± 829",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1950918,
            "range": "± 6879",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 237846,
            "range": "± 501",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1952116,
            "range": "± 3332",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 280515,
            "range": "± 636",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1965662,
            "range": "± 3370",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 352821,
            "range": "± 1257",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 2081726,
            "range": "± 6035",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 618272,
            "range": "± 6159",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 249928,
            "range": "± 707",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 249919,
            "range": "± 886",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 248035,
            "range": "± 1118",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 247722,
            "range": "± 3527",
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
            "value": 11,
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
            "value": 720,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 764,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5296,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 261,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 299,
            "range": "± 3",
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
          "id": "d4fe687c5272a236e579b7b1d32d0f76860241e2",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-23T12:20:42Z",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/pull/11/commits/d4fe687c5272a236e579b7b1d32d0f76860241e2"
        },
        "date": 1777651870649,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 177957031,
            "range": "± 99378162",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 645858494,
            "range": "± 555579664",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 1855821110,
            "range": "± 1556126660",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 207429,
            "range": "± 391",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 212022,
            "range": "± 2186",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 218638,
            "range": "± 1154",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 316664,
            "range": "± 625",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1690976,
            "range": "± 5046",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1694230,
            "range": "± 5594",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1717501,
            "range": "± 10215",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1816225,
            "range": "± 20037",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 207106,
            "range": "± 136",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 206827,
            "range": "± 1148",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 210044,
            "range": "± 478",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 215363,
            "range": "± 589",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 209152,
            "range": "± 201",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 208860,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 826,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 872,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 391,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 420,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1709,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 1846,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1371,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1493,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 9732,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 10765,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10663,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11577,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 95456,
            "range": "± 376",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 103808,
            "range": "± 710",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 94710,
            "range": "± 182",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 101662,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 341,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 343,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 229506,
            "range": "± 426",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1719255,
            "range": "± 20679",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 233436,
            "range": "± 577",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1744240,
            "range": "± 9065",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 256005,
            "range": "± 1541",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1741357,
            "range": "± 5263",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 1938791,
            "range": "± 3516",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 13804348,
            "range": "± 42560",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 206704,
            "range": "± 11155",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1705578,
            "range": "± 4062",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 208072,
            "range": "± 186",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1707829,
            "range": "± 4173",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 218010,
            "range": "± 359",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1715653,
            "range": "± 6286",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 327012,
            "range": "± 2035",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1829886,
            "range": "± 28027",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 484313,
            "range": "± 3473",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 217730,
            "range": "± 232",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 219297,
            "range": "± 1505",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 217983,
            "range": "± 594",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 217878,
            "range": "± 858",
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
            "value": 8,
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 585,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 621,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5066,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 229,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 269,
            "range": "± 4",
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
          "id": "3075f0568e641cf61049df2c2211888067e80693",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-23T12:20:42Z",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/pull/11/commits/3075f0568e641cf61049df2c2211888067e80693"
        },
        "date": 1777651958079,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 173792721,
            "range": "± 105557306",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 699985947,
            "range": "± 492125219",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 1896771427,
            "range": "± 1723099343",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 205516,
            "range": "± 218",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 207409,
            "range": "± 280",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 216852,
            "range": "± 522",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 317107,
            "range": "± 5198",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1688303,
            "range": "± 14608",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1692572,
            "range": "± 8867",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1697490,
            "range": "± 5394",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1814831,
            "range": "± 23386",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 206858,
            "range": "± 2340",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 207306,
            "range": "± 615",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 207809,
            "range": "± 640",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 207942,
            "range": "± 295",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 206803,
            "range": "± 734",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 206930,
            "range": "± 394",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 828,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 859,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 402,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 427,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1715,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 1857,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1351,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1555,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 9913,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 10909,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10741,
            "range": "± 107",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11816,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 73151,
            "range": "± 1162",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 80826,
            "range": "± 179",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 98901,
            "range": "± 794",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 106042,
            "range": "± 448",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 341,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 343,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 227997,
            "range": "± 751",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1718429,
            "range": "± 4904",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 234076,
            "range": "± 591",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1722750,
            "range": "± 5410",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 256049,
            "range": "± 4421",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1769447,
            "range": "± 5099",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 1943829,
            "range": "± 4230",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 13889096,
            "range": "± 46867",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 204781,
            "range": "± 273",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1681914,
            "range": "± 15503",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 206462,
            "range": "± 236",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1683325,
            "range": "± 3164",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 217931,
            "range": "± 574",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1707037,
            "range": "± 8962",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 319347,
            "range": "± 3442",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1812721,
            "range": "± 25578",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 488331,
            "range": "± 6368",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 217951,
            "range": "± 1086",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 219156,
            "range": "± 306",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 217730,
            "range": "± 1839",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 217696,
            "range": "± 896",
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
            "value": 8,
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 591,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 627,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5068,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 233,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 262,
            "range": "± 5",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}