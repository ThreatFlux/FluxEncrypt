window.BENCHMARK_DATA = {
  "lastUpdate": 1794619942802,
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
          "id": "d0efa4a32a1f6cf29f269f1a38d88b7ae9a3016a",
          "message": "chore: release v0.8.3",
          "timestamp": "2026-11-14T01:16:07Z",
          "tree_id": "dc4995d1d9a60008f325794f84dfa2d9496e092e",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/d0efa4a32a1f6cf29f269f1a38d88b7ae9a3016a"
        },
        "date": 1794619941623,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 45045669,
            "range": "± 31944264",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 193509889,
            "range": "± 146239526",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 566609386,
            "range": "± 558739640",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 64249,
            "range": "± 443",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 65432,
            "range": "± 522",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 76272,
            "range": "± 3020",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 174548,
            "range": "± 4356",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 867337,
            "range": "± 1844",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 871565,
            "range": "± 4596",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 878231,
            "range": "± 6533",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 987734,
            "range": "± 22672",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 65330,
            "range": "± 1261",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 65533,
            "range": "± 207",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 66078,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 65794,
            "range": "± 328",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 65848,
            "range": "± 307",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 65374,
            "range": "± 181",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 769,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 801,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 386,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 416,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1608,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 1751,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1358,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1462,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 10185,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 11181,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10757,
            "range": "± 148",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11844,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 71958,
            "range": "± 408",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 80134,
            "range": "± 317",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 95350,
            "range": "± 319",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 103444,
            "range": "± 384",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 320,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 324,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 84698,
            "range": "± 1567",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 906857,
            "range": "± 3394",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 90144,
            "range": "± 498",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 906094,
            "range": "± 5334",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 113128,
            "range": "± 514",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 932236,
            "range": "± 5584",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 799949,
            "range": "± 3758",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 7295694,
            "range": "± 353054",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 64295,
            "range": "± 313",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 868078,
            "range": "± 3283",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 65538,
            "range": "± 431",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 866621,
            "range": "± 3824",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 76979,
            "range": "± 644",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 879937,
            "range": "± 4190",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 169547,
            "range": "± 1161",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 984698,
            "range": "± 3098",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 230024,
            "range": "± 2805",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 76021,
            "range": "± 904",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 77519,
            "range": "± 522",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 75983,
            "range": "± 355",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 75931,
            "range": "± 646",
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
            "value": 562,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 596,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5035,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 222,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 260,
            "range": "± 6",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}