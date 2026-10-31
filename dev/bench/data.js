window.BENCHMARK_DATA = {
  "lastUpdate": 1793431737302,
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
          "id": "f358d3fa934c0362f8c9ea76e45dbc4424635bcc",
          "message": "chore: release v0.7.11",
          "timestamp": "2026-10-31T07:08:18Z",
          "tree_id": "b9fa2137f33d6b38047affda6bbfde9bef4b0e36",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/f358d3fa934c0362f8c9ea76e45dbc4424635bcc"
        },
        "date": 1793431736877,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 180555944,
            "range": "± 131452355",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 865300365,
            "range": "± 647364358",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2322722236,
            "range": "± 1483955982",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 236353,
            "range": "± 1972",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 238056,
            "range": "± 2019",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 249094,
            "range": "± 707",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 350676,
            "range": "± 1019",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1199374,
            "range": "± 15385",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1199849,
            "range": "± 30556",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1212818,
            "range": "± 21924",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1315080,
            "range": "± 31241",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 237139,
            "range": "± 978",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 236935,
            "range": "± 759",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 237492,
            "range": "± 977",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 237873,
            "range": "± 9911",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 237447,
            "range": "± 689",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 237690,
            "range": "± 1138",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 951,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 981,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 426,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 456,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1882,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2025,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1462,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1594,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 10257,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 11337,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10817,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11900,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 82134,
            "range": "± 212",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 90883,
            "range": "± 236",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 96510,
            "range": "± 999",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 102096,
            "range": "± 2072",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 482,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 480,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 288168,
            "range": "± 4987",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1275502,
            "range": "± 28299",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 298752,
            "range": "± 1297",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1288280,
            "range": "± 21355",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 336825,
            "range": "± 1965",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1309353,
            "range": "± 28353",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2339803,
            "range": "± 32613",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 10069145,
            "range": "± 58076",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 236674,
            "range": "± 1714",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1205059,
            "range": "± 21097",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 237960,
            "range": "± 3157",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1196690,
            "range": "± 19928",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 248718,
            "range": "± 1294",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1206674,
            "range": "± 25746",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 342665,
            "range": "± 6242",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1307210,
            "range": "± 9730",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 594555,
            "range": "± 11070",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 247429,
            "range": "± 929",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 248870,
            "range": "± 1226",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 247355,
            "range": "± 474",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 247353,
            "range": "± 1389",
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
            "value": 760,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 784,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5483,
            "range": "± 33",
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
            "range": "± 3",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}