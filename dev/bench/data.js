window.BENCHMARK_DATA = {
  "lastUpdate": 1791365509651,
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
          "id": "0898eed21fe5dc7c792a6da6b22ff90c5f81a3ad",
          "message": "ci(release): write the Windows checksum with an LF line ending (#27)\n\nThe Package (Windows) step wrote the \"<hash>  <archive>\" line with\nOut-File, which ends it in CRLF. `shasum -a 256 -c` and macOS\n`sha256sum -c` then look for a file named \"<archive>\\r\" and fail, so the\npublished Windows checksum could not be verified there. Write the line\nwith [System.IO.File]::WriteAllText and an explicit LF, the step\nrust-cicd-template, threatflux-unifi-sdk and file-scanner already use,\nand record the fix in the changelog.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-10-07T05:11:53-04:00",
          "tree_id": "397fc3297afa9490186b72510dc4d1ebb4ff20cc",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/0898eed21fe5dc7c792a6da6b22ff90c5f81a3ad"
        },
        "date": 1791365509080,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 183781067,
            "range": "± 112971949",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 717629303,
            "range": "± 562949743",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2193226681,
            "range": "± 1579175467",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 211699,
            "range": "± 4276",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 214226,
            "range": "± 546",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 246726,
            "range": "± 532",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 316460,
            "range": "± 1704",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1747729,
            "range": "± 123895",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1749907,
            "range": "± 17929",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1759334,
            "range": "± 16764",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1861610,
            "range": "± 22210",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 215105,
            "range": "± 816",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 215169,
            "range": "± 650",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 214180,
            "range": "± 465",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 214233,
            "range": "± 5315",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 214378,
            "range": "± 549",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 211793,
            "range": "± 18585",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 970,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 996,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 442,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 467,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 4547,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 4693,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1505,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1665,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 34363,
            "range": "± 558",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 35439,
            "range": "± 418",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10876,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11887,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 79671,
            "range": "± 1705",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 91614,
            "range": "± 368",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 90645,
            "range": "± 452",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 97475,
            "range": "± 320",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 464,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 467,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 266191,
            "range": "± 1418",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1837677,
            "range": "± 11270",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 277122,
            "range": "± 1158",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1829220,
            "range": "± 21104",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 336151,
            "range": "± 3477",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1859173,
            "range": "± 32399",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2318541,
            "range": "± 8271",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14488150,
            "range": "± 36887",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 209947,
            "range": "± 753",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1771086,
            "range": "± 9118",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 211179,
            "range": "± 1300",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1767837,
            "range": "± 15131",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 245290,
            "range": "± 738",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1778186,
            "range": "± 24414",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 314910,
            "range": "± 1505",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1876255,
            "range": "± 17759",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 545852,
            "range": "± 4170",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 222790,
            "range": "± 817",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 224301,
            "range": "± 638",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 222354,
            "range": "± 1378",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 222499,
            "range": "± 2830",
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
            "value": 734,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 773,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5339,
            "range": "± 129",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 262,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 301,
            "range": "± 2",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}