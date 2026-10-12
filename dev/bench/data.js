window.BENCHMARK_DATA = {
  "lastUpdate": 1791844234725,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6f7e1ad0db49f164b6b529f227cd435b94048ea4",
          "message": "chore(deps): bump zeroize (#28)\n\nBumps the rust-minor-patch group with 1 update: [zeroize](https://github.com/RustCrypto/utils).\n\n\nUpdates `zeroize` from 1.9.0 to 1.9.1\n- [Commits](https://github.com/RustCrypto/utils/compare/zeroize-v1.9.0...zeroize-v1.9.1)\n\n---\nupdated-dependencies:\n- dependency-name: zeroize\n  dependency-version: 1.9.1\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: rust-minor-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-12T18:12:05-04:00",
          "tree_id": "ad040a09b8d6f7104ce44bc800e599413d796f68",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/6f7e1ad0db49f164b6b529f227cd435b94048ea4"
        },
        "date": 1791844234224,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 178830064,
            "range": "± 97588227",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 691187104,
            "range": "± 523788292",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 1742717036,
            "range": "± 1421921063",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 183828,
            "range": "± 339",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 185638,
            "range": "± 386",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 193968,
            "range": "± 3310",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 269712,
            "range": "± 643",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1525360,
            "range": "± 16317",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1529345,
            "range": "± 6086",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1533741,
            "range": "± 18762",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1611966,
            "range": "± 19979",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 185697,
            "range": "± 365",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 185874,
            "range": "± 2762",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 184610,
            "range": "± 1666",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 184452,
            "range": "± 343",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 184162,
            "range": "± 834",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 184413,
            "range": "± 1070",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 894,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 912,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 405,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 422,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 1745,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 1854,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1239,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1310,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 8370,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 9262,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 8745,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 9447,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 64652,
            "range": "± 331",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 71611,
            "range": "± 223",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 72769,
            "range": "± 271",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 78419,
            "range": "± 308",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 449,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 451,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 222230,
            "range": "± 509",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1569345,
            "range": "± 38407",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 230320,
            "range": "± 668",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1573860,
            "range": "± 11624",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 258059,
            "range": "± 5155",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1600486,
            "range": "± 16769",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 1815800,
            "range": "± 9984",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 12548277,
            "range": "± 80030",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 184727,
            "range": "± 365",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1523262,
            "range": "± 18977",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 186261,
            "range": "± 329",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1528014,
            "range": "± 13391",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 194132,
            "range": "± 1183",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1535549,
            "range": "± 23540",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 269386,
            "range": "± 12793",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1609648,
            "range": "± 20251",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 454563,
            "range": "± 13873",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 194621,
            "range": "± 490",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 196030,
            "range": "± 989",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 194428,
            "range": "± 1633",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 194559,
            "range": "± 332",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/config_default",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "configuration_overhead/config_builder",
            "value": 9,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data",
            "value": 697,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 726,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5163,
            "range": "± 116",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/empty_data_decrypt",
            "value": 243,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte_decrypt",
            "value": 278,
            "range": "± 5",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}