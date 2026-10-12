window.BENCHMARK_DATA = {
  "lastUpdate": 1791844353583,
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
      },
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
          "id": "4e398c9724fff8f33d1a09a97f4e68a45b090bdc",
          "message": "chore(ci): bump the github-actions group with 8 updates (#29)\n\nBumps the github-actions group with 8 updates:\n\n| Package | From | To |\n| --- | --- | --- |\n| [ThreatFlux/github_actions/.github/workflows/reusable-auto-release.yml](https://github.com/threatflux/github_actions) | `0.7.7` | `0.7.8` |\n| [dtolnay/rust-toolchain](https://github.com/dtolnay/rust-toolchain) | `7e38f4b43b4db5c8dd498af069a4f6196df1d067` | `e2a55d2ffb04f378e9626c28d38b36d230d1e12f` |\n| [taiki-e/install-action](https://github.com/taiki-e/install-action) | `2.87.25` | `2.87.27` |\n| [actions/upload-artifact](https://github.com/actions/upload-artifact) | `7.0.1` | `7.0.2` |\n| [github/codeql-action/init](https://github.com/github/codeql-action) | `4.38.2` | `4.38.3` |\n| [github/codeql-action/analyze](https://github.com/github/codeql-action) | `4.38.2` | `4.38.3` |\n| [actions/download-artifact](https://github.com/actions/download-artifact) | `8.0.1` | `8.0.2` |\n| [github/codeql-action/upload-sarif](https://github.com/github/codeql-action) | `4.38.2` | `4.38.3` |\n\n\nUpdates `ThreatFlux/github_actions/.github/workflows/reusable-auto-release.yml` from 0.7.7 to 0.7.8\n- [Release notes](https://github.com/threatflux/github_actions/releases)\n- [Changelog](https://github.com/ThreatFlux/github_actions/blob/main/docs/CHANGELOG.md)\n- [Commits](https://github.com/threatflux/github_actions/compare/eb9f3cf78c3899be0c4c9323d5cc86de5e1fdee8...ad88f2f0cc91e6a4f2737040af917e732a53e7cc)\n\nUpdates `dtolnay/rust-toolchain` from 7e38f4b43b4db5c8dd498af069a4f6196df1d067 to e2a55d2ffb04f378e9626c28d38b36d230d1e12f\n- [Release notes](https://github.com/dtolnay/rust-toolchain/releases)\n- [Commits](https://github.com/dtolnay/rust-toolchain/compare/7e38f4b43b4db5c8dd498af069a4f6196df1d067...e2a55d2ffb04f378e9626c28d38b36d230d1e12f)\n\nUpdates `taiki-e/install-action` from 2.87.25 to 2.87.27\n- [Release notes](https://github.com/taiki-e/install-action/releases)\n- [Changelog](https://github.com/taiki-e/install-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/taiki-e/install-action/compare/183e4297cca2404691e9380e1307288dced5c82a...ab6895351a88b908e96a4697860d4ffea5e57dbe)\n\nUpdates `actions/upload-artifact` from 7.0.1 to 7.0.2\n- [Release notes](https://github.com/actions/upload-artifact/releases)\n- [Commits](https://github.com/actions/upload-artifact/compare/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a...cf430e030ddbb5b0abf93d22962f4752f3646cd9)\n\nUpdates `github/codeql-action/init` from 4.38.2 to 4.38.3\n- [Release notes](https://github.com/github/codeql-action/releases)\n- [Changelog](https://github.com/github/codeql-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/github/codeql-action/compare/2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2...24c54180a607b1449ed407dd24f251e4e9147c8d)\n\nUpdates `github/codeql-action/analyze` from 4.38.2 to 4.38.3\n- [Release notes](https://github.com/github/codeql-action/releases)\n- [Changelog](https://github.com/github/codeql-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/github/codeql-action/compare/2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2...24c54180a607b1449ed407dd24f251e4e9147c8d)\n\nUpdates `actions/download-artifact` from 8.0.1 to 8.0.2\n- [Release notes](https://github.com/actions/download-artifact/releases)\n- [Commits](https://github.com/actions/download-artifact/compare/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c...9000827ccba6bdab643e8b6fd33ac0654aef8333)\n\nUpdates `github/codeql-action/upload-sarif` from 4.38.2 to 4.38.3\n- [Release notes](https://github.com/github/codeql-action/releases)\n- [Changelog](https://github.com/github/codeql-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/github/codeql-action/compare/2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2...24c54180a607b1449ed407dd24f251e4e9147c8d)\n\n---\nupdated-dependencies:\n- dependency-name: ThreatFlux/github_actions/.github/workflows/reusable-auto-release.yml\n  dependency-version: 0.7.8\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: github-actions\n- dependency-name: dtolnay/rust-toolchain\n  dependency-version: e2a55d2ffb04f378e9626c28d38b36d230d1e12f\n  dependency-type: direct:production\n  dependency-group: github-actions\n- dependency-name: taiki-e/install-action\n  dependency-version: 2.87.27\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: github-actions\n- dependency-name: actions/upload-artifact\n  dependency-version: 7.0.2\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: github-actions\n- dependency-name: github/codeql-action/init\n  dependency-version: 4.38.3\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: github-actions\n- dependency-name: github/codeql-action/analyze\n  dependency-version: 4.38.3\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: github-actions\n- dependency-name: actions/download-artifact\n  dependency-version: 8.0.2\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: github-actions\n- dependency-name: github/codeql-action/upload-sarif\n  dependency-version: 4.38.3\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n  dependency-group: github-actions\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-10-12T18:12:18-04:00",
          "tree_id": "e5a6ccd00273fd2f036bffd2040ac1bca7d81548",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/4e398c9724fff8f33d1a09a97f4e68a45b090bdc"
        },
        "date": 1791844352782,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 171736620,
            "range": "± 96694615",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 809933713,
            "range": "± 491551927",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2180516970,
            "range": "± 1627609573",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 210641,
            "range": "± 446",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 214045,
            "range": "± 835",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 243259,
            "range": "± 675",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/524288",
            "value": 317899,
            "range": "± 1966",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/1024",
            "value": 1746754,
            "range": "± 16441",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/8192",
            "value": 1748292,
            "range": "± 19758",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/65536",
            "value": 1761031,
            "range": "± 20438",
            "unit": "ns/iter"
          },
          {
            "name": "decryption/hybrid/524288",
            "value": 1870502,
            "range": "± 29799",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes128Gcm",
            "value": 213069,
            "range": "± 639",
            "unit": "ns/iter"
          },
          {
            "name": "cipher_suites/encrypt/Aes256Gcm",
            "value": 211113,
            "range": "± 673",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/default",
            "value": 210940,
            "range": "± 1425",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/small_chunks",
            "value": 211394,
            "range": "± 923",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/large_chunks",
            "value": 211009,
            "range": "± 712",
            "unit": "ns/iter"
          },
          {
            "name": "configurations/encrypt/no_hw_accel",
            "value": 211127,
            "range": "± 868",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/1024",
            "value": 972,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/1024",
            "value": 995,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/1024",
            "value": 425,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/1024",
            "value": 471,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/8192",
            "value": 2045,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/8192",
            "value": 2087,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/8192",
            "value": 1487,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/8192",
            "value": 1638,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/65536",
            "value": 30420,
            "range": "± 232",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/65536",
            "value": 31482,
            "range": "± 475",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/65536",
            "value": 10830,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/65536",
            "value": 11931,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_encrypt/524288",
            "value": 78955,
            "range": "± 679",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_encrypt/524288",
            "value": 88923,
            "range": "± 1461",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes128_decrypt/524288",
            "value": 95773,
            "range": "± 1503",
            "unit": "ns/iter"
          },
          {
            "name": "aes_gcm/aes256_decrypt/524288",
            "value": 98004,
            "range": "± 1076",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes128",
            "value": 459,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "aes_key_generation/aes256",
            "value": 458,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/1024",
            "value": 269152,
            "range": "± 2516",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/1024",
            "value": 1836599,
            "range": "± 23762",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/8192",
            "value": 281200,
            "range": "± 1744",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/8192",
            "value": 1848852,
            "range": "± 22650",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/65536",
            "value": 336719,
            "range": "± 1521",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/65536",
            "value": 1864167,
            "range": "± 13371",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_encrypt/524288",
            "value": 2340734,
            "range": "± 17457",
            "unit": "ns/iter"
          },
          {
            "name": "file_operations/file_decrypt/524288",
            "value": 14549260,
            "range": "± 55010",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/1024",
            "value": 210444,
            "range": "± 2349",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/1024",
            "value": 1764796,
            "range": "± 22477",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/8192",
            "value": 211871,
            "range": "± 2608",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/8192",
            "value": 1771468,
            "range": "± 9780",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/65536",
            "value": 243263,
            "range": "± 1542",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/65536",
            "value": 1783943,
            "range": "± 29548",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_encrypt/524288",
            "value": 326318,
            "range": "± 1537",
            "unit": "ns/iter"
          },
          {
            "name": "cryptum_api/cryptum_decrypt/524288",
            "value": 1933807,
            "range": "± 26650",
            "unit": "ns/iter"
          },
          {
            "name": "concurrent_operations/concurrent_encrypt_4_threads",
            "value": 564164,
            "range": "± 5480",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/zeros",
            "value": 223101,
            "range": "± 1064",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/ones",
            "value": 225356,
            "range": "± 1369",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/sequential",
            "value": 222622,
            "range": "± 572",
            "unit": "ns/iter"
          },
          {
            "name": "memory_patterns/encrypt/random_pattern",
            "value": 222948,
            "range": "± 1030",
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
            "value": 729,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/single_byte",
            "value": 771,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "edge_cases/large_aad",
            "value": 5336,
            "range": "± 64",
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
            "value": 301,
            "range": "± 3",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}