window.BENCHMARK_DATA = {
  "lastUpdate": 1757179535632,
  "repoUrl": "https://github.com/ThreatFlux/FluxEncrypt",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "c821a8eb08b4bee2156543110370b5be759beecf",
          "message": "fix: Fix literal overflow on 32-bit architectures\n\n- Replace hardcoded 100GB size limit with architecture-specific constants\n- Use 4GB limit for 32-bit systems (max usize value ~4.29GB)\n- Keep 100GB limit for 64-bit systems\n- Fixes cross-compilation for armv7-unknown-linux-gnueabihf target\n\nThe literal 100_000_000_000 exceeds the range of usize on 32-bit systems\nwhere usize max value is 4,294,967,295.",
          "timestamp": "2025-09-06T13:07:36-04:00",
          "tree_id": "66d228917cbd4a80ad4afda49771a2a1139d5bf6",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/c821a8eb08b4bee2156543110370b5be759beecf"
        },
        "date": 1757179025046,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 176421708,
            "range": "± 111611835",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 783844927,
            "range": "± 538855336",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2526135228,
            "range": "± 1708799802",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 234391,
            "range": "± 299",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 238438,
            "range": "± 1349",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 267237,
            "range": "± 588",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1048576",
            "value": 60,
            "range": "± 1",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "a3a1c450f4cbaef9b42fd054ef2cfad00f5e8622",
          "message": "style: Remove trailing whitespace in verify.rs\n\n- Applied cargo fmt to remove trailing whitespace\n- No functional changes",
          "timestamp": "2025-09-06T13:15:48-04:00",
          "tree_id": "71c0b5b959d0684847e66ae4b5356bf3a39a861e",
          "url": "https://github.com/ThreatFlux/FluxEncrypt/commit/a3a1c450f4cbaef9b42fd054ef2cfad00f5e8622"
        },
        "date": 1757179535209,
        "tool": "cargo",
        "benches": [
          {
            "name": "key_generation/rsa/2048",
            "value": 210627466,
            "range": "± 133270340",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/3072",
            "value": 779220113,
            "range": "± 545212000",
            "unit": "ns/iter"
          },
          {
            "name": "key_generation/rsa/4096",
            "value": 2515036500,
            "range": "± 1675280743",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1024",
            "value": 236713,
            "range": "± 377",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/8192",
            "value": 240580,
            "range": "± 499",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/65536",
            "value": 270560,
            "range": "± 1128",
            "unit": "ns/iter"
          },
          {
            "name": "encryption/hybrid/1048576",
            "value": 70,
            "range": "± 1",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}