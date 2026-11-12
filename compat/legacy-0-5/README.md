This isolated workspace deliberately keeps the published `fluxencrypt = 0.5.0`
consumer as a historical compatibility baseline. It is not a production
dependency or a member of the current release workspace.

The fixed fixture uses a public all-zero AES-256 key and nonce
`000102030405060708090a0b`. It was generated independently using Node's standard
AES-256-GCM implementation and the original `base64(nonce || ciphertext || tag)`
layout. GitHub CI checks those exact bytes with both the published 0.5 library
and current source, then checks bidirectional interoperability for rollback.

The legacy implementation is not used for real secrets or private RSA work.
Keep its exact version and lockfile when updating active dependencies. Tests
run on GitHub; local contributor gates remain formatting and lint.
