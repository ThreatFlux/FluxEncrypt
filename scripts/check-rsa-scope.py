#!/usr/bin/env python3
"""Guard the documented RustSec exception: no RustCrypto private operations.

This catches the former inner().decrypt path and private-operation imports;
it is a regression guard, not a whole-program constant-time proof.
"""
import re
from pathlib import Path


BLOCKED = (
    re.compile(r'\.inner\s*\(\s*\)\s*\.\s*(?:decrypt(?:_blinded)?|sign(?:_blinded|_with_rng)?)\s*\('),
    re.compile(r'\brsa\s*::\s*(?:hazmat|Pss|Pkcs1v15Sign)\b'),
    re.compile(r'\brsa\s*::\s*(?:pkcs1v15|pss)\s*::[^;]*\b(?:SigningKey|BlindedSigningKey)\b'),
)


def violations(source):
    return [pattern.pattern for pattern in BLOCKED if pattern.search(source)]


def main():
    errors = []
    for root in ('fluxencrypt/src', 'fluxencrypt-async/src', 'fluxencrypt-cli/src'):
        for path in Path(root).rglob('*.rs'):
            if violations(path.read_text()):
                errors.append(str(path))
    if errors:
        raise SystemExit('RustCrypto private RSA operations violate RUSTSEC-2023-0071 scope: ' + ', '.join(errors))
    print('RSA exception scope: no forbidden RustCrypto private-operation paths found')


if __name__ == '__main__':
    main()
