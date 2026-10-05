#!/usr/bin/env python3
"""Require immutable action and reusable-workflow references."""
import re
from pathlib import Path


def main():
    count = 0
    for path in sorted(Path('.github/workflows').glob('*.yml')):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = re.search(r'\buses:\s*(\S+)', line)
            if not match:
                continue
            reference = match[1]
            if not re.fullmatch(r'[^@]+@[0-9a-f]{40}', reference):
                raise SystemExit(f'{path}:{number}: expected a full commit SHA')
            count += 1
    if count == 0:
        raise SystemExit('no action references found')
    print(f'Validated {count} immutable action/workflow references')


if __name__ == '__main__':
    main()
