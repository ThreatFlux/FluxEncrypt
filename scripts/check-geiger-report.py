#!/usr/bin/env python3
"""Validate a native informational Geiger report without dropping diagnostics."""
import json
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit


def validate_metrics(metrics, name):
    if not isinstance(metrics, dict) or not isinstance(metrics.get('forbids_unsafe'), bool):
        raise ValueError(f'missing metrics for {name}')
    for scope in ['used', 'unused']:
        counts = metrics.get(scope)
        if not isinstance(counts, dict):
            raise ValueError(f'missing {scope} metrics for {name}')
        for counter in ['functions', 'exprs', 'item_impls', 'item_traits', 'methods']:
            values = counts.get(counter, {})
            for kind in ['safe', 'unsafe_']:
                value = values.get(kind)
                if type(value) is not int or value < 0:
                    raise ValueError(f'invalid {counter} count for {name}')


def validate_report(path, package):
    root = Path(__file__).resolve().parents[1]
    members = {'fluxencrypt', 'fluxencrypt-cli', 'fluxencrypt-async'}
    if package not in members:
        raise ValueError('unexpected workspace package')
    version = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']
    report = json.loads(path.read_text())
    for key in ['packages', 'packages_without_metrics', 'used_but_not_scanned_files']:
        if not isinstance(report.get(key), list):
            raise ValueError(f'expected native report array: {key}')
    expected = {package, 'fluxencrypt'}
    for name in expected:
        entries = [entry for entry in report['packages'] if entry.get('package', {}).get('id', {}).get('name') == name]
        if len(entries) != 1:
            raise ValueError(f'missing or duplicate metrics for {name}')
        entry = entries[0]
        identity = entry['package']['id']
        if identity.get('version') != version:
            raise ValueError(f'wrong package version for {name}')
        source = identity.get('source', {}).get('Path')
        if not isinstance(source, str):
            raise ValueError(f'expected path package for {name}')
        location = urlsplit(source)
        # Upstream may encode the Cargo package-id fragment into the file URL.
        local_path = Path(unquote(location.path).split('#', 1)[0]).resolve()
        if location.scheme != 'file' or location.netloc or local_path != root / name:
            raise ValueError(f'expected local workspace source for {name}')
        validate_metrics(entry.get('unsafety'), name)
    print(f'{package}: informational metrics for {len(report["packages"])} packages; '
          f'{len(report["used_but_not_scanned_files"])} unscanned input files retained')


if __name__ == '__main__':
    validate_report(Path(sys.argv[1]), sys.argv[2])
