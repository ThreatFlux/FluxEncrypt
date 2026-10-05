"""Reject missing, fabricated, or unrelated workspace inventory metrics."""
import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import tomllib
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('geiger_report', Path(__file__).with_name('check-geiger-report.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']


def report():
    metrics = {scope: {kind: {'safe': 1, 'unsafe_': 2} for kind in ['functions', 'exprs', 'item_impls', 'item_traits', 'methods']} for scope in ['used', 'unused']}
    metrics['forbids_unsafe'] = False
    identity = {'name': 'fluxencrypt', 'version': VERSION, 'source': {'Path': (ROOT / 'fluxencrypt').as_uri()}}
    return {'packages': [{'package': {'id': identity}, 'unsafety': metrics}], 'packages_without_metrics': [], 'used_but_not_scanned_files': ['generated/input.rs']}


class InventoryTests(unittest.TestCase):
    def validate(self, value, package='fluxencrypt'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(value))
            with contextlib.redirect_stdout(io.StringIO()):
                module.validate_report(path, package)

    def test_accepts_native_report_with_unsafe_counts_and_unscanned_inputs(self):
        self.validate(report())

    def test_rejects_missing_workspace_metrics_or_wrong_version(self):
        value = report()
        for change in ['missing', 'duplicate', 'version', 'source', 'empty_metrics', 'boolean_count']:
            invalid = copy.deepcopy(value)
            entry = invalid['packages'][0]
            if change == 'missing': invalid['packages'] = []
            if change == 'duplicate': invalid['packages'].append(copy.deepcopy(entry))
            if change == 'version': entry['package']['id']['version'] = '0.0.0'
            if change == 'source': entry['package']['id']['source'] = {'Path': ROOT.as_uri()}
            if change == 'empty_metrics': entry['unsafety'] = {}
            if change == 'boolean_count': entry['unsafety']['used']['exprs']['unsafe_'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(invalid)

    def test_rejects_unrelated_package_and_missing_report_schema(self):
        with self.assertRaises(ValueError):
            self.validate(report(), 'unrelated')
        with self.assertRaises(ValueError):
            self.validate({'packages': []})


if __name__ == '__main__':
    unittest.main()
