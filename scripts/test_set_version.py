"""Release preparation must retain path dependencies and feature flags."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('set_version', Path(__file__).with_name('set-version.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class VersionTests(unittest.TestCase):
    def test_updates_only_local_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[workspace.package]\nversion = "0.7.6"\n')
            member = '[dependencies]\nfluxencrypt = { version = "0.7.6", path = "../fluxencrypt", features = ["serde"] }\nclap = { version = "4.6.7", features = ["derive"] }\n'
            for name in ['fluxencrypt', 'fluxencrypt-cli', 'fluxencrypt-async']:
                (root / name).mkdir()
                (root / name / 'Cargo.toml').write_text(member)
            module.update_version(root, '0.7.7')
            self.assertIn('version = "0.7.7"', (root / 'Cargo.toml').read_text())
            for name in ['fluxencrypt', 'fluxencrypt-cli', 'fluxencrypt-async']:
                self.assertEqual((root / name / 'Cargo.toml').read_text(), member.replace('0.7.6', '0.7.7'))

    def test_rejects_untrusted_release_text_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in ['0.7.7; echo injected', '0.7.7"', '../0.7.7', '0.7']:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    module.update_version(root, value)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
