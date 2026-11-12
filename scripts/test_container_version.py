"""Container release names must match the three crates and the compiled CLI."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "container_version", Path(__file__).with_name("container-version.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ROOT = Path(__file__).resolve().parents[1]


def fixture(root):
    (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.8.0"\n')
    for name in MODULE.PACKAGES:
        directory = root / name
        directory.mkdir()
        (directory / "Cargo.toml").write_text(
            f'[package]\nname = "{name}"\nversion.workspace = true\n'
        )


class ContainerVersionTests(unittest.TestCase):
    def test_release_tag_matches_all_inherited_package_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            self.assertEqual(MODULE.expected_version(root, "tag", "v0.8.0"), "0.8.0")
            with self.assertRaisesRegex(ValueError, "differs from manifest"):
                MODULE.expected_version(root, "tag", "v0.8.1")

    def test_explicit_member_mismatch_refuses_a_mixed_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            (root / "fluxencrypt-async/Cargo.toml").write_text(
                '[package]\nname = "fluxencrypt-async"\nversion = "0.7.12"\n'
            )
            with self.assertRaisesRegex(ValueError, "all three crates"):
                MODULE.expected_version(root, "tag", "v0.8.0")

    def test_branch_images_keep_branch_names_without_relabeling_as_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root)
            self.assertEqual(MODULE.expected_version(root, "branch", "main"), "0.8.0")

    def test_actual_compiled_version_must_match_the_source_manifest(self):
        MODULE.verify_reported("fluxencrypt-cli 0.8.0", "0.8.0")
        for reported in ["fluxencrypt-cli 0.7.12", "", "fluxencrypt-cli 0.8.1"]:
            with self.subTest(reported=reported), self.assertRaises(ValueError):
                MODULE.verify_reported(reported, "0.8.0")

    def test_real_workflow_binds_before_build_and_checks_every_platform(self):
        source = (ROOT / ".github/workflows/docker.yml").read_text(encoding="utf-8")
        self.assertLess(
            source.index("name: Verify container package version"),
            source.index("name: Build and push image by digest"),
        )
        smoke = source.split("smoke_test() {", 1)[1].split("\n        }", 1)[0]
        self.assertIn(
            'python3 scripts/container-version.py --reported "${reported}"', smoke
        )
        self.assertIn('smoke_test "${platform}" "${PUSHED_IMAGE}"', source)
        publish = source.split("  publish:\n", 1)[1].split("    steps:", 1)[0]
        self.assertIn("needs: [build, scan, sign, sbom]", publish)
        self.assertIn("flavor: latest=false", source)


if __name__ == "__main__":
    unittest.main()
