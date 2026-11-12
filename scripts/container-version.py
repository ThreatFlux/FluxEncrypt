#!/usr/bin/env python3
"""Bind container tags and compiled CLI versions to the published crate family."""

import argparse
import os
import tomllib
from pathlib import Path

PACKAGES = ("fluxencrypt", "fluxencrypt-async", "fluxencrypt-cli")


def expected_version(root, ref_type, ref_name):
    with (root / "Cargo.toml").open("rb") as source:
        workspace = tomllib.load(source).get("workspace", {}).get("package", {})
    versions = set()
    for name in PACKAGES:
        with (root / name / "Cargo.toml").open("rb") as source:
            package = tomllib.load(source)["package"]
        if package["name"] != name:
            raise ValueError(f"{name}/Cargo.toml declares a different package")
        version = package.get("version")
        if isinstance(version, dict) and version.get("workspace") is True:
            version = workspace.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError(f"cannot resolve {name} version")
        versions.add(version)
    if len(versions) != 1:
        raise ValueError(
            "container release requires matching versions for all three crates"
        )
    version = versions.pop()
    if ref_type == "tag" and ref_name != "v" + version:
        raise ValueError(
            f"container tag {ref_name} differs from manifest version {version}"
        )
    return version


def verify_reported(reported, expected):
    words = reported.split()
    if not words or words[-1] != expected:
        raise ValueError(
            f"compiled CLI version differs from manifest version {expected}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reported", help="Actual CLI --version output from the built image"
    )
    args = parser.parse_args()
    version = expected_version(
        Path(__file__).resolve().parents[1],
        os.environ.get("GITHUB_REF_TYPE", ""),
        os.environ.get("GITHUB_REF_NAME", ""),
    )
    if args.reported is not None:
        verify_reported(args.reported, version)
    print(version)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from error
