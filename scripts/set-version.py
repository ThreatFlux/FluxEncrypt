#!/usr/bin/env python3
"""Update workspace and local package requirements without changing features."""
import re
import sys
from pathlib import Path


def update_version(root, version):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?", version):
        raise ValueError("invalid release version")
    manifest = root / "Cargo.toml"
    source = manifest.read_text()
    source, count = re.subn(r'(?m)^version = "[^"]+"$', f'version = "{version}"', source)
    if count != 1:
        raise ValueError("expected exactly one workspace version")
    manifests = {manifest: source}
    for member in ["fluxencrypt", "fluxencrypt-cli", "fluxencrypt-async"]:
        path = root / member / "Cargo.toml"
        text = path.read_text()
        text = re.sub(r'(fluxencrypt(?:-async)? = \{ version = ")[^"]+("[^\n]+path = )',
                      lambda match: match[1] + version + match[2], text)
        manifests[path] = text
    for path, text in manifests.items():
        path.write_text(text)


if __name__ == "__main__":
    update_version(Path(__file__).resolve().parents[1], sys.argv[1])
