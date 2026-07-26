#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

python3 - <<'PY'
import json
from pathlib import Path
import tomllib

root = Path.cwd()
with (root / "rust/Cargo.toml").open("rb") as handle:
    rust_version = tomllib.load(handle)["workspace"]["package"]["version"]
package_version = json.loads((root / "package.json").read_text(encoding="utf-8"))["version"]
manifest_version = json.loads(
    (root / "extension/manifest.json").read_text(encoding="utf-8")
)["version"]

versions = {
    "Rust workspace": rust_version,
    "package.json": package_version,
    "Chromium manifest": manifest_version,
}
if len(set(versions.values())) != 1:
    raise SystemExit(
        "Chromium release versions disagree: "
        + ", ".join(f"{name}={value}" for name, value in versions.items())
    )

expected_packages = {
    "rust/Cargo.lock": {
        "hns-chromium-native-host",
        "hns-chromium-platform-runtime",
    },
    "rust/fuzz/Cargo.lock": {
        "hns-core",
        "hns-dane",
        "hns-p2p",
        "hns-urkel",
    },
    "tools/hns-header-snapshot-exporter/Cargo.lock": {
        "hns-chain",
        "hns-core",
        "hns-p2p",
        "hns-sync",
    },
}
for relative, names in expected_packages.items():
    with (root / relative).open("rb") as handle:
        packages = tomllib.load(handle)["package"]
    locked = {package["name"]: package["version"] for package in packages}
    for name in sorted(names):
        actual = locked.get(name)
        if actual != rust_version:
            raise SystemExit(
                f"{relative}: {name} is {actual or 'missing'}; expected {rust_version}"
            )

print(f"Chromium extension, native host, and Rust workspace agree on {rust_version}.")
PY
