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

expected_product_packages = {
    "rust/Cargo.lock": {
        "hns-browser-setup",
        "hns-chromium-native-host",
        "hns-chromium-platform-runtime",
    },
}
for relative, names in expected_product_packages.items():
    with (root / relative).open("rb") as handle:
        packages = tomllib.load(handle)["package"]
    locked = {package["name"]: package["version"] for package in packages}
    for name in sorted(names):
        actual = locked.get(name)
        if actual != rust_version:
            raise SystemExit(
                f"{relative}: {name} is {actual or 'missing'}; expected {rust_version}"
            )

expected_engine_packages = {
    "rust/fuzz/Cargo.lock": {
        "hns-browser-dane": "0.2.0",
        "hns-browser-dnssec": "0.2.0",
        "hns-browser-p2p": "0.2.0",
        "hns-browser-primitives": "0.2.0",
        "hns-browser-urkel": "0.2.0",
    },
    "tools/hns-header-snapshot-exporter/Cargo.lock": {
        "hns-browser-chain": "0.2.0",
        "hns-browser-p2p": "0.2.0",
        "hns-browser-primitives": "0.2.0",
        "hns-browser-sync": "0.2.0",
        "hns-browser-urkel": "0.2.0",
    },
}
for relative, expected in expected_engine_packages.items():
    with (root / relative).open("rb") as handle:
        packages = tomllib.load(handle)["package"]
    actual = sorted(
        (package["name"], package["version"])
        for package in packages
        if package["name"].startswith("hns-browser-")
    )
    wanted = sorted(expected.items())
    if actual != wanted:
        raise SystemExit(
            f"{relative}: consolidated engine packages are {actual}; expected {wanted}"
        )

print(
    f"Chromium extension, native host, Setup application, and Rust workspace "
    f"agree on {rust_version}; standalone tools pin the expected consolidated "
    f"hns-browser packages."
)
PY
