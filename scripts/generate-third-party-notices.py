#!/usr/bin/env python3
"""Generate the Chromium extension/native-host third-party notices.

Generation is deliberately offline. Rust package metadata and license files
come from Cargo's checksum-verified registry or immutable Git cache. The
lightweight ``--check`` mode verifies the complete asset digest and every
committed input fingerprint, so it is suitable for a clean CI checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from verify_cargo_git_policy import (
    ALLOWED_ENGINE_PACKAGES,
    ENGINE_LOCK_SOURCE,
)


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "extension/THIRD_PARTY_NOTICES.txt"
OUTPUT_SHA256 = ROOT / "scripts/third-party-notices.sha256"
SCHEMA = "3"
LOCKED_INPUT_PATHS = (
    "scripts/generate-third-party-notices.py",
    "scripts/verify_cargo_git_policy.py",
    "rust/Cargo.toml",
    "rust/Cargo.lock",
    "extension/manifest.json",
    "package.json",
)


def workspace_manifest_inputs() -> tuple[str, ...]:
    with (ROOT / "rust/Cargo.toml").open("rb") as handle:
        members = tomllib.load(handle).get("workspace", {}).get("members", [])
    if not isinstance(members, list) or not members:
        raise RuntimeError("The active Rust workspace has no explicit members.")
    manifests = []
    for member in members:
        if not isinstance(member, str) or "*" in member:
            raise RuntimeError(f"Unsupported Rust workspace member: {member!r}")
        relative = Path("rust") / member / "Cargo.toml"
        if not (ROOT / relative).is_file():
            raise RuntimeError(f"Missing active workspace manifest: {relative}")
        manifests.append(relative.as_posix())
    return tuple(sorted(manifests))


RUST_MANIFEST_INPUTS = workspace_manifest_inputs()
INPUT_PATHS = LOCKED_INPUT_PATHS + RUST_MANIFEST_INPUTS
LICENSE_FILE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")
MAX_NOTICE_FILE_SIZE = 512 * 1024
RUST_SHIPPING_TARGETS = (
    ("x86_64-unknown-linux-gnu", "hns-chromium-native-host"),
    ("aarch64-apple-darwin", "hns-chromium-native-host"),
    ("x86_64-pc-windows-msvc", "hns-chromium-native-host"),
)

# These registry packages are published without their workspace-level license
# files. The companion packages are from the same upstream project and release
# family and contain the project license texts named by the package manifest.
RUST_LICENSE_FILE_FALLBACKS = {
    ("asn1-rs-impl", "0.2.0"): ("asn1-rs", "0.7.2"),
    ("jni-sys-macros", "0.4.1"): ("jni-sys", "0.4.1"),
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def input_fingerprints() -> dict[str, str]:
    return {
        relative: sha256_bytes((ROOT / relative).read_bytes())
        for relative in INPUT_PATHS
    }


def check_committed_asset() -> int:
    if not OUTPUT.is_file():
        print(f"Missing generated third-party notices asset: {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
        return 1

    text = OUTPUT.read_text(encoding="utf-8")
    failures: list[str] = []
    expected_output_digest = ""
    if not OUTPUT_SHA256.is_file():
        failures.append(f"the committed digest file {OUTPUT_SHA256.relative_to(ROOT)} is missing")
    else:
        digest_fields = OUTPUT_SHA256.read_text(encoding="utf-8").strip().split()
        if len(digest_fields) != 2 or digest_fields[1] != OUTPUT.relative_to(ROOT).as_posix():
            failures.append("the committed asset digest record is malformed")
        elif not re.fullmatch(r"[0-9a-f]{64}", digest_fields[0]):
            failures.append("the committed asset digest is not a SHA-256 value")
        else:
            expected_output_digest = digest_fields[0]
    if expected_output_digest and sha256_bytes(OUTPUT.read_bytes()) != expected_output_digest:
        failures.append("the complete generated notices asset does not match its committed SHA-256")
    if not text.startswith(
        "HNS DANE BROWSER CHROMIUM THIRD-PARTY SOFTWARE NOTICES\n"
    ):
        failures.append("the generated marker is missing")
    if f"Generator schema: {SCHEMA}\n" not in text:
        failures.append("the generator schema is stale")
    for relative, digest in input_fingerprints().items():
        if f"  {relative} = {digest}\n" not in text:
            failures.append(f"the fingerprint for {relative} is stale")

    if not re.search(r"^RUST COMPONENTS \([1-9][0-9]*\)$", text, re.MULTILINE):
        failures.append("the Chromium native-host Rust inventory is missing")

    if failures:
        print("Third-party notices are stale:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        print(
            "Resolve the locked Cargo dependencies, then run "
            "python3 scripts/generate-third-party-notices.py.",
            file=sys.stderr,
        )
        return 1

    print("Third-party notices match the locked dependency inputs.")
    return 0


def cargo_metadata(target: str) -> dict:
    command = [
        "cargo",
        "+1.92.0",
        "metadata",
        "--offline",
        "--locked",
        "--manifest-path",
        str(ROOT / "rust/Cargo.toml"),
        "--filter-platform",
        target,
        "--format-version",
        "1",
    ]
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    try:
        output = subprocess.check_output(command, cwd=ROOT, env=environment)
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        raise RuntimeError(
            "Unable to read pinned Cargo metadata offline. Build the locked Rust workspace "
            "once to populate Cargo's verified registry cache."
        ) from error
    return json.loads(output)


def shipping_rust_packages(metadata: dict, root_package: str) -> list[dict]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [
        package["id"]
        for package in metadata["packages"]
        if package["name"] == root_package and package["source"] is None
    ]
    if len(roots) != 1:
        raise RuntimeError(
            f"Expected one workspace {root_package} package, found {len(roots)}."
        )

    reachable: set[str] = set()
    pending = roots[:]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        node = nodes[package_id]
        for dependency in node["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])

    third_party = [
        packages[package_id]
        for package_id in reachable
        if packages[package_id]["source"] is not None
    ]
    third_party.sort(key=lambda package: (package["name"].casefold(), package["version"]))
    if not third_party:
        raise RuntimeError(
            f"The {root_package} Rust dependency closure unexpectedly contains no external Cargo packages."
        )
    for package in third_party:
        if not package.get("license"):
            raise RuntimeError(
                f"Rust package {package['name']} {package['version']} has no declared license expression."
            )
    return third_party


def shipping_rust_packages_for_targets() -> tuple[list[dict], dict[str, int]]:
    packages_by_id: dict[str, dict] = {}
    target_counts: dict[str, int] = {}
    for target, root_package in RUST_SHIPPING_TARGETS:
        target_packages = shipping_rust_packages(cargo_metadata(target), root_package)
        target_counts[target] = len(target_packages)
        for package in target_packages:
            package_id = package["id"]
            existing = packages_by_id.get(package_id)
            if existing is not None and existing != package:
                raise RuntimeError(
                    f"Cargo returned conflicting metadata for package {package_id} "
                    f"across shipped application targets."
                )
            packages_by_id[package_id] = package

    packages = sorted(
        packages_by_id.values(),
        key=lambda package: (package["name"].casefold(), package["version"], package["id"]),
    )
    if not packages:
        raise RuntimeError("The shipped Rust target closures contain no external Cargo packages.")
    return packages, target_counts


def registry_license_files(package: dict) -> list[tuple[str, str]]:
    package_dir = Path(package["manifest_path"]).resolve().parent
    files: list[Path] = []
    for candidate in sorted(package_dir.rglob("*")):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        if candidate.name.upper().startswith(LICENSE_FILE_PREFIXES):
            files.append(candidate)
    license_file = package.get("license_file")
    if license_file:
        candidate = Path(license_file).resolve()
        try:
            candidate.relative_to(package_dir)
        except ValueError as error:
            raise RuntimeError(
                f"License file for {package['name']} escapes its verified registry package."
            ) from error
        if candidate not in files:
            files.append(candidate)

    result: list[tuple[str, str]] = []
    for candidate in sorted(files):
        size = candidate.stat().st_size
        if not 0 <= size <= MAX_NOTICE_FILE_SIZE:
            raise RuntimeError(f"License file has an unexpected size: {candidate}")
        try:
            content = candidate.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
        except UnicodeDecodeError as error:
            raise RuntimeError(f"License file is not UTF-8 text: {candidate}") from error
        if content:
            result.append((candidate.relative_to(package_dir).as_posix(), content))
    return result


def rust_package_license_files(package: dict) -> list[tuple[str, str]]:
    source = package.get("source")
    if not isinstance(source, str) or not source.startswith("git+"):
        return registry_license_files(package)

    name = package["name"]
    if source != ENGINE_LOCK_SOURCE or name not in ALLOWED_ENGINE_PACKAGES:
        raise RuntimeError(
            f"Unreviewed Cargo Git source for {name} {package['version']}: "
            f"{source}"
        )

    package_dir = Path(package["manifest_path"]).resolve().parent
    checkout_root = package_dir.parents[1]
    expected_package_dir = checkout_root / "crates" / name
    if package_dir != expected_package_dir:
        raise RuntimeError(
            f"Unexpected canonical engine package location for {name}: "
            f"{package_dir}"
        )

    files: list[tuple[str, str]] = []
    for candidate in sorted(checkout_root.iterdir()):
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or not candidate.name.upper().startswith(LICENSE_FILE_PREFIXES)
        ):
            continue
        size = candidate.stat().st_size
        if not 0 <= size <= MAX_NOTICE_FILE_SIZE:
            raise RuntimeError(
                f"Engine license file has an unexpected size: {candidate}"
            )
        try:
            content = (
                candidate.read_text(encoding="utf-8")
                .replace("\r\n", "\n")
                .strip()
            )
        except UnicodeDecodeError as error:
            raise RuntimeError(
                f"Engine license file is not UTF-8 text: {candidate}"
            ) from error
        if content:
            files.append(
                (f"canonical engine workspace/{candidate.name}", content)
            )
    return files


def sqlite_public_domain_notice(rust_packages: list[dict]) -> tuple[str, str] | None:
    package = next(
        (package for package in rust_packages if package["name"] == "libsqlite3-sys"),
        None,
    )
    if package is None:
        return None
    source = Path(package["manifest_path"]).parent / "sqlite3/sqlite3.c"
    if not source.is_file():
        raise RuntimeError("Bundled libsqlite3-sys is missing sqlite3/sqlite3.c.")
    source_text = source.read_text(encoding="utf-8")
    version_match = re.search(r"SQLite\n\*\* version ([0-9]+(?:\.[0-9]+)*)", source_text)
    notice_match = re.search(
        r"\*\* The author disclaims copyright.*?\*\*    May you share freely, never taking more than you give\.",
        source_text,
        flags=re.DOTALL,
    )
    if not version_match or not notice_match:
        raise RuntimeError("Unable to locate the bundled SQLite public-domain notice.")
    lines = []
    for line in notice_match.group(0).splitlines():
        lines.append(re.sub(r"^\s*\*\* ?", "", line).rstrip())
    return (
        f"SQLite {version_match.group(1)} public-domain dedication",
        "\n".join(lines).strip(),
    )


def generate() -> str:
    rust_packages, rust_target_counts = shipping_rust_packages_for_targets()

    notice_groups: dict[str, dict[str, object]] = {}

    def add_notice(applies_to: str, source_name: str, content: str) -> None:
        normalized = content.replace("\r\n", "\n").strip()
        digest = sha256_bytes(normalized.encode("utf-8"))
        group = notice_groups.setdefault(
            digest,
            {"content": normalized, "applies_to": set(), "source_names": set()},
        )
        group["applies_to"].add(applies_to)  # type: ignore[union-attr]
        group["source_names"].add(source_name)  # type: ignore[union-attr]

    package_license_files: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for package in rust_packages:
        key = (package["name"], package["version"])
        package_license_files[key] = rust_package_license_files(package)
    for key, fallback in RUST_LICENSE_FILE_FALLBACKS.items():
        if key in package_license_files and not package_license_files[key]:
            fallback_files = package_license_files.get(fallback)
            if not fallback_files:
                raise RuntimeError(
                    f"Missing reviewed companion license files for {key[0]} {key[1]}."
                )
            package_license_files[key] = [
                (f"companion {fallback[0]} {fallback[1]}/{name}", content)
                for name, content in fallback_files
            ]

    for package in rust_packages:
        key = (package["name"], package["version"])
        label = f"Rust crate {package['name']} {package['version']}"
        files = package_license_files[key]
        if not files:
            raise RuntimeError(
                f"No license/notice text is available for {package['name']} {package['version']}."
            )
        for name, content in files:
            add_notice(label, name, content)

    sqlite_notice = sqlite_public_domain_notice(rust_packages)
    if sqlite_notice:
        source_name, content = sqlite_notice
        add_notice("Bundled SQLite used by libsqlite3-sys", source_name, content)

    lines = [
        "HNS DANE BROWSER CHROMIUM THIRD-PARTY SOFTWARE NOTICES",
        "",
        "This Chromium extension and native host include open-source components. The inventory",
        "below is generated from the locked non-development Cargo dependency closures reachable",
        "from hns-chromium-native-host on every supported desktop target. Cargo build-time",
        "dependencies are retained conservatively. Workspace-owned HNS DANE Browser crates and",
        "test-only, lint, mobile, fuzz, and snapshot-exporter dependencies are excluded.",
        "The extension JavaScript has no third-party runtime package dependency.",
        "",
        "Supported desktop Rust target closure counts:",
        *(
            f"  {target}: {rust_target_counts[target]} external Cargo components"
            for target, _ in RUST_SHIPPING_TARGETS
        ),
        "",
        "License expressions are the declarations in the verified package metadata. The reproduced",
        "texts come from checksum-verified registry packages or immutable Cargo Git checkouts.",
        "Inclusion here does not imply endorsement by the component authors.",
        "",
        f"Generator schema: {SCHEMA}",
        "Generated input SHA-256:",
    ]
    for relative, digest in input_fingerprints().items():
        lines.append(f"  {relative} = {digest}")

    lines.extend(["", f"RUST COMPONENTS ({len(rust_packages)})"])
    for package in rust_packages:
        lines.append(f"  {package['name']} {package['version']} | {package['license']}")

    lines.extend(["", "LICENSE AND NOTICE TEXTS"])
    for digest in sorted(notice_groups):
        group = notice_groups[digest]
        applies_to = sorted(  # type: ignore[arg-type]
            group["applies_to"],
            key=lambda value: (value.casefold(), value),
        )
        source_names = sorted(  # type: ignore[arg-type]
            group["source_names"],
            key=lambda value: (value.casefold(), value),
        )
        lines.extend([
            "",
            "=" * 80,
            f"Notice SHA-256: {digest}",
            "Applies to:",
        ])
        lines.extend(f"  - {value}" for value in applies_to)
        lines.append("Source file names:")
        lines.extend(f"  - {value}" for value in source_names)
        lines.extend(["-" * 80, str(group["content"])])

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the full asset digest, fingerprints, and inventory without dependency caches",
    )
    arguments = parser.parse_args()
    if arguments.check:
        return check_committed_asset()

    try:
        generated = generate()
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generated, encoding="utf-8", newline="\n")
    OUTPUT_SHA256.write_text(
        f"{sha256_bytes(generated.encode('utf-8'))}  {OUTPUT.relative_to(ROOT).as_posix()}\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"Wrote {OUTPUT.relative_to(ROOT)} and {OUTPUT_SHA256.relative_to(ROOT)} "
        f"({len(generated.encode('utf-8'))} bytes)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
