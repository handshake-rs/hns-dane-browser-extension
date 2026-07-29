#!/usr/bin/env python3
"""Generate the Chromium extension/native-host third-party notices.

Generation is deliberately offline. Rust package metadata and license files
come from Cargo's checksum-verified registry cache. The
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

from verify_cargo_git_policy import CRATES_IO_SOURCE


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "extension/THIRD_PARTY_NOTICES.txt"
OUTPUT_SHA256 = ROOT / "scripts/third-party-notices.sha256"
SCHEMA = "5"
LOCKED_INPUT_PATHS = (
    "scripts/generate-third-party-notices.py",
    "scripts/verify_cargo_git_policy.py",
    "release/license-texts/BSL-1.0.txt",
    "release/license-texts/CC0-1.0.txt",
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
    ("x86_64-unknown-linux-musl", "hns-chromium-native-host"),
    ("aarch64-unknown-linux-musl", "hns-chromium-native-host"),
    ("x86_64-pc-windows-msvc", "hns-chromium-native-host"),
    ("aarch64-pc-windows-msvc", "hns-chromium-native-host"),
    ("x86_64-apple-darwin", "hns-chromium-native-host"),
    ("aarch64-apple-darwin", "hns-chromium-native-host"),
    ("x86_64-unknown-linux-gnu", "hns-browser-setup"),
    ("aarch64-unknown-linux-gnu", "hns-browser-setup"),
    ("x86_64-pc-windows-msvc", "hns-browser-setup"),
    ("aarch64-pc-windows-msvc", "hns-browser-setup"),
    ("x86_64-apple-darwin", "hns-browser-setup"),
    ("aarch64-apple-darwin", "hns-browser-setup"),
)

# These registry packages are published without their workspace-level license
# files. The companion packages are from the same upstream project and release
# family and contain the project license texts named by the package manifest.
RUST_LICENSE_FILE_FALLBACKS = {
    ("asn1-rs-impl", "0.2.0"): ("asn1-rs", "0.7.2"),
}

# Some checksum-verified registry packages declare a standard license but omit
# the corresponding workspace-level text from the published crate. Keep this
# mapping explicit so a new or changed expression fails closed during release.
DECLARED_LICENSE_FALLBACK_IDS = {
    "MIT": ("MIT",),
    "Apache-2.0": ("Apache-2.0",),
    "MIT OR Apache-2.0": ("MIT", "Apache-2.0"),
    "MIT/Apache-2.0": ("MIT", "Apache-2.0"),
    "(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0": (
        "MIT",
        "Apache-2.0",
    ),
    "BSL-1.0": ("BSL-1.0",),
    "CC0-1.0": ("CC0-1.0",),
    "Zlib OR Apache-2.0 OR MIT": ("Zlib", "Apache-2.0", "MIT"),
}

CANONICAL_CRATE_LICENSE_SOURCES = {
    "MIT": (("quinn", "0.11.11"), "LICENSE-MIT"),
    "Apache-2.0": (("quinn", "0.11.11"), "LICENSE-APACHE"),
    "Zlib": (("glow", "0.17.0"), "LICENSE-ZLIB"),
}

REVIEWED_LICENSE_TEXT_SOURCES = {
    "BSL-1.0": "release/license-texts/BSL-1.0.txt",
    "CC0-1.0": "release/license-texts/CC0-1.0.txt",
}

SUPPLEMENTAL_PACKAGE_LICENSE_FILES = {
    ("epaint_default_fonts", "0.35.0"): (
        "fonts/Hack-Regular.txt",
        "fonts/OFL.txt",
        "fonts/UFL.txt",
        "fonts/emoji-icon-font-mit-license.txt",
    ),
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
        failures.append("the Chromium native-host/setup Rust inventory is missing")

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
        target_counts[f"{root_package} @ {target}"] = len(target_packages)
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


def package_relative_text_files(
    package: dict, relative_paths: tuple[str, ...]
) -> list[tuple[str, str]]:
    package_dir = Path(package["manifest_path"]).resolve().parent
    result: list[tuple[str, str]] = []
    for relative in relative_paths:
        candidate = package_dir / relative
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError(
                f"Missing reviewed license file for {package['name']} "
                f"{package['version']}: {relative}"
            )
        resolved = candidate.resolve()
        try:
            resolved.relative_to(package_dir)
        except ValueError as error:
            raise RuntimeError(
                f"Reviewed license file for {package['name']} escapes its "
                f"verified registry package: {relative}"
            ) from error
        size = resolved.stat().st_size
        if not 0 <= size <= MAX_NOTICE_FILE_SIZE:
            raise RuntimeError(f"License file has an unexpected size: {resolved}")
        try:
            content = (
                resolved.read_text(encoding="utf-8")
                .replace("\r\n", "\n")
                .strip()
            )
        except UnicodeDecodeError as error:
            raise RuntimeError(
                f"License file is not UTF-8 text: {resolved}"
            ) from error
        if not content:
            raise RuntimeError(f"License file is unexpectedly empty: {resolved}")
        result.append((relative, content))
    return result


def reviewed_repository_license_text(
    license_id: str, relative: str
) -> tuple[str, str]:
    candidate = ROOT / relative
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError(
            f"Missing reviewed repository text for {license_id}: {relative}"
        )
    size = candidate.stat().st_size
    if not 0 <= size <= MAX_NOTICE_FILE_SIZE:
        raise RuntimeError(f"License file has an unexpected size: {candidate}")
    try:
        content = (
            candidate.read_text(encoding="utf-8")
            .replace("\r\n", "\n")
            .strip()
        )
    except UnicodeDecodeError as error:
        raise RuntimeError(
            f"License file is not UTF-8 text: {candidate}"
        ) from error
    if not content:
        raise RuntimeError(f"License file is unexpectedly empty: {candidate}")
    return (f"reviewed canonical {license_id} text/{relative}", content)


def declared_license_fallback_files(
    package: dict, rust_packages_by_key: dict[tuple[str, str], dict]
) -> list[tuple[str, str]]:
    expression = package["license"]
    license_ids = DECLARED_LICENSE_FALLBACK_IDS.get(expression)
    if license_ids is None:
        raise RuntimeError(
            f"No reviewed canonical text mapping exists for the license "
            f"expression on {package['name']} {package['version']}: {expression}"
        )

    files: list[tuple[str, str]] = []
    for license_id in license_ids:
        crate_source = CANONICAL_CRATE_LICENSE_SOURCES.get(license_id)
        if crate_source is not None:
            source_key, relative = crate_source
            source_package = rust_packages_by_key.get(source_key)
            if source_package is None:
                raise RuntimeError(
                    f"The reviewed canonical {license_id} source package "
                    f"{source_key[0]} {source_key[1]} is not in the shipping closure."
                )
            [(name, content)] = package_relative_text_files(
                source_package, (relative,)
            )
            files.append(
                (
                    f"canonical {license_id} text from checksum-verified "
                    f"{source_key[0]} {source_key[1]}/{name}",
                    content,
                )
            )
            continue

        repository_source = REVIEWED_LICENSE_TEXT_SOURCES.get(license_id)
        if repository_source is None:
            raise RuntimeError(
                f"No reviewed canonical text source exists for {license_id}."
            )
        files.append(
            reviewed_repository_license_text(license_id, repository_source)
        )
    return files


def rust_package_license_files(package: dict) -> list[tuple[str, str]]:
    source = package.get("source")
    if source != CRATES_IO_SOURCE:
        raise RuntimeError(
            f"Unreviewed non-crates.io source for {package['name']} "
            f"{package['version']}: "
            f"{source}"
        )
    return registry_license_files(package)


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
    rust_packages_by_key = {
        (package["name"], package["version"]): package
        for package in rust_packages
    }

    notice_groups: dict[str, dict[str, object]] = {}

    def add_notice(applies_to: str, source_name: str, content: str) -> None:
        normalized = "\n".join(
            line.rstrip() for line in content.replace("\r\n", "\n").splitlines()
        ).strip()
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
        if not package_license_files[key]:
            package_license_files[key] = declared_license_fallback_files(
                package, rust_packages_by_key
            )
        supplemental = SUPPLEMENTAL_PACKAGE_LICENSE_FILES.get(key)
        if supplemental is not None:
            package_license_files[key].extend(
                package_relative_text_files(package, supplemental)
            )

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
        "This Chromium extension, native host, and setup application include open-source",
        "components. The inventory",
        "below is generated from the locked non-development Cargo dependency closures reachable",
        "from hns-chromium-native-host and hns-browser-setup on representative supported desktop",
        "targets. Cargo build-time dependencies are retained conservatively. Workspace-owned HNS",
        "DANE Browser crates and test-only, lint, fuzz, and snapshot-exporter dependencies are",
        "excluded.",
        "The extension JavaScript has no third-party runtime package dependency.",
        "",
        "Supported desktop Rust target closure counts:",
        *(
            f"  {closure}: {rust_target_counts[closure]} external Cargo components"
            for closure in sorted(rust_target_counts)
        ),
        "",
        "License expressions are the declarations in the verified package metadata. The reproduced",
        "texts come from checksum-verified registry packages or fingerprinted canonical license",
        "texts reviewed in this repository.",
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
