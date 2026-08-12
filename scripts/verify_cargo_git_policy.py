#!/usr/bin/env python3
"""Require registry inputs or the exact reviewed HNS source revisions."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ENGINE_VERSIONS = {
    "hns-browser-observability": "0.2.1",
    "hns-browser-runtime": "0.2.1",
    "hns-icann-dane": "0.2.1",
    "hns-namespace-resolution": "0.2.1",
    "hns-resolution-policy": "0.2.1",
}
ENGINE_REQUIREMENTS = {
    package: f"={version}" for package, version in ENGINE_VERSIONS.items()
}
ENGINE_GIT_URL = "https://github.com/handshake-rs/hns-dane-engine.git"
ENGINE_REVISION = "65c397e8347f37085ea67d2c9c745ce896328e64"
HNS_RS_GIT_URL = "https://github.com/handshake-rs/hns-rs.git"
HNS_RS_REVISION = "b24b66c382de53330ec21dd3137e056a2bea3e2d"
APPROVED_ENGINE_GIT = {
    package: ("0.2.1", ENGINE_REVISION)
    for package in {
        "hns-dane",
        "hns-browser-dane",
        "hns-dnssec",
        "hns-browser-dnssec",
        "hns-p2p",
        "hns-browser-p2p",
        "hns-resolver",
        "hns-browser-resolver",
        "hns-sync",
        "hns-browser-sync",
        "hns-chain",
        "hns-browser-chain",
        "hns-urkel",
        "hns-browser-urkel",
        "hns-core",
        "hns-browser-primitives",
        "hns-cache",
        "hns-dns-wire",
        "hns-gateway",
        "hns-browser-gateway",
        "hns-transport",
        "hns-browser-transport",
        "hns-loopback-proxy",
        "hns-browser-loopback-proxy",
        "hns-browser-observability",
        "hns-browser-runtime",
        "hns-icann-dane",
        "hns-namespace-resolution",
        "hns-resolution-policy",
        "hns-light-chain",
    }
}
APPROVED_HNS_RS_GIT = {
    package: ("0.2.0", HNS_RS_REVISION)
    for package in {
        "hns-covenants",
        "hns-encoding",
        "hns-header-consensus",
        "hns-primitives",
        "hns-service-authority",
        "hns-urkel-proof",
    }
}
APPROVED_CARGO_GIT = {
    package: (version, ENGINE_GIT_URL, revision)
    for package, (version, revision) in APPROVED_ENGINE_GIT.items()
} | {
    package: (version, HNS_RS_GIT_URL, revision)
    for package, (version, revision) in APPROVED_HNS_RS_GIT.items()
}
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
ENGINE_PACKAGES = frozenset(ENGINE_VERSIONS)
ROOT_MANIFEST = Path("rust/Cargo.toml")
MIGRATED_LOCAL_CRATES = frozenset(
    {
        "hns-cache",
        "hns-chain",
        "hns-core",
        "hns-dane",
        "hns-dnssec",
        "hns-gateway",
        "hns-loopback-proxy",
        "hns-p2p",
        "hns-resolver",
        "hns-sync",
        "hns-transport",
        "hns-urkel",
    }
)
LOCKFILES = (
    Path("rust/Cargo.lock"),
    Path("rust/fuzz/Cargo.lock"),
    Path("tools/hns-header-snapshot-exporter/Cargo.lock"),
)


class CargoSourcePolicyError(RuntimeError):
    """A Cargo manifest or lockfile violates the reviewed source policy."""


def tracked_cargo_manifests(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return sorted(
        path
        for raw in result.stdout.split(b"\0")
        if raw
        and (path := Path(raw.decode())).name == "Cargo.toml"
        and (root / path).is_file()
    )


def git_specs(
    value: Any, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        if "git" in value:
            yield path, value
        for key, child in value.items():
            yield from git_specs(child, (*path, str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from git_specs(child, (*path, str(index)))


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def validate_manifests(root: Path, manifests: list[Path]) -> None:
    for relative_path in manifests:
        document = load_toml(root / relative_path)
        for location, specification in git_specs(document):
            rendered_location = ".".join(location) or "<document root>"
            package = location[-1] if location else ""
            approved = APPROVED_CARGO_GIT.get(package)
            if (
                approved is None
                or specification.get("git") != approved[1]
                or specification.get("rev") != approved[2]
                or specification.get("version") != f"={approved[0]}"
                or "branch" in specification
                or "tag" in specification
            ):
                raise CargoSourcePolicyError(
                    f"{relative_path}:{rendered_location}: Cargo Git dependency "
                    "is not an exact reviewed HNS source revision"
                )

    root_document = load_toml(root / ROOT_MANIFEST)
    dependencies = root_document.get("workspace", {}).get("dependencies", {})
    if not isinstance(dependencies, Mapping):
        raise CargoSourcePolicyError(
            f"{ROOT_MANIFEST}: [workspace.dependencies] is missing"
        )
    for package in sorted(ENGINE_PACKAGES):
        specification = dependencies.get(package)
        requirement = (
            specification.get("version")
            if isinstance(specification, Mapping)
            else None
        )
        expected_requirement = ENGINE_REQUIREMENTS[package]
        if requirement != expected_requirement:
            raise CargoSourcePolicyError(
                f"{ROOT_MANIFEST}: {package} must be pinned to "
                f"{expected_requirement!r}, found {requirement!r}"
            )
        if (
            specification.get("git") != ENGINE_GIT_URL
            or specification.get("rev") != ENGINE_REVISION
            or {"path", "registry", "branch", "tag", "package"}.intersection(
                specification
            )
        ):
            raise CargoSourcePolicyError(
                f"{ROOT_MANIFEST}: {package} must use the exact reviewed "
                f"hns-dane-engine revision {ENGINE_REVISION}"
            )


def validate_lockfiles(root: Path) -> None:
    root_packages: dict[str, int] = {package: 0 for package in ENGINE_PACKAGES}

    for relative_path in LOCKFILES:
        document = load_toml(root / relative_path)
        for package in document.get("package", []):
            source = package.get("source")
            name = package.get("name", "<unknown>")
            if isinstance(source, str) and source.startswith("git+"):
                approved = APPROVED_CARGO_GIT.get(name)
                expected_prefix = (
                    f"git+{approved[1]}?rev={approved[2]}#"
                    if approved is not None
                    else ""
                )
                revision = source.rsplit("#", 1)[-1]
                if (
                    approved is None
                    or package.get("version") != approved[0]
                    or not source.startswith(expected_prefix)
                    or revision != approved[2]
                ):
                    raise CargoSourcePolicyError(
                        f"{relative_path}: locked Cargo Git package {name!r} is not allowed"
                    )
                if relative_path == Path("rust/Cargo.lock") and name in root_packages:
                    root_packages[name] += 1
                continue
            if name in APPROVED_CARGO_GIT:
                raise CargoSourcePolicyError(
                    f"{relative_path}: {name} must come from its exact reviewed "
                    f"HNS source revision, found {source!r}"
                )

    for package, count in sorted(root_packages.items()):
        if count != 1:
            raise CargoSourcePolicyError(
                "rust/Cargo.lock: expected exactly one reviewed Git package for "
                f"{package} {ENGINE_VERSIONS[package]}, found {count}"
            )


def verify_repository(
    root: Path = ROOT, manifests: list[Path] | None = None
) -> None:
    for package in sorted(MIGRATED_LOCAL_CRATES):
        path = root / "rust/crates" / package
        if path.exists():
            raise CargoSourcePolicyError(
                f"{path.relative_to(root)}: migrated engine crate must not be restored locally"
            )
    validate_manifests(
        root,
        tracked_cargo_manifests(root) if manifests is None else manifests,
    )
    validate_lockfiles(root)


def main() -> int:
    try:
        verify_repository()
    except (
        CargoSourcePolicyError,
        OSError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"Cargo source policy failed: {error}", file=sys.stderr)
        return 1
    print(
        "Cargo source policy permits registry inputs plus the exact reviewed "
        "hns-dane-engine and hns-rs revisions and pins the canonical packages."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
