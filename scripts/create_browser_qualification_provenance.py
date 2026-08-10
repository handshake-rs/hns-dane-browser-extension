#!/usr/bin/env python3
"""Validate and describe exact-SHA installed-browser qualification inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile


REPOSITORY = "https://github.com/handshake-rs/hns-dane-browser-extension"
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
REQUIRED_ROLES = (
    "nativeHostExecutable",
    "nativeHostArchive",
    "nativeHostArchiveChecksum",
    "canonicalExtension",
    "canonicalExtensionChecksum",
)
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
FORBIDDEN_EXACT_NAMES = {
    ".env",
    ".envrc",
    "credentials.json",
    "google-services.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "keystore.properties",
    "local.properties",
    "release.properties",
    "signing.properties",
}
FORBIDDEN_SUFFIXES = (
    ".asc",
    ".jks",
    ".kdbx",
    ".key",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".p8",
    ".pem",
    ".pfx",
    ".pkcs12",
)


class ProvenanceError(ValueError):
    """A qualification input cannot be safely attributed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_archive_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ProvenanceError(f"unsafe archive path: {name!r}")
    return path


def reject_secret_material(name: str, data: bytes) -> None:
    path = checked_archive_name(name)
    for part in path.parts:
        lowered = part.casefold()
        if (
            lowered in FORBIDDEN_EXACT_NAMES
            or lowered.startswith(".env.")
            or lowered.startswith("service-account") and lowered.endswith(".json")
            or lowered.startswith("firebase-adminsdk") and lowered.endswith(".json")
            or lowered.endswith(FORBIDDEN_SUFFIXES)
        ):
            raise ProvenanceError(f"secret-bearing filename is forbidden: {name}")
    for marker in PRIVATE_KEY_MARKERS:
        if marker in data:
            raise ProvenanceError(f"private-key material is forbidden: {name}")


def zip_payloads(path: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = checked_archive_name(info.filename).as_posix()
            if info.flag_bits & 0x1:
                raise ProvenanceError(f"encrypted ZIP entry is forbidden: {name}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ProvenanceError(f"archive link is forbidden: {name}")
            if info.is_dir():
                continue
            data = archive.read(info)
            reject_secret_material(name, data)
            if name in payloads:
                raise ProvenanceError(f"duplicate archive entry: {name}")
            payloads[name] = data
    return payloads


def tar_payloads(path: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            name = checked_archive_name(member.name).as_posix()
            if member.isdir():
                continue
            if not member.isfile():
                raise ProvenanceError(f"archive link or special entry is forbidden: {name}")
            handle = archive.extractfile(member)
            if handle is None:
                raise ProvenanceError(f"unable to read archive entry: {name}")
            data = handle.read()
            reject_secret_material(name, data)
            if name in payloads:
                raise ProvenanceError(f"duplicate archive entry: {name}")
            payloads[name] = data
    return payloads


def load_json_entry(payloads: dict[str, bytes], suffix: str) -> dict[str, object]:
    matches = [data for name, data in payloads.items() if name.endswith(suffix)]
    if len(matches) != 1:
        raise ProvenanceError(f"archive must contain exactly one {suffix}")
    try:
        value = json.loads(matches[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvenanceError(f"archive {suffix} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ProvenanceError(f"archive {suffix} must be a JSON object")
    return value


def verify_sidecar(sidecar: Path, artifact: Path) -> None:
    try:
        fields = sidecar.read_text(encoding="ascii").strip().split()
    except UnicodeDecodeError as error:
        raise ProvenanceError(f"checksum sidecar is not ASCII: {sidecar}") from error
    if fields != [sha256_file(artifact), artifact.name]:
        raise ProvenanceError(f"checksum sidecar does not match {artifact.name}")


def validate_inputs(
    files: dict[str, Path], source_commit: str, rust_target: str
) -> None:
    if set(files) != set(REQUIRED_ROLES):
        raise ProvenanceError(
            "qualification roles must be exactly: " + ", ".join(REQUIRED_ROLES)
        )
    for role, path in files.items():
        if not path.is_file() or path.is_symlink():
            raise ProvenanceError(f"{role} must be a regular non-symlink file: {path}")
        reject_secret_material(path.name, path.read_bytes())

    verify_sidecar(files["nativeHostArchiveChecksum"], files["nativeHostArchive"])
    verify_sidecar(
        files["canonicalExtensionChecksum"], files["canonicalExtension"]
    )

    native_payloads = tar_payloads(files["nativeHostArchive"])
    native_matches = [
        data
        for name, data in native_payloads.items()
        if name.endswith("/rust/target/release/hns-chromium-native-host")
    ]
    if len(native_matches) != 1:
        raise ProvenanceError("native archive must contain exactly one native host")
    raw_host = files["nativeHostExecutable"].read_bytes()
    if native_matches[0] != raw_host:
        raise ProvenanceError("native archive does not contain the exact staged native host")
    native_metadata = load_json_entry(native_payloads, "/RELEASE-METADATA.json")
    if native_metadata.get("source", {}).get("commit") != source_commit:
        raise ProvenanceError("native archive source commit does not match")
    if native_metadata.get("nativeHost", {}).get("rustTarget") != rust_target:
        raise ProvenanceError("native archive Rust target does not match")

    extension_payloads = zip_payloads(files["canonicalExtension"])
    extension_metadata = load_json_entry(extension_payloads, "RELEASE-METADATA.json")
    if extension_metadata.get("source", {}).get("commit") != source_commit:
        raise ProvenanceError("extension archive source commit does not match")
    if extension_metadata.get("extensionPackageVariant") != "canonicalUnpacked":
        raise ProvenanceError("extension archive is not the canonical unpacked package")
    try:
        manifest = json.loads(extension_payloads["manifest.json"])
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvenanceError("canonical extension manifest is missing or invalid") from error
    if not isinstance(manifest.get("key"), str) or not manifest["key"]:
        raise ProvenanceError("canonical extension manifest lacks its public identity key")


def build_provenance(arguments: argparse.Namespace) -> dict[str, object]:
    if not COMMIT_PATTERN.fullmatch(arguments.source_commit):
        raise ProvenanceError("source commit must be a lowercase 40-character Git SHA")
    files: dict[str, Path] = {}
    for assignment in arguments.file:
        role, separator, value = assignment.partition("=")
        if not separator or not role or not value or role in files:
            raise ProvenanceError(f"invalid or duplicate --file assignment: {assignment}")
        files[role] = Path(value).resolve()
    validate_inputs(files, arguments.source_commit, arguments.rust_target)

    return {
        "schemaVersion": 1,
        "artifactPurpose": "installedBrowserQualificationInput",
        "source": {
            "repository": REPOSITORY,
            "commit": arguments.source_commit,
            "commitUrl": f"{REPOSITORY}/commit/{arguments.source_commit}",
        },
        "platform": {
            "operatingSystem": arguments.platform,
            "architecture": arguments.architecture,
            "rustTarget": arguments.rust_target,
            "runnerImage": arguments.runner_image,
        },
        "files": [
            {
                "role": role,
                "path": files[role].name,
                "size": files[role].stat().st_size,
                "sha256": sha256_file(files[role]),
            }
            for role in REQUIRED_ROLES
        ],
        "securityBoundary": {
            "containsSecrets": False,
            "containsPrivateKeys": False,
            "hnsaAdmissionEnabled": False,
            "hnsrRequesterEnabled": False,
            "hnsrProviderEnabled": False,
            "walletProviderEnabled": False,
            "valueMovementEnabled": False,
            "p2pMarketplaceEnabled": False,
        },
        "qualification": {
            "status": "pendingInstalledBrowserRun",
            "requiresIsolatedProfile": True,
            "doesNotQualifyReleaseByItself": True,
        },
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--rust-target", required=True)
    parser.add_argument("--runner-image", required=True)
    parser.add_argument("--file", action="append", default=[], required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        provenance = build_provenance(arguments)
        output = arguments.output.resolve()
        if output.exists() and output.is_symlink():
            raise ProvenanceError("provenance output may not be a symlink")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, ProvenanceError) as error:
        print(f"Browser qualification provenance failed: {error}")
        return 1
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
