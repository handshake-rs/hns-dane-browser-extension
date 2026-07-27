#!/usr/bin/env python3
"""Build deterministic Chromium extension and native-host release archives."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import zipfile


REPOSITORY_URL = "https://github.com/handshake-rs/hns-dane-browser-extension"
LICENSE_NAME = "PolyForm Noncommercial License 1.0.0"
GITHUB_SPONSORS_URL = "https://github.com/sponsors/denuoweb"
DONATION_URL = (
    "handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh"
    "?label=Denuo%20Web%20Handshake%20Browser"
    "&message=Handshake%20Browser%20donation"
)
EXTENSION_ID_PATTERN = re.compile(r"[a-p]{32}")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
PLATFORMS = {"linux", "macos", "windows"}
ARCHITECTURES = {"x64", "arm64"}
RUST_TARGETS = {
    ("linux", "x64"): "x86_64-unknown-linux-musl",
    ("linux", "arm64"): "aarch64-unknown-linux-musl",
    ("windows", "x64"): "x86_64-pc-windows-msvc",
    ("windows", "arm64"): "aarch64-pc-windows-msvc",
    ("macos", "x64"): "x86_64-apple-darwin",
    ("macos", "arm64"): "aarch64-apple-darwin",
}
ZIP_EPOCH = 315532800  # 1980-01-01, the earliest ZIP timestamp.


class PackagingError(ValueError):
    """A release input or source tree is invalid."""


def load_canonical_identity(repository_root: Path) -> tuple[str, dict[str, object]]:
    identity_path = repository_root / "release/extension-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    if (
        identity.get("schemaVersion") != 1
        or identity.get("algorithm") != "chromium-rsa-public-key-sha256"
    ):
        raise PackagingError("the canonical extension identity schema is invalid")
    canonical_id = identity.get("canonicalId")
    encoded_key = identity.get("publicKeyDerBase64")
    if (
        not isinstance(canonical_id, str)
        or not EXTENSION_ID_PATTERN.fullmatch(canonical_id)
        or not isinstance(encoded_key, str)
    ):
        raise PackagingError("the canonical extension identity is incomplete")
    try:
        public_key_der = base64.b64decode(encoded_key, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PackagingError(
            "the canonical extension public key is not valid base64"
        ) from error
    digest_prefix = hashlib.sha256(public_key_der).digest()[:16]
    derived_id = "".join(
        chr(ord("a") + nibble)
        for byte in digest_prefix
        for nibble in (byte >> 4, byte & 0x0F)
    )
    if canonical_id != derived_id:
        raise PackagingError(
            "the canonical extension ID does not match its public key"
        )
    return canonical_id, identity


def normalized_text(path: Path) -> bytes:
    text = path.read_text(encoding="utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def load_release_context(
    repository_root: Path,
    source_commit: str,
    source_tag: str,
    extension_id: str,
) -> dict[str, object]:
    if not COMMIT_PATTERN.fullmatch(source_commit):
        raise PackagingError("source commit must be a lowercase 40-character Git SHA")
    if not EXTENSION_ID_PATTERN.fullmatch(extension_id):
        raise PackagingError(
            "extension ID must contain exactly 32 lowercase characters from a through p"
        )

    package = json.loads(
        (repository_root / "package.json").read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (repository_root / "extension/manifest.json").read_text(encoding="utf-8")
    )
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+(?:\.\d+){1,3}", version):
        raise PackagingError("the Chromium manifest has an invalid release version")
    if package.get("version") != version:
        raise PackagingError("package.json and the Chromium manifest versions disagree")
    if source_tag != f"v{version}":
        raise PackagingError(
            f"source tag {source_tag!r} does not match manifest version {version!r}"
        )

    repository = package.get("repository")
    repository_value = (
        repository.get("url") if isinstance(repository, dict) else repository
    )
    if (
        not isinstance(repository_value, str)
        or repository_value.removesuffix(".git") != REPOSITORY_URL
        or manifest.get("homepage_url") != REPOSITORY_URL
    ):
        raise PackagingError("package and manifest source links are not canonical")
    if manifest.get("manifest_version") != 3:
        raise PackagingError("the store package must use Manifest V3")
    canonical_extension_id, identity = load_canonical_identity(repository_root)
    native_registration_ids = list(
        dict.fromkeys([canonical_extension_id, extension_id])
    )

    return {
        "canonical_extension_id": canonical_extension_id,
        "version": version,
        "manifest": manifest,
        "native_registration_ids": native_registration_ids,
        "metadata": {
            "schemaVersion": 1,
            "name": "HNS DANE Browser",
            "version": version,
            "extension": {
                "canonicalIdentityAlgorithm": identity["algorithm"],
                "canonicalReleaseId": canonical_extension_id,
                "canonicalPublicKeyDerBase64": identity["publicKeyDerBase64"],
                "catalogIdsMayDiffer": True,
                "manifestVersion": 3,
                "nativeRegistrationIds": native_registration_ids,
                "supportedBrowsers": [
                    "Brave",
                    "Chromium",
                    "Google Chrome",
                    "Microsoft Edge",
                    "Opera",
                    "Vivaldi",
                ],
            },
            "source": {
                "repository": REPOSITORY_URL,
                "commit": source_commit,
                "commitUrl": f"{REPOSITORY_URL}/commit/{source_commit}",
                "tag": source_tag,
                "tagUrl": f"{REPOSITORY_URL}/releases/tag/{source_tag}",
            },
            "license": {
                "name": LICENSE_NAME,
                "path": "LICENSE",
                "url": f"{REPOSITORY_URL}/blob/{source_tag}/LICENSE",
            },
            "donationUrls": [GITHUB_SPONSORS_URL, DONATION_URL],
        },
    }


def checked_source_files(directory: Path) -> dict[str, tuple[bytes, int]]:
    if not directory.is_dir():
        raise PackagingError(f"required directory is missing: {directory}")
    files: dict[str, tuple[bytes, int]] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise PackagingError(f"release input may not contain symlinks: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PackagingError(f"release input is not a regular file: {path}")
        relative = path.relative_to(directory).as_posix()
        checked_archive_path(relative)
        files[relative] = (path.read_bytes(), 0o644)
    return files


def checked_archive_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or "\\" in name
    ):
        raise PackagingError(f"unsafe archive path: {name!r}")
    return path


def write_deterministic_zip(
    destination: Path,
    files: dict[str, tuple[bytes, int]],
    source_date_epoch: int,
) -> None:
    timestamp = time.gmtime(max(source_date_epoch, ZIP_EPOCH))[:6]
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as archive:
            for name in sorted(files):
                checked_archive_path(name)
                data, mode = files[name]
                info = zipfile.ZipInfo(name, timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = ((stat.S_IFREG | mode) & 0xFFFF) << 16
                info.flag_bits |= 0x800
                archive.writestr(
                    info,
                    data,
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def write_deterministic_tar_gz(
    destination: Path,
    root_name: str,
    files: dict[str, tuple[bytes, int]],
    source_date_epoch: int,
) -> None:
    checked_archive_path(root_name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.unlink(missing_ok=True)
    directories = {root_name}
    for relative in files:
        path = checked_archive_path(f"{root_name}/{relative}")
        for length in range(1, len(path.parts)):
            directories.add(PurePosixPath(*path.parts[:length]).as_posix())

    try:
        with temporary.open("wb") as output:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=output,
                mtime=source_date_epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.USTAR_FORMAT,
                ) as archive:
                    for directory in sorted(
                        directories, key=lambda value: (value.count("/"), value)
                    ):
                        info = tarfile.TarInfo(f"{directory}/")
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        normalize_tar_info(info, source_date_epoch)
                        archive.addfile(info)
                    for relative in sorted(files):
                        data, mode = files[relative]
                        info = tarfile.TarInfo(f"{root_name}/{relative}")
                        info.size = len(data)
                        info.mode = mode
                        normalize_tar_info(info, source_date_epoch)
                        archive.addfile(info, io.BytesIO(data))
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_tar_info(info: tarfile.TarInfo, source_date_epoch: int) -> None:
    info.mtime = source_date_epoch
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksum(destination: Path) -> Path:
    checksum_path = destination.with_name(f"{destination.name}.sha256")
    checksum_path.write_text(
        f"{sha256_file(destination)}  {destination.name}\n",
        encoding="ascii",
        newline="\n",
    )
    return checksum_path


def validate_native_binary(
    native_host: Path,
    platform: str,
    architecture: str,
    rust_target: str,
) -> None:
    expected_target = RUST_TARGETS.get((platform, architecture))
    if rust_target != expected_target:
        raise PackagingError(
            f"{platform}-{architecture} must use Rust target {expected_target}"
        )
    data = native_host.read_bytes()
    if platform == "linux":
        if (
            len(data) < 20
            or data[:4] != b"\x7fELF"
            or data[4] != 2
            or data[5] != 1
        ):
            raise PackagingError("Linux native host is not a 64-bit little-endian ELF")
        machine = int.from_bytes(data[18:20], "little")
        expected_machine = 62 if architecture == "x64" else 183
    elif platform == "windows":
        if len(data) < 64 or data[:2] != b"MZ":
            raise PackagingError("Windows native host is not a PE executable")
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if (
            pe_offset > len(data) - 6
            or data[pe_offset : pe_offset + 4] != b"PE\0\0"
        ):
            raise PackagingError("Windows native host has an invalid PE header")
        machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")
        expected_machine = 0x8664 if architecture == "x64" else 0xAA64
    else:
        if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise PackagingError(
                "macOS native host is not a little-endian 64-bit Mach-O"
            )
        machine = int.from_bytes(data[4:8], "little")
        expected_machine = 0x01000007 if architecture == "x64" else 0x0100000C
    if machine != expected_machine:
        raise PackagingError(
            f"native host architecture does not match {platform}-{architecture}"
        )


def package_extension(arguments: argparse.Namespace) -> list[Path]:
    root = arguments.repository_root.resolve()
    context = load_release_context(
        root,
        arguments.source_commit,
        arguments.source_tag,
        arguments.extension_id,
    )
    files = checked_source_files(root / "dist/chromium-extension")
    manifest_bytes = (root / "extension/manifest.json").read_bytes()
    if files.get("manifest.json", (None, None))[0] != manifest_bytes:
        raise PackagingError(
            "dist/chromium-extension is stale; rebuild it before packaging"
        )
    canonical_manifest = dict(context["manifest"])
    canonical_manifest["key"] = context["metadata"]["extension"][
        "canonicalPublicKeyDerBase64"
    ]
    files["LICENSE"] = (normalized_text(root / "LICENSE"), 0o644)
    version = context["version"]
    canonical_destination = (
        arguments.output_dir.resolve()
        / f"hns-dane-browser-extension-v{version}-mv3.zip"
    )
    canonical_files = dict(files)
    canonical_files["manifest.json"] = (canonical_json(canonical_manifest), 0o644)
    canonical_files["RELEASE-METADATA.json"] = (
        canonical_json(
            {
                **context["metadata"],
                "extensionPackageVariant": "canonicalUnpacked",
                "manifestKeyIncluded": True,
            }
        ),
        0o644,
    )
    write_deterministic_zip(
        canonical_destination,
        canonical_files,
        arguments.source_date_epoch,
    )

    store_destination = (
        arguments.output_dir.resolve()
        / f"hns-dane-browser-extension-v{version}-mv3-store.zip"
    )
    store_files = dict(files)
    store_files["RELEASE-METADATA.json"] = (
        canonical_json(
            {
                **context["metadata"],
                "extensionPackageVariant": "storeFirstSubmission",
                "manifestKeyIncluded": False,
            }
        ),
        0o644,
    )
    write_deterministic_zip(
        store_destination,
        store_files,
        arguments.source_date_epoch,
    )
    return [
        canonical_destination,
        write_checksum(canonical_destination),
        store_destination,
        write_checksum(store_destination),
    ]


def native_installation_readme(
    version: str,
    platform: str,
    architecture: str,
    canonical_extension_id: str,
    extension_id: str,
    source_tag: str,
) -> bytes:
    registration_ids = list(
        dict.fromkeys([canonical_extension_id, extension_id])
    )
    if platform == "windows":
        extension_id_argument = ", ".join(
            f'"{candidate}"' for candidate in registration_ids
        )
        install_command = (
            "Set-ExecutionPolicy -Scope Process Bypass -Force; "
            "& .\\extension\\install\\install.ps1 "
            f"-ExtensionId @({extension_id_argument}) -Browser all"
        )
        uninstall_command = (
            "Set-ExecutionPolicy -Scope Process Bypass -Force; "
            "& .\\extension\\install\\uninstall.ps1 -Browser all"
        )
        command_shell = "PowerShell"
        command_language = "powershell"
        prerequisite = (
            "The installer uses the current user's Windows certificate store."
        )
        signing_notice = (
            "This automated Windows bundle is unsigned until project "
            "Authenticode credentials are configured."
        )
    else:
        extension_id_arguments = " ".join(
            f"--extension-id {candidate}" for candidate in registration_ids
        )
        install_command = (
            "bash extension/install/install.sh "
            f"{extension_id_arguments} --browser all"
        )
        uninstall_command = "bash extension/install/uninstall.sh --browser all"
        command_shell = "a terminal"
        command_language = "sh"
        prerequisite = (
            "Linux requires certutil (libnss3-tools or nss-tools). "
            "macOS uses the current user's login keychain."
        )
        signing_notice = (
            "This automated macOS bundle is unsigned and not notarized until "
            "project Apple Developer credentials are configured."
            if platform == "macos"
            else "Verify this Linux bundle against the published SHA256SUMS file."
        )
    registration_list = ", ".join(f"`{value}`" for value in registration_ids)
    text = f"""# HNS DANE Browser native host

Version: {version}
Platform: {platform}-{architecture}
Canonical release/default extension ID: `{canonical_extension_id}`
Native registration ID(s) in this bundle: {registration_list}

This native host works with the browser-neutral Manifest V3 HNS DANE Browser
extension on Google Chrome, Chromium, Microsoft Edge, Brave, Vivaldi, and
Opera. Install the intended extension first and verify its exact ID on the
browser's extension-management page. Store catalogs can assign IDs that differ
from the canonical release/default ID. Register only the exact IDs you verified;
the installers accept additional repeated IDs for catalog-specific builds.
The canonical ID applies to the GitHub/unpacked package. Store users must add
the exact catalog ID shown by the extension setup page if it is not already in
the generated command below.

Close every selected Chromium browser, extract this entire archive without
changing its directory layout, open {command_shell} in the extracted top-level
directory, and run:

```{command_language}
{install_command}
```

The installer registers the native host for the exact extension ID(s), creates
one local P-256 CA for this installation, and installs that CA for the current
user. {prerequisite}

{signing_notice}

To remove the native host, registrations, local CA, and runtime data, close
the browsers and run:

```{command_language}
{uninstall_command}
```

Source: {REPOSITORY_URL}/tree/{source_tag}
License: {LICENSE_NAME} (the included LICENSE file)
Third-party notices: extension/THIRD_PARTY_NOTICES.txt
Donate with GitHub Sponsors: {GITHUB_SPONSORS_URL}
Donate with HNS: {DONATION_URL}
"""
    return text.encode("utf-8")


def package_native(arguments: argparse.Namespace) -> list[Path]:
    root = arguments.repository_root.resolve()
    context = load_release_context(
        root,
        arguments.source_commit,
        arguments.source_tag,
        arguments.extension_id,
    )
    if arguments.platform not in PLATFORMS:
        raise PackagingError(f"unsupported native platform: {arguments.platform}")
    if arguments.architecture not in ARCHITECTURES:
        raise PackagingError(
            f"unsupported native architecture: {arguments.architecture}"
        )
    native_host = arguments.native_host.resolve()
    if not native_host.is_file() or native_host.is_symlink():
        raise PackagingError(f"native host is missing or unsafe: {native_host}")
    expected_binary_name = (
        "hns-chromium-native-host.exe"
        if arguments.platform == "windows"
        else "hns-chromium-native-host"
    )
    if native_host.name != expected_binary_name:
        raise PackagingError(
            f"{arguments.platform} native host must be named {expected_binary_name}"
        )
    validate_native_binary(
        native_host,
        arguments.platform,
        arguments.architecture,
        arguments.rust_target,
    )

    files: dict[str, tuple[bytes, int]] = {
        "LICENSE": (normalized_text(root / "LICENSE"), 0o644),
        "README.md": (
            native_installation_readme(
                str(context["version"]),
                arguments.platform,
                arguments.architecture,
                str(context["canonical_extension_id"]),
                arguments.extension_id,
                arguments.source_tag,
            ),
            0o644,
        ),
        "RELEASE-METADATA.json": (
            canonical_json(
                {
                    **context["metadata"],
                    "nativeHost": {
                        "architecture": arguments.architecture,
                        "binary": f"rust/target/release/{expected_binary_name}",
                        "codeSigningStatus": "unsigned"
                        if arguments.platform in {"macos", "windows"}
                        else "notApplicable",
                        "notarizationStatus": "notNotarized"
                        if arguments.platform == "macos"
                        else "notApplicable",
                        "platform": arguments.platform,
                        "rustTarget": arguments.rust_target,
                    },
                }
            ),
            0o644,
        ),
        "extension/THIRD_PARTY_NOTICES.txt": (
            normalized_text(root / "extension/THIRD_PARTY_NOTICES.txt"),
            0o644,
        ),
        f"rust/target/release/{expected_binary_name}": (
            native_host.read_bytes(),
            0o755,
        ),
    }
    if arguments.platform == "windows":
        installer_paths = [
            "extension/install/install.ps1",
            "extension/install/uninstall.ps1",
        ]
    else:
        installer_paths = [
            "extension/install/install.sh",
            "extension/install/uninstall.sh",
        ]
    for relative in installer_paths:
        mode = 0o755 if relative.endswith(".sh") else 0o644
        files[relative] = (normalized_text(root / relative), mode)

    version = context["version"]
    stem = (
        f"hns-dane-browser-native-host-v{version}-"
        f"{arguments.platform}-{arguments.architecture}"
    )
    if arguments.platform == "windows":
        destination = arguments.output_dir.resolve() / f"{stem}.zip"
        prefixed = {f"{stem}/{name}": value for name, value in files.items()}
        write_deterministic_zip(
            destination,
            prefixed,
            arguments.source_date_epoch,
        )
    else:
        destination = arguments.output_dir.resolve() / f"{stem}.tar.gz"
        write_deterministic_tar_gz(
            destination,
            stem,
            files,
            arguments.source_date_epoch,
        )
    return [destination, write_checksum(destination)]


def positive_epoch(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a Unix timestamp") from error
    if parsed < ZIP_EPOCH or parsed > 0xFFFFFFFF:
        raise argparse.ArgumentTypeError(
            "must fit the deterministic ZIP and gzip timestamp ranges"
        )
    return parsed


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=positive_epoch, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--extension-id", required=True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    extension = subparsers.add_parser(
        "extension", help="package the browser-neutral MV3 extension"
    )
    add_common_arguments(extension)
    extension.set_defaults(package=package_extension)

    native = subparsers.add_parser(
        "native", help="package one platform native host and installers"
    )
    add_common_arguments(native)
    native.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    native.add_argument(
        "--architecture", choices=sorted(ARCHITECTURES), required=True
    )
    native.add_argument("--rust-target", required=True)
    native.add_argument("--native-host", type=Path, required=True)
    native.set_defaults(package=package_native)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        outputs = arguments.package(arguments)
    except (OSError, PackagingError, json.JSONDecodeError) as error:
        raise SystemExit(f"release packaging failed: {error}") from error
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
