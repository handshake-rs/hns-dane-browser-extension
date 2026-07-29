#!/usr/bin/env python3
"""Build deterministic extension, native-host, and setup release archives."""

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
import shutil
import stat
import subprocess
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
NATIVE_RUST_TARGETS = {
    ("linux", "x64"): "x86_64-unknown-linux-musl",
    ("linux", "arm64"): "aarch64-unknown-linux-musl",
    ("windows", "x64"): "x86_64-pc-windows-msvc",
    ("windows", "arm64"): "aarch64-pc-windows-msvc",
    ("macos", "x64"): "x86_64-apple-darwin",
    ("macos", "arm64"): "aarch64-apple-darwin",
}
SETUP_RUST_TARGETS = {
    **NATIVE_RUST_TARGETS,
    ("linux", "x64"): "x86_64-unknown-linux-gnu",
    ("linux", "arm64"): "aarch64-unknown-linux-gnu",
}
LINUX_RUNTIME_LOADERS = {
    "x64": "ld-linux-x86-64.so.2",
    "arm64": "ld-linux-aarch64.so.1",
}
LINUX_SETUP_HOST_SONAMES = (
    "libdecor-0.so.0",
    "libEGL.so.1",
    "libGL.so.1",
    "libGLX.so.0",
    "libgcc_s.so.1",
    "libwayland-client.so.0",
    "libwayland-cursor.so.0",
    "libwayland-egl.so.1",
    "libX11.so.6",
    "libX11-xcb.so.1",
    "libxcb.so.1",
    "libXcursor.so.1",
    "libXext.so.6",
    "libXfixes.so.3",
    "libXi.so.6",
    "libxkbcommon.so.0",
    "libxkbcommon-x11.so.0",
    "libXrandr.so.2",
)
LINUX_REQUIRED_CERTUTIL_SONAMES = (
    "libc.so.6",
    "libnspr4.so",
    "libnss3.so",
    "libnssckbi.so",
    "libsoftokn3.so",
)
LINUX_REQUIRED_NSS_AUXILIARY = (
    "libfreebl3.chk",
    "libsoftokn3.chk",
)
LINUX_SETUP_SYSTEM_SONAMES = {
    "libanl.so.1",
    "libc.so.6",
    "libdl.so.2",
    "libm.so.6",
    "libpthread.so.0",
    "libresolv.so.2",
    "librt.so.1",
    "libthread_db.so.1",
    "libutil.so.1",
    # The GUI stack must remain coherent with host-loaded Mesa, NVIDIA, and
    # libdecor modules. None of these libraries may be injected by the AppDir.
    *LINUX_SETUP_HOST_SONAMES,
    *LINUX_RUNTIME_LOADERS.values(),
}
LINUX_RUNTIME_METADATA_SCHEMA_VERSION = 2
MACOS_DEPLOYMENT_TARGET = "11.0"
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


def validate_release_binary(
    binary: Path,
    platform: str,
    architecture: str,
    rust_target: str,
    expected_rust_target: str,
    description: str,
) -> None:
    if rust_target != expected_rust_target:
        raise PackagingError(
            f"{platform}-{architecture} {description} must use Rust target "
            f"{expected_rust_target}"
        )
    data = binary.read_bytes()
    if platform == "linux":
        if (
            len(data) < 20
            or data[:4] != b"\x7fELF"
            or data[4] != 2
            or data[5] != 1
        ):
            raise PackagingError(
                f"Linux {description} is not a 64-bit little-endian ELF"
            )
        machine = int.from_bytes(data[18:20], "little")
        expected_machine = 62 if architecture == "x64" else 183
    elif platform == "windows":
        if len(data) < 64 or data[:2] != b"MZ":
            raise PackagingError(f"Windows {description} is not a PE executable")
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if (
            pe_offset > len(data) - 6
            or data[pe_offset : pe_offset + 4] != b"PE\0\0"
        ):
            raise PackagingError(f"Windows {description} has an invalid PE header")
        machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")
        expected_machine = 0x8664 if architecture == "x64" else 0xAA64
    else:
        if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise PackagingError(
                f"macOS {description} is not a little-endian 64-bit Mach-O"
            )
        machine = int.from_bytes(data[4:8], "little")
        expected_machine = 0x01000007 if architecture == "x64" else 0x0100000C
    if machine != expected_machine:
        raise PackagingError(
            f"{description} architecture does not match {platform}-{architecture}"
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
    macos_signed_notarized: bool,
    windows_authenticode_signed: bool,
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
            "The Windows executables are Authenticode signed by the project "
            "publisher and carry RFC 3161 SHA-256 timestamps."
            if windows_authenticode_signed
            else (
                "This automated Windows bundle is unsigned until project "
                "Authenticode credentials are configured."
            )
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
        if platform == "macos" and macos_signed_notarized:
            signing_notice = (
                "This macOS native host is signed with the project Developer ID "
                "Application certificate and accepted by Apple's notarization "
                "service. Apple does not support stapling a notarization ticket "
                "to a standalone executable; Gatekeeper can retrieve its ticket "
                "from Apple when the Mac is online."
            )
        elif platform == "macos":
            signing_notice = (
                "This automated macOS bundle is unsigned and not notarized until "
                "project Apple Developer credentials are configured."
            )
        else:
            signing_notice = (
                "Verify this Linux bundle against the published SHA256SUMS file."
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
    if arguments.macos_signed_notarized and arguments.platform != "macos":
        raise PackagingError(
            "--macos-signed-notarized is valid only for macOS packages"
        )
    if (
        arguments.windows_authenticode_signed
        and arguments.platform != "windows"
    ):
        raise PackagingError(
            "--windows-authenticode-signed is valid only for Windows packages"
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
    validate_release_binary(
        native_host,
        arguments.platform,
        arguments.architecture,
        arguments.rust_target,
        NATIVE_RUST_TARGETS[(arguments.platform, arguments.architecture)],
        "native host",
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
                arguments.macos_signed_notarized,
                arguments.windows_authenticode_signed,
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
                        "codeSigningStatus": (
                            "developerIdSigned"
                            if arguments.macos_signed_notarized
                            else (
                                "authenticodeSigned"
                                if arguments.windows_authenticode_signed
                                else "unsigned"
                            )
                        )
                        if arguments.platform in {"macos", "windows"}
                        else "notApplicable",
                        "notarizationStatus": (
                            "acceptedOnlineTicket"
                            if arguments.macos_signed_notarized
                            else "notNotarized"
                        )
                        if arguments.platform == "macos"
                        else "notApplicable",
                        "platform": arguments.platform,
                        "rustTarget": arguments.rust_target,
                        "timestampStatus": (
                            "rfc3161Sha256"
                            if arguments.windows_authenticode_signed
                            else "notApplicable"
                        )
                        if arguments.platform == "windows"
                        else "notApplicable",
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


def run_system_tool(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise PackagingError(
            f"release runtime staging command failed: {' '.join(command)}: "
            f"{detail.strip()}"
        ) from error
    return completed.stdout


def linux_library_catalog() -> dict[str, Path]:
    catalog: dict[str, Path] = {}
    for line in run_system_tool(["ldconfig", "-p"]).splitlines():
        match = re.match(
            r"^\s*(\S+)\s+\([^)]*\)\s+=>\s+(\S+)\s*$",
            line,
        )
        if match:
            catalog.setdefault(match.group(1), Path(match.group(2)))
    return catalog


def linux_dependencies(binary: Path) -> list[tuple[str, Path]]:
    dependencies: list[tuple[str, Path]] = []
    for line in run_system_tool(["ldd", str(binary)]).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("linux-vdso"):
            continue
        if "=> not found" in stripped:
            raise PackagingError(f"Linux runtime dependency is missing: {stripped}")
        linked = re.match(r"^(\S+)\s+=>\s+(\S+)\s+\(", stripped)
        if linked:
            dependencies.append((linked.group(1), Path(linked.group(2))))
            continue
        loader = re.match(r"^(/\S+)\s+\(", stripped)
        if loader:
            path = Path(loader.group(1))
            dependencies.append((path.name, path))
    return dependencies


def debian_package_for_file(path: Path) -> str:
    candidates = [path]
    resolved = path.resolve()
    if resolved != path:
        candidates.append(resolved)
    for candidate in candidates:
        completed = subprocess.run(
            ["dpkg-query", "--search", str(candidate)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout.splitlines()[0].split(": ", 1)[0]
    raise PackagingError(f"unable to identify the package owning {path}")


def stage_linux_runtime(arguments: argparse.Namespace) -> list[Path]:
    architecture = arguments.architecture
    rust_target = SETUP_RUST_TARGETS[("linux", architecture)]
    certutil = arguments.certutil.resolve()
    if not certutil.is_file():
        raise PackagingError(f"certutil is missing: {certutil}")
    validate_release_binary(
        certutil,
        "linux",
        architecture,
        rust_target,
        rust_target,
        "certutil helper",
    )
    setup_executable = arguments.setup_executable.resolve()
    if (
        not setup_executable.is_file()
        or setup_executable.name != "hns-dane-browser-setup"
    ):
        raise PackagingError(
            "Linux runtime staging requires hns-dane-browser-setup"
        )
    validate_release_binary(
        setup_executable,
        "linux",
        architecture,
        rust_target,
        rust_target,
        "setup executable",
    )

    output = arguments.output_dir.resolve()
    if output.exists():
        raise PackagingError(f"Linux runtime output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    if temporary.exists():
        raise PackagingError(f"Linux runtime temporary output exists: {temporary}")

    catalog = linux_library_catalog()
    queued: dict[str, Path] = {}
    auxiliary: dict[str, Path] = {}

    def add_library(name: str, source: Path) -> None:
        if "/" in name or name in {"", ".", ".."}:
            raise PackagingError(f"invalid Linux runtime library name: {name!r}")
        resolved_source = source.resolve()
        if not resolved_source.is_file():
            raise PackagingError(f"Linux runtime library is missing: {source}")
        previous = queued.get(name)
        if previous is not None and previous != resolved_source:
            if previous.read_bytes() != resolved_source.read_bytes():
                raise PackagingError(
                    f"conflicting Linux runtime libraries use the name {name}"
                )
            return
        queued[name] = resolved_source

    missing_host_libraries = sorted(
        soname
        for soname in LINUX_SETUP_HOST_SONAMES
        if soname not in catalog
    )
    if missing_host_libraries:
        raise PackagingError(
            "required Linux setup host libraries are missing: "
            + ", ".join(missing_host_libraries)
        )

    nss_seeds: dict[str, Path] = {}
    for line in run_system_tool(["dpkg-query", "--listfiles", "libnss3"]).splitlines():
        path = Path(line)
        if ".so" in path.name and path.is_file():
            add_library(path.name, path)
            nss_seeds[path.name] = path
        elif path.suffix == ".chk" and path.is_file():
            auxiliary[path.name] = path.resolve()

    def collect_closure(
        initial_files: list[Path],
        initial_names: set[str],
    ) -> set[str]:
        names = set(initial_names)
        scanned: set[Path] = set()
        scan_queue = list(initial_files)
        while scan_queue:
            source = scan_queue.pop()
            resolved_source = source.resolve()
            if resolved_source in scanned:
                continue
            scanned.add(resolved_source)
            for soname, dependency in linux_dependencies(resolved_source):
                add_library(soname, dependency)
                names.add(soname)
                scan_queue.append(dependency)
        return names

    certutil_libraries = collect_closure(
        [certutil, *nss_seeds.values()],
        set(nss_seeds),
    )
    unexpected_setup_libraries = sorted(
        {
            soname
            for soname, _dependency in linux_dependencies(setup_executable)
            if soname not in LINUX_SETUP_SYSTEM_SONAMES
        }
    )
    if unexpected_setup_libraries:
        raise PackagingError(
            "Linux setup has an unclassified host dependency: "
            + ", ".join(unexpected_setup_libraries)
        )
    setup_libraries: set[str] = set()

    loader_name = LINUX_RUNTIME_LOADERS[architecture]
    missing = [
        name
        for name in (
            *LINUX_REQUIRED_CERTUTIL_SONAMES,
            *LINUX_REQUIRED_NSS_AUXILIARY,
            loader_name,
        )
        if name not in queued and name not in auxiliary
    ]
    if missing:
        raise PackagingError(
            "Linux runtime closure is incomplete: " + ", ".join(sorted(missing))
        )

    packages: dict[str, str] = {}
    file_owners: dict[str, str] = {}
    for destination_name, source in {
        "certutil": certutil,
        **{f"lib/{name}": path for name, path in queued.items()},
        **{f"lib/{name}": path for name, path in auxiliary.items()},
    }.items():
        package = debian_package_for_file(source)
        if package not in packages:
            packages[package] = run_system_tool(
                ["dpkg-query", "--show", "--showformat=${Version}", package]
            )
        file_owners[destination_name] = package

    try:
        (temporary / "lib").mkdir(parents=True)
        (temporary / "licenses").mkdir(parents=True)
        shutil.copyfile(certutil, temporary / "certutil")
        (temporary / "certutil").chmod(0o755)
        for name, source in sorted(queued.items()):
            destination = temporary / "lib" / name
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
        for name, source in sorted(auxiliary.items()):
            destination = temporary / "lib" / name
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
        for package in sorted(packages):
            base_package = package.split(":", 1)[0]
            copyright_path = Path("/usr/share/doc") / base_package / "copyright"
            if not copyright_path.is_file():
                raise PackagingError(
                    f"copyright file is missing for bundled package {package}"
                )
            license_name = f"{package.replace(':', '_')}.copyright"
            shutil.copyfile(copyright_path.resolve(), temporary / "licenses" / license_name)

        staged_files = checked_source_files(temporary)
        os_release = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
        runtime_metadata = {
            "schemaVersion": LINUX_RUNTIME_METADATA_SCHEMA_VERSION,
            "architecture": architecture,
            "distribution": {
                "id": os_release.get("ID", "unknown"),
                "version": os_release.get("VERSION_ID", "unknown"),
            },
            "files": {
                name: {
                    "ownerPackage": file_owners.get(name),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                for name, (data, _mode) in sorted(staged_files.items())
            },
            "packages": dict(sorted(packages.items())),
            "certutilLibraries": sorted(certutil_libraries),
            "setupLibraries": sorted(setup_libraries),
            "setupSystemLibraries": sorted(LINUX_SETUP_HOST_SONAMES),
        }
        (temporary / "RUNTIME-METADATA.json").write_bytes(
            canonical_json(runtime_metadata)
        )
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return [output]


def linux_app_run() -> bytes:
    return b"""#!/bin/sh
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export HNS_SETUP_CERTUTIL="$app_dir/usr/libexec/certutil"
exec "$app_dir/usr/bin/hns-dane-browser-setup" "$@"
"""


def linux_certutil_launcher(loader_name: str) -> bytes:
    return f"""#!/bin/sh
set -eu
libexec_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
runtime_lib="$libexec_dir/certutil-runtime"
exec "$runtime_lib/{loader_name}" \\
  --library-path "$runtime_lib" \\
  "$libexec_dir/certutil.bin" "$@"
""".encode("utf-8")


def macos_info_plist(version: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>hns-dane-browser-setup</string>
  <key>CFBundleIdentifier</key>
  <string>com.denuoweb.hns-dane-browser.setup</string>
  <key>CFBundleName</key>
  <string>HNS DANE Browser Setup</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>{version}</string>
  <key>CFBundleVersion</key>
  <string>{version}</string>
  <key>LSMinimumSystemVersion</key>
  <string>{MACOS_DEPLOYMENT_TARGET}</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
""".encode("utf-8")


def setup_installation_readme(
    version: str,
    platform: str,
    architecture: str,
    source_tag: str,
    macos_signed_notarized: bool,
    windows_authenticode_signed: bool,
) -> bytes:
    if platform == "windows":
        launch = r".\hns-dane-browser-setup.exe"
        language = "powershell"
        layout = (
            "The executable embeds the version-matched native host, links the "
            "Microsoft CRT statically where supported, and otherwise relies only "
            "on Windows components."
        )
        signing = (
            "This Windows setup executable is Authenticode signed by the "
            "project publisher and carries an RFC 3161 SHA-256 timestamp. "
            "Verify the publisher shown by Windows before continuing."
            if windows_authenticode_signed
            else (
                "This automated Windows setup executable is unsigned until "
                "project Authenticode credentials are configured, so Microsoft "
                "Defender SmartScreen may warn. Check the archive against "
                "SHA256SUMS before deciding whether to continue; checksum "
                "verification is required."
            )
        )
    elif platform == "macos":
        launch = 'open "HNS DANE Browser Setup.app"'
        language = "sh"
        layout = (
            "The app embeds the version-matched native host and relies only on "
            "macOS system frameworks. It supports macOS "
            f"{MACOS_DEPLOYMENT_TARGET} or newer."
        )
        if macos_signed_notarized:
            signing = (
                "This macOS app is signed with the project Developer ID "
                "Application certificate, accepted by Apple's notarization "
                "service, and carries a stapled ticket for offline Gatekeeper "
                "verification."
            )
        else:
            signing = (
                "This automated macOS app is unsigned and not notarized until "
                "project Apple Developer credentials are configured. If Gatekeeper "
                "blocks the first launch, use Finder to Control-click the app and "
                "choose Open, or approve that attempted launch in System Settings "
                "> Privacy & Security. Do not disable Gatekeeper globally."
            )
    else:
        launch = "./HNS-DANE-Browser-Setup.AppDir/AppRun"
        language = "sh"
        layout = (
            "The AppDir embeds the statically linked musl native host in the "
            "native GNU setup application and bundles NSS certutil, NSS/NSPR, "
            "and an isolated helper loader/runtime. It uses the host's coherent "
            "Wayland/X11/OpenGL stack; no AppDir-wide library path is injected. "
            f"No system certutil package is required. This v{version} Linux "
            "build requires glibc 2.39 or newer and common desktop GUI libraries "
            "(Ubuntu 24.04 / Debian 13 generation)."
        )
        signing = "Verify this Linux bundle against the published SHA256SUMS file."
    runtime_license_line = (
        "Bundled Linux runtime licenses: "
        "HNS-DANE-Browser-Setup.AppDir/usr/share/licenses/\n"
        if platform == "linux"
        else ""
    )

    text = f"""# HNS DANE Browser setup

Version: {version}
Platform: {platform}-{architecture}

Install the HNS DANE Browser extension first and confirm its exact ID on the
browser extension-management or setup page. Extract this complete archive, then
launch the setup application from the extracted top-level directory:

```{language}
{launch}
```

The setup application performs an explicit per-user install or uninstall for
the Chromium browsers and extension IDs selected by the user. {layout}

{signing}

Do not move individual files out of the extracted application layout. Verify
the archive checksum before launching it.

Source: {REPOSITORY_URL}/tree/{source_tag}
License: {LICENSE_NAME} (the included LICENSE file)
Third-party notices: THIRD_PARTY_NOTICES.txt
{runtime_license_line}\
Donate with GitHub Sponsors: {GITHUB_SPONSORS_URL}
Donate with HNS: {DONATION_URL}
"""
    return text.encode("utf-8")


def verify_staged_linux_runtime(
    runtime: Path,
    architecture: str,
) -> tuple[dict[str, tuple[bytes, int]], dict[str, object]]:
    runtime_files = checked_source_files(runtime)
    metadata_name = "RUNTIME-METADATA.json"
    if metadata_name not in runtime_files:
        raise PackagingError("Linux setup runtime metadata is missing")
    metadata = json.loads(runtime_files[metadata_name][0])
    if (
        metadata.get("schemaVersion") != LINUX_RUNTIME_METADATA_SCHEMA_VERSION
        or metadata.get("architecture") != architecture
        or not isinstance(metadata.get("files"), dict)
        or not isinstance(metadata.get("packages"), dict)
        or not isinstance(metadata.get("certutilLibraries"), list)
        or not isinstance(metadata.get("setupLibraries"), list)
        or not isinstance(metadata.get("setupSystemLibraries"), list)
    ):
        raise PackagingError("Linux setup runtime metadata is invalid")
    expected_hashes = {
        name: details.get("sha256")
        for name, details in metadata["files"].items()
        if isinstance(name, str) and isinstance(details, dict)
    }
    actual_hashes = {
        name: hashlib.sha256(data).hexdigest()
        for name, (data, _mode) in runtime_files.items()
        if name != metadata_name
    }
    if expected_hashes != actual_hashes:
        raise PackagingError("Linux setup runtime files do not match their metadata")

    required = {
        "certutil",
        f"lib/{LINUX_RUNTIME_LOADERS[architecture]}",
        *(f"lib/{name}" for name in LINUX_REQUIRED_CERTUTIL_SONAMES),
        *(f"lib/{name}" for name in LINUX_REQUIRED_NSS_AUXILIARY),
    }
    missing = sorted(required.difference(runtime_files))
    if missing:
        raise PackagingError(
            "Linux setup runtime is incomplete: " + ", ".join(missing)
        )
    for classification in (
        metadata["certutilLibraries"],
        metadata["setupLibraries"],
        metadata["setupSystemLibraries"],
    ):
        if any(
            not isinstance(name, str)
            or not name
            or "/" in name
            or "\\" in name
            for name in classification
        ):
            raise PackagingError(
                "Linux runtime library classifications contain an unsafe name"
            )
    certutil_libraries = set(metadata["certutilLibraries"])
    setup_libraries = set(metadata["setupLibraries"])
    setup_system_libraries = set(metadata["setupSystemLibraries"])
    available_libraries = {
        name.removeprefix("lib/")
        for name in runtime_files
        if name.startswith("lib/")
    }
    if (
        not certutil_libraries.issubset(available_libraries)
        or not setup_libraries.issubset(available_libraries)
    ):
        raise PackagingError("Linux runtime library classifications are invalid")
    required_certutil_libraries = {
        LINUX_RUNTIME_LOADERS[architecture],
        "libc.so.6",
        "libnspr4.so",
        "libnss3.so",
        "libnssckbi.so",
        "libsoftokn3.so",
    }
    if not required_certutil_libraries.issubset(certutil_libraries):
        raise PackagingError("Linux certutil runtime classification is incomplete")
    if setup_libraries:
        raise PackagingError(
            "Linux setup runtime must not bundle shared libraries: "
            + ", ".join(sorted(setup_libraries))
        )
    if setup_system_libraries != set(LINUX_SETUP_HOST_SONAMES):
        raise PackagingError(
            "Linux setup host library classification is incomplete"
        )
    if not any(name.startswith("licenses/") for name in runtime_files):
        raise PackagingError("Linux setup runtime contains no dependency licenses")
    freebl_modules = {
        name
        for name in ("lib/libfreebl3.so", "lib/libfreeblpriv3.so")
        if name in runtime_files
    }
    if not freebl_modules:
        raise PackagingError("Linux setup runtime contains no NSS freebl module")
    for module in sorted(
        name
        for name in runtime_files
        if re.fullmatch(
            r"lib/lib(?:freebl3|freeblpriv3|nssdbm3|softokn3)\.so",
            name,
        )
    ):
        check_file = module.removesuffix(".so") + ".chk"
        if check_file not in runtime_files:
            raise PackagingError(
                f"Linux setup runtime omits the NSS integrity file {check_file}"
            )
    certutil_path = runtime / "certutil"
    validate_release_binary(
        certutil_path,
        "linux",
        architecture,
        SETUP_RUST_TARGETS[("linux", architecture)],
        SETUP_RUST_TARGETS[("linux", architecture)],
        "certutil helper",
    )
    return runtime_files, metadata


def package_setup(arguments: argparse.Namespace) -> list[Path]:
    root = arguments.repository_root.resolve()
    context = load_release_context(
        root,
        arguments.source_commit,
        arguments.source_tag,
        arguments.extension_id,
    )
    if arguments.platform not in PLATFORMS:
        raise PackagingError(f"unsupported setup platform: {arguments.platform}")
    if arguments.architecture not in ARCHITECTURES:
        raise PackagingError(
            f"unsupported setup architecture: {arguments.architecture}"
        )
    if arguments.macos_signed_notarized and arguments.platform != "macos":
        raise PackagingError(
            "--macos-signed-notarized is valid only for macOS packages"
        )
    if (
        arguments.windows_authenticode_signed
        and arguments.platform != "windows"
    ):
        raise PackagingError(
            "--windows-authenticode-signed is valid only for Windows packages"
        )

    expected_setup_name = (
        "hns-dane-browser-setup.exe"
        if arguments.platform == "windows"
        else "hns-dane-browser-setup"
    )
    setup_executable = arguments.setup_executable.resolve()
    if (
        not setup_executable.is_file()
        or setup_executable.is_symlink()
        or setup_executable.name != expected_setup_name
    ):
        raise PackagingError(
            f"{arguments.platform} setup executable must be a regular "
            f"{expected_setup_name} file"
        )
    validate_release_binary(
        setup_executable,
        arguments.platform,
        arguments.architecture,
        arguments.setup_rust_target,
        SETUP_RUST_TARGETS[(arguments.platform, arguments.architecture)],
        "setup executable",
    )

    expected_host_name = (
        "hns-chromium-native-host.exe"
        if arguments.platform == "windows"
        else "hns-chromium-native-host"
    )
    native_host = arguments.embedded_native_host.resolve()
    if (
        not native_host.is_file()
        or native_host.is_symlink()
        or native_host.name != expected_host_name
    ):
        raise PackagingError(
            f"embedded native host must be a regular {expected_host_name} file"
        )
    validate_release_binary(
        native_host,
        arguments.platform,
        arguments.architecture,
        arguments.native_rust_target,
        NATIVE_RUST_TARGETS[(arguments.platform, arguments.architecture)],
        "embedded native host",
    )
    setup_bytes = setup_executable.read_bytes()
    native_host_bytes = native_host.read_bytes()
    if native_host_bytes not in setup_bytes:
        raise PackagingError(
            "setup executable does not contain the exact native host payload"
        )

    version = str(context["version"])
    setup_metadata: dict[str, object] = {
        "architecture": arguments.architecture,
        "codeSigningStatus": (
            "developerIdSigned"
            if arguments.macos_signed_notarized
            else (
                "authenticodeSigned"
                if arguments.windows_authenticode_signed
                else "unsigned"
            )
        )
        if arguments.platform in {"macos", "windows"}
        else "notApplicable",
        "embeddedNativeHost": {
            "fileName": expected_host_name,
            "includedAsStandaloneFile": False,
            "rustTarget": arguments.native_rust_target,
            "sha256": hashlib.sha256(native_host_bytes).hexdigest(),
        },
        "notarizationStatus": (
            "acceptedAndStapled"
            if arguments.macos_signed_notarized
            else "notNotarized"
        )
        if arguments.platform == "macos"
        else "notApplicable",
        "platform": arguments.platform,
        "setupRustTarget": arguments.setup_rust_target,
        "selfContained": True,
        "timestampStatus": (
            "rfc3161Sha256"
            if arguments.windows_authenticode_signed
            else "notApplicable"
        )
        if arguments.platform == "windows"
        else "notApplicable",
    }
    files: dict[str, tuple[bytes, int]] = {
        "LICENSE": (normalized_text(root / "LICENSE"), 0o644),
        "README.md": (
            setup_installation_readme(
                version,
                arguments.platform,
                arguments.architecture,
                arguments.source_tag,
                arguments.macos_signed_notarized,
                arguments.windows_authenticode_signed,
            ),
            0o644,
        ),
        "THIRD_PARTY_NOTICES.txt": (
            normalized_text(root / "extension/THIRD_PARTY_NOTICES.txt"),
            0o644,
        ),
    }

    if arguments.platform == "linux":
        if arguments.linux_runtime is None:
            raise PackagingError("Linux setup packaging requires --linux-runtime")
        runtime_files, runtime_metadata = verify_staged_linux_runtime(
            arguments.linux_runtime.resolve(),
            arguments.architecture,
        )
        app_root = "HNS-DANE-Browser-Setup.AppDir"
        files[f"{app_root}/AppRun"] = (linux_app_run(), 0o755)
        files[f"{app_root}/usr/bin/{expected_setup_name}"] = (setup_bytes, 0o755)
        files[f"{app_root}/usr/libexec/certutil"] = (
            linux_certutil_launcher(
                LINUX_RUNTIME_LOADERS[arguments.architecture]
            ),
            0o755,
        )
        files[f"{app_root}/usr/libexec/certutil.bin"] = (
            runtime_files["certutil"][0],
            0o755,
        )
        certutil_libraries = set(runtime_metadata["certutilLibraries"])
        for name in sorted(certutil_libraries):
            files[
                f"{app_root}/usr/libexec/certutil-runtime/{name}"
            ] = (
                runtime_files[f"lib/{name}"][0],
                0o755
                if name == LINUX_RUNTIME_LOADERS[arguments.architecture]
                else 0o644,
            )
        for name in LINUX_REQUIRED_NSS_AUXILIARY:
            files[
                f"{app_root}/usr/libexec/certutil-runtime/{name}"
            ] = runtime_files[f"lib/{name}"]
        for name, value in runtime_files.items():
            if name.startswith("licenses/"):
                files[f"{app_root}/usr/share/{name}"] = value
        files[f"{app_root}/usr/share/runtime/RUNTIME-METADATA.json"] = (
            canonical_json(runtime_metadata),
            0o644,
        )
        setup_metadata.update(
            {
                "binary": f"{app_root}/usr/bin/{expected_setup_name}",
                "bundledCertutil": f"{app_root}/usr/libexec/certutil",
                "launcher": f"{app_root}/AppRun",
                "linuxRuntime": runtime_metadata,
                "selfContained": False,
                "systemLibraries": sorted(LINUX_SETUP_HOST_SONAMES),
            }
        )
    elif arguments.platform == "macos":
        app_root = "HNS DANE Browser Setup.app"
        binary_path = f"{app_root}/Contents/MacOS/{expected_setup_name}"
        files[binary_path] = (setup_bytes, 0o755)
        files[f"{app_root}/Contents/Info.plist"] = (
            macos_info_plist(version),
            0o644,
        )
        files[f"{app_root}/Contents/Resources/LICENSE"] = (
            files["LICENSE"][0],
            0o644,
        )
        files[
            f"{app_root}/Contents/Resources/THIRD_PARTY_NOTICES.txt"
        ] = (
            files["THIRD_PARTY_NOTICES.txt"][0],
            0o644,
        )
        setup_metadata.update(
            {
                "binary": binary_path,
                "bundle": app_root,
                "minimumSystemVersion": MACOS_DEPLOYMENT_TARGET,
                "runtimeDependencies": "systemFrameworksOnly",
            }
        )
    else:
        files[expected_setup_name] = (setup_bytes, 0o755)
        setup_metadata.update(
            {
                "binary": expected_setup_name,
                "crtLinkage": "static",
                "runtimeDependencies": "windowsComponentsOnly",
            }
        )

    files["RELEASE-METADATA.json"] = (
        canonical_json({**context["metadata"], "setup": setup_metadata}),
        0o644,
    )
    stem = (
        f"hns-dane-browser-setup-v{version}-"
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
    native.add_argument(
        "--macos-signed-notarized",
        action="store_true",
        help="mark a macOS binary already signed and accepted by Apple",
    )
    native.add_argument(
        "--windows-authenticode-signed",
        action="store_true",
        help="mark a Windows binary already Authenticode signed and timestamped",
    )
    native.set_defaults(package=package_native)

    setup = subparsers.add_parser(
        "setup", help="package one platform setup application"
    )
    add_common_arguments(setup)
    setup.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    setup.add_argument(
        "--architecture", choices=sorted(ARCHITECTURES), required=True
    )
    setup.add_argument("--native-rust-target", required=True)
    setup.add_argument("--setup-rust-target", required=True)
    setup.add_argument("--setup-executable", type=Path, required=True)
    setup.add_argument("--embedded-native-host", type=Path, required=True)
    setup.add_argument("--linux-runtime", type=Path)
    setup.add_argument(
        "--macos-signed-notarized",
        action="store_true",
        help="mark a macOS app already signed, accepted, and stapled",
    )
    setup.add_argument(
        "--windows-authenticode-signed",
        action="store_true",
        help="mark a Windows app already Authenticode signed and timestamped",
    )
    setup.set_defaults(package=package_setup)

    linux_runtime = subparsers.add_parser(
        "linux-runtime",
        help=(
            "stage the bundled NSS/NSPR runtime and validate host "
            "dependencies for a Linux setup app"
        ),
    )
    linux_runtime.add_argument("--output-dir", type=Path, required=True)
    linux_runtime.add_argument(
        "--architecture", choices=sorted(ARCHITECTURES), required=True
    )
    linux_runtime.add_argument("--certutil", type=Path, required=True)
    linux_runtime.add_argument("--setup-executable", type=Path, required=True)
    linux_runtime.set_defaults(package=stage_linux_runtime)
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
