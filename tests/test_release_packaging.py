from __future__ import annotations

import base64
import gzip
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parent.parent
PACKAGER = ROOT / "scripts/package-release.py"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop"
EPOCH = "1700000000"
IDENTITY = json.loads(
    (ROOT / "release/extension-identity.json").read_text(encoding="utf-8")
)
CANONICAL_ID = IDENTITY["canonicalId"]


def fake_native_binary(platform: str, architecture: str) -> bytes:
    if platform == "linux":
        binary = bytearray(64)
        binary[:6] = b"\x7fELF\x02\x01"
        machine = 62 if architecture == "x64" else 183
        binary[18:20] = machine.to_bytes(2, "little")
    elif platform == "windows":
        binary = bytearray(128)
        binary[:2] = b"MZ"
        binary[0x3C:0x40] = (64).to_bytes(4, "little")
        binary[64:68] = b"PE\0\0"
        machine = 0x8664 if architecture == "x64" else 0xAA64
        binary[68:70] = machine.to_bytes(2, "little")
    else:
        binary = bytearray(64)
        binary[:4] = b"\xcf\xfa\xed\xfe"
        machine = 0x01000007 if architecture == "x64" else 0x0100000C
        binary[4:8] = machine.to_bytes(4, "little")
    return bytes(binary)


LINUX_RUNTIME_LIBRARIES = (
    "ld-linux-x86-64.so.2",
    "libc.so.6",
    "libfreebl3.chk",
    "libfreebl3.so",
    "libfreeblpriv3.chk",
    "libfreeblpriv3.so",
    "libnspr4.so",
    "libnss3.so",
    "libnssckbi.so",
    "libnssdbm3.chk",
    "libnssdbm3.so",
    "libsoftokn3.chk",
    "libsoftokn3.so",
)
LINUX_SETUP_SYSTEM_LIBRARIES = (
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


def fake_setup_binary(
    platform: str,
    architecture: str,
    native_host: bytes,
) -> bytes:
    return (
        fake_native_binary(platform, architecture)
        + b"\0embedded-native-host\0"
        + native_host
    )


def write_fake_linux_runtime(directory: Path) -> None:
    files: dict[str, bytes] = {
        "certutil": fake_native_binary("linux", "x64"),
        "licenses/fake-runtime.copyright": b"Fake runtime license fixture\n",
    }
    files.update(
        {
            f"lib/{name}": f"fixture:{name}\n".encode()
            for name in LINUX_RUNTIME_LIBRARIES
        }
    )
    for name, data in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    metadata = {
        "schemaVersion": 2,
        "architecture": "x64",
        "distribution": {"id": "fixture", "version": "1"},
        "files": {
            name: {
                "ownerPackage": "fixture",
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for name, data in sorted(files.items())
        },
        "packages": {"fixture": "1"},
        "certutilLibraries": sorted(
            name
            for name in LINUX_RUNTIME_LIBRARIES
            if name.startswith("ld-linux")
            or name == "libc.so.6"
            or any(
                marker in name
                for marker in ("freebl", "nspr", "nss", "softokn")
            )
        ),
        "setupLibraries": [],
        "setupSystemLibraries": sorted(LINUX_SETUP_SYSTEM_LIBRARIES),
    }
    (directory / "RUNTIME-METADATA.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class ReleasePackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run(
            ["node", "extension/scripts/build.mjs"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        cls.version = json.loads(
            (ROOT / "extension/manifest.json").read_text(encoding="utf-8")
        )["version"]
        cls.tag = f"v{cls.version}"

    def run_packager(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(PACKAGER), *arguments],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

    def common_arguments(self, output: Path) -> list[str]:
        return [
            "--output-dir",
            str(output),
            "--source-date-epoch",
            EPOCH,
            "--source-commit",
            COMMIT,
            "--source-tag",
            self.tag,
            "--extension-id",
            EXTENSION_ID,
        ]

    def test_extension_zip_is_deterministic_and_store_ready(self) -> None:
        public_key = base64.b64decode(
            IDENTITY["publicKeyDerBase64"],
            validate=True,
        )
        derived_id = "".join(
            chr(ord("a") + nibble)
            for byte in hashlib.sha256(public_key).digest()[:16]
            for nibble in (byte >> 4, byte & 0x0F)
        )
        self.assertEqual(CANONICAL_ID, derived_id)
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            self.run_packager("extension", *self.common_arguments(first))
            self.run_packager("extension", *self.common_arguments(second))
            name = f"hns-dane-browser-extension-v{self.version}-mv3.zip"
            first_archive = first / name
            second_archive = second / name
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assert_checksum(first_archive)
            store_name = (
                f"hns-dane-browser-extension-v{self.version}-mv3-store.zip"
            )
            first_store_archive = first / store_name
            second_store_archive = second / store_name
            self.assertEqual(
                first_store_archive.read_bytes(),
                second_store_archive.read_bytes(),
            )
            self.assert_checksum(first_store_archive)

            with zipfile.ZipFile(first_archive) as archive:
                names = archive.namelist()
                self.assertEqual(names, sorted(names))
                self.assertIn("LICENSE", names)
                self.assertIn("RELEASE-METADATA.json", names)
                self.assertIn("manifest.json", names)
                self.assertNotIn("key.pem", names)
                manifest = json.loads(archive.read("manifest.json"))
                metadata = json.loads(archive.read("RELEASE-METADATA.json"))
                self.assertEqual(manifest["manifest_version"], 3)
                self.assertEqual(
                    manifest["key"],
                    IDENTITY["publicKeyDerBase64"],
                )
                self.assertEqual(
                    metadata["extensionPackageVariant"],
                    "canonicalUnpacked",
                )
                self.assertTrue(metadata["manifestKeyIncluded"])
                self.assertEqual(
                    metadata["extension"]["canonicalReleaseId"],
                    CANONICAL_ID,
                )
                self.assertEqual(
                    metadata["extension"]["nativeRegistrationIds"],
                    [CANONICAL_ID, EXTENSION_ID],
                )
                self.assertTrue(metadata["extension"]["catalogIdsMayDiffer"])
                self.assertEqual(metadata["source"]["commit"], COMMIT)
                self.assertEqual(metadata["license"]["path"], "LICENSE")
                self.assertEqual(
                    metadata["donationUrls"][0],
                    "https://github.com/sponsors/denuoweb",
                )
                self.assertTrue(metadata["donationUrls"][1].startswith("handshake:"))
                timestamps = {entry.date_time for entry in archive.infolist()}
                self.assertEqual(timestamps, {(2023, 11, 14, 22, 13, 20)})
            with zipfile.ZipFile(first_store_archive) as archive:
                store_manifest = json.loads(archive.read("manifest.json"))
                store_metadata = json.loads(
                    archive.read("RELEASE-METADATA.json")
                )
                self.assertNotIn("key", store_manifest)
                self.assertEqual(
                    store_metadata["extensionPackageVariant"],
                    "storeFirstSubmission",
                )
                self.assertFalse(store_metadata["manifestKeyIncluded"])

    def test_candidate_extension_metadata_claims_only_its_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "candidate"
            self.run_packager(
                "extension",
                "--output-dir",
                str(output),
                "--source-date-epoch",
                EPOCH,
                "--source-commit",
                COMMIT,
                "--candidate-source",
                "--extension-id",
                EXTENSION_ID,
            )
            archive_path = (
                output
                / f"hns-dane-browser-extension-v{self.version}-mv3.zip"
            )
            with zipfile.ZipFile(archive_path) as archive:
                metadata = json.loads(archive.read("RELEASE-METADATA.json"))
                build_metadata = json.loads(archive.read("BUILD-METADATA.json"))
            self.assertEqual(metadata["source"]["commit"], COMMIT)
            self.assertTrue(metadata["source"]["qualificationCandidate"])
            self.assertNotIn("tag", metadata["source"])
            self.assertNotIn("tagUrl", metadata["source"])
            self.assertEqual(
                metadata["license"]["url"],
                "https://github.com/handshake-rs/"
                f"hns-dane-browser-extension/blob/{COMMIT}/LICENSE",
            )
            self.assertNotIn("sourceTag", build_metadata)

    def test_candidate_native_metadata_and_readme_are_commit_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "candidate"
            binary = root / "hns-chromium-native-host"
            binary.write_bytes(fake_native_binary("linux", "x64"))
            binary.chmod(0o755)
            self.run_packager(
                "native",
                "--output-dir",
                str(output),
                "--source-date-epoch",
                EPOCH,
                "--source-commit",
                COMMIT,
                "--candidate-source",
                "--extension-id",
                EXTENSION_ID,
                "--platform",
                "linux",
                "--architecture",
                "x64",
                "--rust-target",
                "x86_64-unknown-linux-musl",
                "--native-host",
                str(binary),
            )
            stem = f"hns-dane-browser-native-host-v{self.version}-linux-x64"
            with tarfile.open(output / f"{stem}.tar.gz", "r:gz") as archive:
                metadata = json.load(
                    archive.extractfile(f"{stem}/RELEASE-METADATA.json")
                )
                readme = archive.extractfile(f"{stem}/README.md").read().decode()
            self.assertTrue(metadata["source"]["qualificationCandidate"])
            self.assertNotIn("tag", metadata["source"])
            self.assertIn(
                f"Source: https://github.com/handshake-rs/"
                f"hns-dane-browser-extension/commit/{COMMIT}",
                readme,
            )

    def test_linux_native_bundle_is_deterministic_and_installable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "hns-chromium-native-host"
            binary.write_bytes(fake_native_binary("linux", "x64"))
            binary.chmod(0o755)
            outputs = [base / "first", base / "second"]
            for output in outputs:
                self.run_packager(
                    "native",
                    *self.common_arguments(output),
                    "--platform",
                    "linux",
                    "--architecture",
                    "x64",
                    "--rust-target",
                    "x86_64-unknown-linux-musl",
                    "--native-host",
                    str(binary),
                )
            stem = (
                f"hns-dane-browser-native-host-v{self.version}-linux-x64"
            )
            name = f"{stem}.tar.gz"
            first_archive = outputs[0] / name
            second_archive = outputs[1] / name
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assert_checksum(first_archive)
            with first_archive.open("rb") as handle:
                with gzip.GzipFile(fileobj=handle) as compressed:
                    compressed.read(1)
                    self.assertEqual(compressed.mtime, int(EPOCH))
            with tarfile.open(first_archive, "r:gz") as archive:
                files = {
                    member.name: member
                    for member in archive.getmembers()
                    if member.isfile()
                }
                binary_name = (
                    f"{stem}/rust/target/release/hns-chromium-native-host"
                )
                install_name = f"{stem}/extension/install/install.sh"
                readme_name = f"{stem}/README.md"
                self.assertIn(binary_name, files)
                self.assertIn(install_name, files)
                self.assertIn(f"{stem}/extension/install/uninstall.sh", files)
                self.assertIn(f"{stem}/LICENSE", files)
                self.assertIn(
                    f"{stem}/extension/THIRD_PARTY_NOTICES.txt", files
                )
                self.assertEqual(stat.S_IMODE(files[binary_name].mode), 0o755)
                self.assertEqual(stat.S_IMODE(files[install_name].mode), 0o755)
                readme = archive.extractfile(files[readme_name]).read().decode()
                self.assertIn(
                    f"--extension-id {CANONICAL_ID} "
                    f"--extension-id {EXTENSION_ID} --browser all",
                    readme,
                )
                self.assertIn("Donate with GitHub Sponsors:", readme)
                self.assertIn("Donate with HNS: handshake:", readme)
                self.assertEqual(
                    {member.mtime for member in archive.getmembers()},
                    {int(EPOCH)},
                )

    def test_windows_bundle_uses_exe_and_powershell_installers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "hns-chromium-native-host.exe"
            binary.write_bytes(fake_native_binary("windows", "arm64"))
            output = base / "output"
            self.run_packager(
                "native",
                *self.common_arguments(output),
                "--platform",
                "windows",
                "--architecture",
                "arm64",
                "--rust-target",
                "aarch64-pc-windows-msvc",
                "--native-host",
                str(binary),
            )
            stem = (
                f"hns-dane-browser-native-host-v{self.version}-windows-arm64"
            )
            archive_path = output / f"{stem}.zip"
            self.assert_checksum(archive_path)
            with zipfile.ZipFile(archive_path) as archive:
                names = archive.namelist()
                self.assertIn(
                    f"{stem}/rust/target/release/hns-chromium-native-host.exe",
                    names,
                )
                self.assertIn(
                    f"{stem}/extension/install/install.ps1",
                    names,
                )
                self.assertIn(
                    f"{stem}/extension/install/uninstall.ps1",
                    names,
                )
                self.assertNotIn(
                    f"{stem}/extension/install/install.sh",
                    names,
                )
                readme = archive.read(f"{stem}/README.md").decode()
                self.assertEqual(
                    readme.count(
                        "Set-ExecutionPolicy -Scope Process Bypass -Force;"
                    ),
                    2,
                )
                self.assertIn(
                    f'-ExtensionId @("{CANONICAL_ID}", '
                    f'"{EXTENSION_ID}")',
                    readme,
                )
                metadata = json.loads(
                    archive.read(f"{stem}/RELEASE-METADATA.json")
                )
                self.assertEqual(
                    metadata["nativeHost"]["codeSigningStatus"],
                    "unsigned",
                )
                self.assertEqual(
                    metadata["nativeHost"]["notarizationStatus"],
                    "notApplicable",
                )
                self.assertIn("Windows bundle is unsigned", readme)

            signed_output = base / "signed-output"
            self.run_packager(
                "native",
                *self.common_arguments(signed_output),
                "--platform",
                "windows",
                "--architecture",
                "arm64",
                "--rust-target",
                "aarch64-pc-windows-msvc",
                "--native-host",
                str(binary),
                "--windows-authenticode-signed",
            )
            with zipfile.ZipFile(
                signed_output / f"{stem}.zip",
            ) as archive:
                metadata = json.loads(
                    archive.read(f"{stem}/RELEASE-METADATA.json")
                )
                readme = archive.read(f"{stem}/README.md").decode()
                self.assertEqual(
                    metadata["nativeHost"]["codeSigningStatus"],
                    "authenticodeSigned",
                )
                self.assertEqual(
                    metadata["nativeHost"]["timestampStatus"],
                    "rfc3161Sha256",
                )
                self.assertIn("RFC 3161 SHA-256 timestamps", readme)
                self.assertNotIn("Windows bundle is unsigned", readme)

    def test_macos_bundle_discloses_signing_and_notarization_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "hns-chromium-native-host"
            binary.write_bytes(fake_native_binary("macos", "arm64"))
            binary.chmod(0o755)
            output = base / "output"
            self.run_packager(
                "native",
                *self.common_arguments(output),
                "--platform",
                "macos",
                "--architecture",
                "arm64",
                "--rust-target",
                "aarch64-apple-darwin",
                "--native-host",
                str(binary),
            )
            stem = (
                f"hns-dane-browser-native-host-v{self.version}-macos-arm64"
            )
            with tarfile.open(output / f"{stem}.tar.gz", "r:gz") as archive:
                readme = archive.extractfile(f"{stem}/README.md").read().decode()
                metadata = json.loads(
                    archive.extractfile(
                        f"{stem}/RELEASE-METADATA.json"
                    ).read()
                )
                self.assertEqual(
                    metadata["nativeHost"]["codeSigningStatus"],
                    "unsigned",
                )
                self.assertEqual(
                    metadata["nativeHost"]["notarizationStatus"],
                    "notNotarized",
                )
                self.assertIn("unsigned and not notarized", readme)

            signed_output = base / "signed-output"
            self.run_packager(
                "native",
                *self.common_arguments(signed_output),
                "--platform",
                "macos",
                "--architecture",
                "arm64",
                "--rust-target",
                "aarch64-apple-darwin",
                "--native-host",
                str(binary),
                "--macos-signed-notarized",
            )
            with tarfile.open(
                signed_output / f"{stem}.tar.gz",
                "r:gz",
            ) as archive:
                readme = archive.extractfile(f"{stem}/README.md").read().decode()
                metadata = json.loads(
                    archive.extractfile(
                        f"{stem}/RELEASE-METADATA.json"
                    ).read()
                )
                self.assertEqual(
                    metadata["nativeHost"]["codeSigningStatus"],
                    "developerIdSigned",
                )
                self.assertEqual(
                    metadata["nativeHost"]["notarizationStatus"],
                    "acceptedOnlineTicket",
                )
                self.assertIn(
                    "Apple does not support stapling a notarization ticket",
                    readme,
                )
                self.assertNotIn("unsigned and not notarized", readme)

    def test_linux_setup_appdir_is_deterministic_and_isolates_certutil(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            native_bytes = fake_native_binary("linux", "x64")
            native_host = base / "hns-chromium-native-host"
            native_host.write_bytes(native_bytes)
            setup = base / "hns-dane-browser-setup"
            setup.write_bytes(fake_setup_binary("linux", "x64", native_bytes))
            runtime = base / "runtime"
            write_fake_linux_runtime(runtime)
            outputs = [base / "first", base / "second"]
            for output in outputs:
                self.run_packager(
                    "setup",
                    *self.common_arguments(output),
                    "--platform",
                    "linux",
                    "--architecture",
                    "x64",
                    "--native-rust-target",
                    "x86_64-unknown-linux-musl",
                    "--setup-rust-target",
                    "x86_64-unknown-linux-gnu",
                    "--setup-executable",
                    str(setup),
                    "--embedded-native-host",
                    str(native_host),
                    "--linux-runtime",
                    str(runtime),
                )

            stem = f"hns-dane-browser-setup-v{self.version}-linux-x64"
            first_archive = outputs[0] / f"{stem}.tar.gz"
            second_archive = outputs[1] / f"{stem}.tar.gz"
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assert_checksum(first_archive)
            app = f"{stem}/HNS-DANE-Browser-Setup.AppDir"
            with tarfile.open(first_archive, "r:gz") as archive:
                files = {
                    member.name: member
                    for member in archive.getmembers()
                    if member.isfile()
                }
                launcher = f"{app}/AppRun"
                setup_name = f"{app}/usr/bin/hns-dane-browser-setup"
                helper = f"{app}/usr/libexec/certutil"
                helper_binary = f"{app}/usr/libexec/certutil.bin"
                self.assertIn(launcher, files)
                self.assertIn(setup_name, files)
                self.assertIn(helper, files)
                self.assertIn(helper_binary, files)
                self.assertIn(
                    f"{app}/usr/libexec/certutil-runtime/libnss3.so",
                    files,
                )
                self.assertIn(
                    f"{app}/usr/libexec/certutil-runtime/libnspr4.so",
                    files,
                )
                self.assertFalse(
                    any(name.startswith(f"{app}/usr/lib/") for name in files)
                )
                self.assertIn(
                    f"{app}/usr/libexec/certutil-runtime/libsoftokn3.chk",
                    files,
                )
                loader = (
                    f"{app}/usr/libexec/certutil-runtime/"
                    "ld-linux-x86-64.so.2"
                )
                self.assertEqual(stat.S_IMODE(files[loader].mode), 0o755)
                self.assertNotIn(f"{app}/usr/lib/libc.so.6", files)
                self.assertIn(
                    f"{app}/usr/share/licenses/fake-runtime.copyright",
                    files,
                )
                self.assertEqual(stat.S_IMODE(files[launcher].mode), 0o755)
                self.assertEqual(stat.S_IMODE(files[setup_name].mode), 0o755)
                self.assertEqual(stat.S_IMODE(files[helper].mode), 0o755)
                self.assertNotIn(
                    f"{app}/usr/bin/hns-chromium-native-host",
                    files,
                )
                app_run = archive.extractfile(files[launcher]).read().decode()
                self.assertIn("HNS_SETUP_CERTUTIL", app_run)
                self.assertNotIn("LD_LIBRARY_PATH", app_run)
                self.assertNotIn('"$app_dir/usr/lib"', app_run)
                self.assertNotIn("HNS_SETUP_CERTUTIL_LIB_DIR", app_run)
                metadata = json.loads(
                    archive.extractfile(
                        f"{stem}/RELEASE-METADATA.json"
                    ).read()
                )
                self.assertFalse(metadata["setup"]["selfContained"])
                self.assertEqual(
                    metadata["setup"]["systemLibraries"],
                    sorted(LINUX_SETUP_SYSTEM_LIBRARIES),
                )
                self.assertEqual(
                    metadata["setup"]["linuxRuntime"]["schemaVersion"],
                    2,
                )
                self.assertEqual(
                    metadata["setup"]["embeddedNativeHost"]["sha256"],
                    hashlib.sha256(native_bytes).hexdigest(),
                )
                self.assertEqual(
                    metadata["setup"]["embeddedNativeHost"]["rustTarget"],
                    "x86_64-unknown-linux-musl",
                )
                self.assertEqual(
                    metadata["setup"]["setupRustTarget"],
                    "x86_64-unknown-linux-gnu",
                )
                self.assertFalse(
                    metadata["setup"]["embeddedNativeHost"][
                        "includedAsStandaloneFile"
                    ]
                )
                readme = archive.extractfile(f"{stem}/README.md").read().decode()
                self.assertIn("No system certutil package is required", readme)
                self.assertIn("host's coherent Wayland/X11/OpenGL stack", readme)
                self.assertIn("Bundled Linux runtime licenses", readme)

    def test_windows_setup_is_one_self_contained_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            native_bytes = fake_native_binary("windows", "arm64")
            native_host = base / "hns-chromium-native-host.exe"
            native_host.write_bytes(native_bytes)
            setup = base / "hns-dane-browser-setup.exe"
            setup.write_bytes(fake_setup_binary("windows", "arm64", native_bytes))
            output = base / "output"
            self.run_packager(
                "setup",
                *self.common_arguments(output),
                "--platform",
                "windows",
                "--architecture",
                "arm64",
                "--native-rust-target",
                "aarch64-pc-windows-msvc",
                "--setup-rust-target",
                "aarch64-pc-windows-msvc",
                "--setup-executable",
                str(setup),
                "--embedded-native-host",
                str(native_host),
            )
            stem = f"hns-dane-browser-setup-v{self.version}-windows-arm64"
            archive_path = output / f"{stem}.zip"
            self.assert_checksum(archive_path)
            with zipfile.ZipFile(archive_path) as archive:
                names = archive.namelist()
                setup_name = f"{stem}/hns-dane-browser-setup.exe"
                self.assertIn(setup_name, names)
                self.assertNotIn(
                    f"{stem}/hns-chromium-native-host.exe",
                    names,
                )
                metadata = json.loads(
                    archive.read(f"{stem}/RELEASE-METADATA.json")
                )
                self.assertEqual(metadata["setup"]["crtLinkage"], "static")
                self.assertEqual(
                    metadata["setup"]["runtimeDependencies"],
                    "windowsComponentsOnly",
                )
                self.assertEqual(
                    metadata["setup"]["codeSigningStatus"],
                    "unsigned",
                )
                readme = archive.read(f"{stem}/README.md").decode()
                self.assertIn("SmartScreen may warn", readme)
                self.assertIn("checksum verification is required", readme)
                self.assertNotIn("Bundled Linux runtime licenses", readme)

            signed_output = base / "signed-output"
            self.run_packager(
                "setup",
                *self.common_arguments(signed_output),
                "--platform",
                "windows",
                "--architecture",
                "arm64",
                "--native-rust-target",
                "aarch64-pc-windows-msvc",
                "--setup-rust-target",
                "aarch64-pc-windows-msvc",
                "--setup-executable",
                str(setup),
                "--embedded-native-host",
                str(native_host),
                "--windows-authenticode-signed",
            )
            with zipfile.ZipFile(
                signed_output / f"{stem}.zip",
            ) as archive:
                metadata = json.loads(
                    archive.read(f"{stem}/RELEASE-METADATA.json")
                )
                readme = archive.read(f"{stem}/README.md").decode()
                self.assertEqual(
                    metadata["setup"]["codeSigningStatus"],
                    "authenticodeSigned",
                )
                self.assertEqual(
                    metadata["setup"]["timestampStatus"],
                    "rfc3161Sha256",
                )
                self.assertIn("RFC 3161 SHA-256 timestamp", readme)
                self.assertNotIn("SmartScreen may warn", readme)

    def test_macos_setup_is_an_unsigned_system_framework_app(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            native_bytes = fake_native_binary("macos", "arm64")
            native_host = base / "hns-chromium-native-host"
            native_host.write_bytes(native_bytes)
            setup = base / "hns-dane-browser-setup"
            setup.write_bytes(fake_setup_binary("macos", "arm64", native_bytes))
            output = base / "output"
            self.run_packager(
                "setup",
                *self.common_arguments(output),
                "--platform",
                "macos",
                "--architecture",
                "arm64",
                "--native-rust-target",
                "aarch64-apple-darwin",
                "--setup-rust-target",
                "aarch64-apple-darwin",
                "--setup-executable",
                str(setup),
                "--embedded-native-host",
                str(native_host),
            )
            stem = f"hns-dane-browser-setup-v{self.version}-macos-arm64"
            app = f"{stem}/HNS DANE Browser Setup.app/Contents"
            with tarfile.open(output / f"{stem}.tar.gz", "r:gz") as archive:
                names = archive.getnames()
                self.assertIn(f"{app}/Info.plist", names)
                self.assertIn(
                    f"{app}/MacOS/hns-dane-browser-setup",
                    names,
                )
                self.assertIn(f"{app}/Resources/LICENSE", names)
                self.assertIn(
                    f"{app}/Resources/THIRD_PARTY_NOTICES.txt",
                    names,
                )
                plist = archive.extractfile(f"{app}/Info.plist").read().decode()
                self.assertIn(
                    "com.denuoweb.hns-dane-browser.setup",
                    plist,
                )
                self.assertIn("LSMinimumSystemVersion", plist)
                self.assertIn("<string>11.0</string>", plist)
                metadata = json.loads(
                    archive.extractfile(
                        f"{stem}/RELEASE-METADATA.json"
                    ).read()
                )
                self.assertEqual(
                    metadata["setup"]["runtimeDependencies"],
                    "systemFrameworksOnly",
                )
                self.assertEqual(
                    metadata["setup"]["notarizationStatus"],
                    "notNotarized",
                )
                self.assertEqual(
                    metadata["setup"]["minimumSystemVersion"],
                    "11.0",
                )
                readme = archive.extractfile(f"{stem}/README.md").read().decode()
                self.assertIn("Control-click the app and choose Open", readme)
                self.assertIn("System Settings > Privacy & Security", readme)
                self.assertIn("Do not disable Gatekeeper globally", readme)
                self.assertNotIn("Bundled Linux runtime licenses", readme)

            signed_output = base / "signed-output"
            self.run_packager(
                "setup",
                *self.common_arguments(signed_output),
                "--platform",
                "macos",
                "--architecture",
                "arm64",
                "--native-rust-target",
                "aarch64-apple-darwin",
                "--setup-rust-target",
                "aarch64-apple-darwin",
                "--setup-executable",
                str(setup),
                "--embedded-native-host",
                str(native_host),
                "--macos-signed-notarized",
            )
            with tarfile.open(
                signed_output / f"{stem}.tar.gz",
                "r:gz",
            ) as archive:
                metadata = json.loads(
                    archive.extractfile(
                        f"{stem}/RELEASE-METADATA.json"
                    ).read()
                )
                self.assertEqual(
                    metadata["setup"]["codeSigningStatus"],
                    "developerIdSigned",
                )
                self.assertEqual(
                    metadata["setup"]["notarizationStatus"],
                    "acceptedAndStapled",
                )
                readme = archive.extractfile(f"{stem}/README.md").read().decode()
                self.assertIn("carries a stapled ticket", readme)
                self.assertNotIn("Control-click", readme)
                self.assertNotIn("Do not disable Gatekeeper", readme)

    def test_signed_notarized_state_is_rejected_for_non_macos_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "hns-chromium-native-host"
            binary.write_bytes(fake_native_binary("linux", "x64"))
            result = subprocess.run(
                [
                    "python3",
                    str(PACKAGER),
                    "native",
                    *self.common_arguments(base / "output"),
                    "--platform",
                    "linux",
                    "--architecture",
                    "x64",
                    "--rust-target",
                    "x86_64-unknown-linux-musl",
                    "--native-host",
                    str(binary),
                    "--macos-signed-notarized",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "--macos-signed-notarized is valid only for macOS",
                result.stderr,
            )

    def test_setup_rejects_a_non_embedded_or_mislabeled_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            native_host = base / "hns-chromium-native-host.exe"
            native_host.write_bytes(fake_native_binary("windows", "arm64"))
            setup = base / "hns-dane-browser-setup.exe"
            setup.write_bytes(fake_native_binary("windows", "x64"))
            result = subprocess.run(
                [
                    "python3",
                    str(PACKAGER),
                    "setup",
                    *self.common_arguments(base / "output"),
                    "--platform",
                    "windows",
                    "--architecture",
                    "x64",
                    "--native-rust-target",
                    "x86_64-pc-windows-msvc",
                    "--setup-rust-target",
                    "x86_64-pc-windows-msvc",
                    "--setup-executable",
                    str(setup),
                    "--embedded-native-host",
                    str(native_host),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "embedded native host architecture does not match windows-x64",
                result.stderr,
            )
            native_host.write_bytes(fake_native_binary("windows", "x64"))
            native_bytes = bytearray(native_host.read_bytes())
            native_bytes[-1] = 1
            native_host.write_bytes(native_bytes)
            result = subprocess.run(
                [
                    "python3",
                    str(PACKAGER),
                    "setup",
                    *self.common_arguments(base / "second-output"),
                    "--platform",
                    "windows",
                    "--architecture",
                    "x64",
                    "--native-rust-target",
                    "x86_64-pc-windows-msvc",
                    "--setup-rust-target",
                    "x86_64-pc-windows-msvc",
                    "--setup-executable",
                    str(setup),
                    "--embedded-native-host",
                    str(native_host),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "does not contain the exact native host payload",
                result.stderr,
            )

    def test_rejects_a_binary_whose_format_or_architecture_is_mislabeled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "hns-chromium-native-host"
            binary.write_bytes(fake_native_binary("linux", "x64"))
            binary.chmod(0o755)
            result = subprocess.run(
                [
                    "python3",
                    str(PACKAGER),
                    "native",
                    *self.common_arguments(base / "output"),
                    "--platform",
                    "linux",
                    "--architecture",
                    "arm64",
                    "--rust-target",
                    "aarch64-unknown-linux-musl",
                    "--native-host",
                    str(binary),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("architecture does not match linux-arm64", result.stderr)

    def test_rejects_placeholder_or_mismatched_extension_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            result = subprocess.run(
                [
                    "python3",
                    str(PACKAGER),
                    "extension",
                    "--output-dir",
                    str(output),
                    "--source-date-epoch",
                    EPOCH,
                    "--source-commit",
                    COMMIT,
                    "--source-tag",
                    self.tag,
                    "--extension-id",
                    "replace-with-store-id",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("extension ID must contain exactly 32", result.stderr)

    def assert_checksum(self, archive: Path) -> None:
        checksum = archive.with_name(f"{archive.name}.sha256")
        expected = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual(
            checksum.read_text(encoding="ascii"),
            f"{expected}  {archive.name}\n",
        )


if __name__ == "__main__":
    unittest.main()
