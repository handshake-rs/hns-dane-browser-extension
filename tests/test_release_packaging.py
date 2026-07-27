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
