from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from create_browser_qualification_provenance import (  # noqa: E402
    ProvenanceError,
    REQUIRED_ROLES,
    build_provenance,
)


COMMIT = "a" * 40
RUST_TARGET = "aarch64-unknown-linux-musl"


class BrowserQualificationProvenanceTests(unittest.TestCase):
    def fixture(self, root: Path) -> argparse.Namespace:
        host = root / "hns-chromium-native-host"
        host.write_bytes(b"exact native host")

        native_archive = root / "native.tar.gz"
        prefix = "hns-dane-browser-native-host-v0.5.6-linux-arm64"
        native_metadata = json.dumps(
            {
                "source": {"commit": COMMIT},
                "nativeHost": {"rustTarget": RUST_TARGET},
            }
        ).encode()
        with tarfile.open(native_archive, "w:gz") as archive:
            for name, data in {
                f"{prefix}/rust/target/release/hns-chromium-native-host": host.read_bytes(),
                f"{prefix}/RELEASE-METADATA.json": native_metadata,
            }.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

        extension = root / "extension.zip"
        with zipfile.ZipFile(extension, "w") as archive:
            archive.writestr("manifest.json", json.dumps({"key": "public-only"}))
            archive.writestr(
                "RELEASE-METADATA.json",
                json.dumps(
                    {
                        "source": {"commit": COMMIT},
                        "extensionPackageVariant": "canonicalUnpacked",
                    }
                ),
            )

        def checksum(path: Path) -> Path:
            sidecar = path.with_name(path.name + ".sha256")
            sidecar.write_text(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n",
                encoding="ascii",
            )
            return sidecar

        assignments = {
            "nativeHostExecutable": host,
            "nativeHostArchive": native_archive,
            "nativeHostArchiveChecksum": checksum(native_archive),
            "canonicalExtension": extension,
            "canonicalExtensionChecksum": checksum(extension),
        }
        self.assertEqual(set(assignments), set(REQUIRED_ROLES))
        return argparse.Namespace(
            source_commit=COMMIT,
            platform="linux",
            architecture="arm64",
            rust_target=RUST_TARGET,
            runner_image="ubuntu-24.04-arm",
            file=[f"{role}={path}" for role, path in assignments.items()],
        )

    def test_describes_exact_files_and_closed_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = self.fixture(Path(directory))
            provenance = build_provenance(arguments)
        self.assertEqual(provenance["source"]["commit"], COMMIT)
        self.assertEqual(
            [entry["role"] for entry in provenance["files"]],
            list(REQUIRED_ROLES),
        )
        self.assertEqual(provenance["qualification"]["status"], "pendingInstalledBrowserRun")
        self.assertTrue(provenance["qualification"]["requiresIsolatedProfile"])
        self.assertTrue(all(value is False for value in provenance["securityBoundary"].values()))

    def test_rejects_native_archive_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = self.fixture(root)
            (root / "hns-chromium-native-host").write_bytes(b"substituted")
            with self.assertRaisesRegex(ProvenanceError, "exact staged native host"):
                build_provenance(arguments)

    def test_rejects_private_key_material_inside_extension(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = self.fixture(root)
            extension = root / "extension.zip"
            with zipfile.ZipFile(extension, "a") as archive:
                archive.writestr(
                    "stolen.txt", "-----" + "BEGIN " + "PRIVATE KEY-----"
                )
            checksum = root / "extension.zip.sha256"
            checksum.write_text(
                f"{hashlib.sha256(extension.read_bytes()).hexdigest()}  extension.zip\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(ProvenanceError, "private-key material"):
                build_provenance(arguments)


class BrowserQualificationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def test_exact_sha_arm64_artifact_is_required(self) -> None:
        self.assertIn("qualification:\n    name: Installed-browser qualification artifact", self.workflow)
        self.assertIn("runs-on: ubuntu-24.04-arm", self.workflow)
        self.assertIn(
            "name: installed-browser-qualification-${{ github.sha }}-linux-arm64",
            self.workflow,
        )
        self.assertIn("needs: [policy, rust, extension, qualification]", self.workflow)

    def test_artifact_build_has_no_credentials_or_product_gate_enables(self) -> None:
        qualification = self.workflow.split("\n  qualification:\n", 1)[1].split(
            "\n  required:\n", 1
        )[0]
        self.assertIn("persist-credentials: false", qualification)
        self.assertIn("scripts/check-runtime-boundaries.sh", qualification)
        self.assertIn("create_browser_qualification_provenance.py", qualification)
        self.assertNotIn("secrets.", qualification)
        self.assertNotRegex(
            qualification,
            r"(?i)(?:hnsa|hnsr|wallet|provider|value|marketplace)[_-]?(?:enabled|available)\s*[:=]\s*true",
        )


if __name__ == "__main__":
    unittest.main()
