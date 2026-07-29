from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/resign-macos-release.yml"
BUILD_SCRIPT = ROOT / "scripts/build-signed-macos-release.sh"
REPLACE_SCRIPT = ROOT / "scripts/replace-macos-release-assets.sh"


class ResignMacosWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
        cls.replace_script = REPLACE_SCRIPT.read_text(encoding="utf-8")
        cls.combined = "\n".join(
            (cls.workflow, cls.build_script, cls.replace_script)
        )

    def test_workflow_is_manual_version_preserving_and_repository_scoped(
        self,
    ) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("push:", self.workflow)
        self.assertIn("default: v0.5.4", self.workflow)
        self.assertIn("confirm_replacement:", self.workflow)
        self.assertIn(
            "GH_REPO\" != handshake-rs/hns-dane-browser-extension",
            self.workflow,
        )
        self.assertIn(
            'GITHUB_REF" != "refs/heads/$DEFAULT_BRANCH',
            self.workflow,
        )
        self.assertIn(
            'RELEASE_TAG" != "v$version"',
            self.workflow,
        )
        self.assertIn(
            'tooling_version" != "$version"',
            self.workflow,
        )
        self.assertNotRegex(self.workflow, r"\b(?:ios|android)\b")

    def test_only_pinned_first_party_actions_are_used(self) -> None:
        references = re.findall(
            r"^\s*uses:\s*([^#\s]+)",
            self.workflow,
            re.MULTILINE,
        )
        self.assertTrue(references)
        for reference in references:
            self.assertRegex(
                reference,
                r"^actions/(?:checkout|setup-node|upload-artifact|download-artifact)"
                r"@[0-9a-f]{40}$",
            )

    def test_signing_secrets_are_environment_scoped_and_validated(self) -> None:
        self.assertIn("environment: macos-signing", self.workflow)
        self.assertIn("environment: release", self.workflow)
        self.assertEqual(self.workflow.count("contents: write"), 1)
        for name in (
            "APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64",
            "APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD",
            "APPLE_NOTARY_API_PRIVATE_KEY_P8_BASE64",
        ):
            self.assertIn(f"secrets.{name}", self.workflow)
        for name in (
            "APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_NAME",
            "APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_SHA256",
            "APPLE_NOTARY_API_ISSUER_ID",
            "APPLE_NOTARY_API_KEY_ID",
            "APPLE_TEAM_ID",
        ):
            self.assertIn(f"vars.{name}", self.workflow)
        self.assertIn("security create-keychain", self.build_script)
        self.assertIn("security delete-keychain", self.build_script)
        self.assertIn("security list-keychains -d user -s", self.build_script)
        self.assertIn("security default-keychain -d user -s", self.build_script)
        self.assertIn("-passin env:APPLE_CERTIFICATE_P12_PASSWORD", self.build_script)
        self.assertIn("-legacy", self.build_script)
        self.assertIn("-passout env:HNS_PKCS12_IMPORT_PASSWORD", self.build_script)
        self.assertIn('security import "$compatible_p12"', self.build_script)
        self.assertIn("certificate_fingerprint", self.build_script)
        self.assertIn("signing_identity", self.build_script)
        self.assertIn("certificate_sha1", self.build_script)
        self.assertIn("APPLE_TEAM_ID", self.build_script)
        self.assertNotIn("set -x", self.combined)

    def test_matrix_builds_and_verifies_both_macos_architectures(self) -> None:
        expected = {
            (
                "x64",
                "macos-15-intel",
                "x86_64-apple-darwin",
                "x86_64-apple-darwin",
            ),
            (
                "arm64",
                "macos-15",
                "aarch64-apple-darwin",
                "aarch64-apple-darwin",
            ),
        }
        rows = set(
            re.findall(
                r"- architecture: (\w+)\n"
                r"\s+runner: ([\w.-]+)\n"
                r"\s+native-rust-target: ([\w.-]+)\n"
                r"\s+setup-rust-target: ([\w.-]+)",
                self.workflow,
            )
        )
        self.assertEqual(rows, expected)
        self.assertIn("-p hns-chromium-native-host", self.build_script)
        self.assertIn("-p hns-browser-setup", self.build_script)
        self.assertIn("--features embedded-host", self.build_script)
        self.assertIn("HNS_NATIVE_HOST_PATH=", self.build_script)
        self.assertIn("--macos-signed-notarized", self.build_script)
        self.assertEqual(
            self.workflow.count('macos-deployment-target: "11.0"'),
            2,
        )
        self.assertIn(
            "MACOSX_DEPLOYMENT_TARGET: "
            "${{ matrix.macos-deployment-target }}",
            self.workflow,
        )
        self.assertIn(
            "scripts/verify-macos-binaries.sh",
            self.build_script,
        )
        self.assertIn("--gui-smoke-test", self.build_script)
        self.assertIn("smoke_pid=", self.build_script)

    def test_hardened_signing_notarization_and_stapling_are_required(self) -> None:
        self.assertGreaterEqual(self.build_script.count("--options runtime"), 2)
        self.assertGreaterEqual(self.build_script.count("--timestamp"), 2)
        self.assertIn("xcrun notarytool submit", self.build_script)
        self.assertNotIn("--wait", self.build_script)
        self.assertIn("xcrun notarytool info", self.build_script)
        self.assertIn('notary_poll_seconds=120', self.build_script)
        self.assertIn('notary_wait_timeout_seconds=19800', self.build_script)
        self.assertIn('"In Progress"', self.build_script)
        self.assertIn("Invalid | Rejected", self.build_script)
        self.assertLess(
            self.build_script.index(
                'submit_for_notarization \\\n  "$setup_upload"'
            ),
            self.build_script.index(
                'wait_for_notary_acceptance \\\n  "$native_upload"'
            ),
        )
        self.assertIn("if: ${{ failure() }}", self.workflow)
        self.assertIn("failed-macos-notary-evidence-", self.workflow)
        self.assertIn("xcrun stapler staple", self.build_script)
        self.assertGreaterEqual(
            self.build_script.count("xcrun stapler validate"),
            2,
        )
        self.assertGreaterEqual(
            self.build_script.count("codesign --verify"),
            4,
        )
        self.assertGreaterEqual(self.build_script.count("spctl --assess"), 2)
        self.assertIn("acceptedOnlineTicket", self.build_script)
        self.assertIn("acceptedAndStapled", self.build_script)

    def test_publisher_backs_up_then_replaces_only_nine_assets(self) -> None:
        self.assertIn("release-before-macos-signing.json", self.replace_script)
        self.assertIn('assets | length\' "$release_json")" != 29', self.replace_script)
        self.assertIn("gh release download", self.replace_script)
        self.assertIn("sha256sum --check SHA256SUMS", self.replace_script)
        self.assertIn("pending_suffix=", self.replace_script)
        upload = self.replace_script.index("gh release upload")
        delete = self.replace_script.index("--method DELETE")
        rename = self.replace_script.index("--method PATCH", delete)
        self.assertLess(upload, delete)
        self.assertLess(delete, rename)
        self.assertIn('replacement_assets+=("SHA256SUMS")', self.replace_script)
        self.assertIn("Final published release asset names are not exact", self.replace_script)
        self.assertIn("Final published asset $asset does not match locally", self.replace_script)
        self.assertIn("release-after-macos-signing.json", self.replace_script)
        self.assertIn(
            "Automated\\nmacOS binaries are unsigned and not notarized",
            self.replace_script,
        )


if __name__ == "__main__":
    unittest.main()
