from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/resign-windows-release.yml"
VERIFY_SCRIPT = ROOT / "scripts/verify-windows-binaries.ps1"
REPLACE_SCRIPT = ROOT / "scripts/replace-windows-release-assets.sh"


class ResignWindowsWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.verify_script = VERIFY_SCRIPT.read_text(encoding="utf-8")
        cls.replace_script = REPLACE_SCRIPT.read_text(encoding="utf-8")
        cls.combined = "\n".join(
            (cls.workflow, cls.verify_script, cls.replace_script)
        )

    def test_workflow_is_manual_version_preserving_and_repository_scoped(
        self,
    ) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("\n  push:", self.workflow)
        self.assertIn("default: v0.5.6", self.workflow)
        self.assertIn("confirm_replacement:", self.workflow)
        self.assertIn(
            "GH_REPO\" != handshake-rs/hns-dane-browser-extension",
            self.workflow,
        )
        self.assertIn(
            'GITHUB_REF" != "refs/heads/$DEFAULT_BRANCH',
            self.workflow,
        )
        self.assertIn('RELEASE_TAG" != "v$version"', self.workflow)
        self.assertIn('tooling_version" != "$version"', self.workflow)

    def test_actions_are_commit_pinned_and_oidc_is_environment_scoped(
        self,
    ) -> None:
        references = re.findall(
            r"^\s*uses:\s*([^#\s]+)",
            self.workflow,
            re.MULTILINE,
        )
        self.assertTrue(references)
        for reference in references:
            self.assertRegex(
                reference,
                r"^(?:actions|azure)/[-A-Za-z0-9_.]+@[0-9a-f]{40}$",
            )
        self.assertIn("environment: windows-signing", self.workflow)
        self.assertIn("environment: release", self.workflow)
        self.assertIn("id-token: write", self.workflow)
        self.assertEqual(self.workflow.count("contents: write"), 1)
        self.assertNotRegex(
            self.combined,
            r"(?i)(pfx|private[_ -]?key|client[_ -]?secret)",
        )

    def test_both_architectures_build_with_static_crt_and_sign_in_order(
        self,
    ) -> None:
        rows = set(
            re.findall(
                r"- architecture: (\w+)\n"
                r"\s+rust-target: ([\w.-]+)",
                self.workflow,
            )
        )
        self.assertEqual(
            rows,
            {
                ("x64", "x86_64-pc-windows-msvc"),
                ("arm64", "aarch64-pc-windows-msvc"),
            },
        )
        self.assertIn("runs-on: windows-2025", self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("target-feature=+crt-static"),
            2,
        )
        native_sign = self.workflow.index(
            "Authenticode sign and timestamp the native host"
        )
        setup_build = self.workflow.index(
            "Verify the native host and build the embedded setup"
        )
        setup_sign = self.workflow.index(
            "Authenticode sign and timestamp the setup"
        )
        self.assertLess(native_sign, setup_build)
        self.assertLess(setup_build, setup_sign)
        self.assertGreaterEqual(
            self.workflow.count("azure/artifact-signing-action@"),
            2,
        )
        self.assertGreaterEqual(
            self.workflow.count("timestamp-rfc3161:"),
            2,
        )
        self.assertIn("--windows-authenticode-signed", self.workflow)

    def test_imports_signer_and_timestamp_are_verified(self) -> None:
        self.assertIn("/dependents", self.verify_script)
        self.assertIn("allowedSystemImports", self.verify_script)
        self.assertIn("non-allowlisted DLL", self.verify_script)
        self.assertIn("dynamic Microsoft CRT", self.verify_script)
        self.assertIn("Get-AuthenticodeSignature", self.verify_script)
        self.assertIn("TimeStamperCertificate", self.verify_script)
        self.assertIn("SignerCertificate.Subject", self.verify_script)
        self.assertIn("signtool verify /pa /all /v /tw", self.verify_script)
        self.assertIn("WINDOWS_AUTHENTICODE_PUBLISHER", self.workflow)
        self.assertIn("--gui-smoke-test", self.workflow)
        self.assertIn("WaitForExit(30000)", self.workflow)

    def test_publisher_transactionally_replaces_only_windows_assets(self) -> None:
        self.assertIn(
            "release-before-windows-signing.json",
            self.replace_script,
        )
        self.assertIn(
            'assets | length\' "$release_json")" != 29',
            self.replace_script,
        )
        self.assertIn("pending_suffix=", self.replace_script)
        upload = self.replace_script.index("gh release upload")
        delete = self.replace_script.index("--method DELETE")
        rename = self.replace_script.index("--method PATCH", delete)
        self.assertLess(upload, delete)
        self.assertLess(delete, rename)
        self.assertIn(
            'replacement_assets+=("SHA256SUMS")',
            self.replace_script,
        )
        self.assertIn("authenticodeSigned", self.replace_script)
        self.assertIn("rfc3161Sha256", self.replace_script)
        self.assertIn(
            "release-after-windows-signing.json",
            self.replace_script,
        )
        self.assertIn(
            "Automated Windows bundles are unsigned.",
            self.replace_script,
        )


if __name__ == "__main__":
    unittest.main()
