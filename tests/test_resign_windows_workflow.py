from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/resign-windows-release.yml"
VERIFY_SCRIPT = ROOT / "scripts/verify-windows-binaries.ps1"
SIGN_SCRIPT = ROOT / "scripts/sign-self-signed-windows.ps1"
REPLACE_SCRIPT = ROOT / "scripts/replace-windows-release-assets.sh"


class ResignWindowsWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.verify_script = VERIFY_SCRIPT.read_text(encoding="utf-8")
        cls.sign_script = SIGN_SCRIPT.read_text(encoding="utf-8")
        cls.replace_script = REPLACE_SCRIPT.read_text(encoding="utf-8")
        cls.combined = "\n".join(
            (
                cls.workflow,
                cls.sign_script,
                cls.verify_script,
                cls.replace_script,
            )
        )

    def test_workflow_is_manual_version_preserving_and_repository_scoped(
        self,
    ) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("\n  push:", self.workflow)
        self.assertIn("default: v0.6.1", self.workflow)
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

    def test_actions_are_commit_pinned_and_signing_secrets_are_environment_scoped(
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
                r"^actions/[-A-Za-z0-9_.]+@[0-9a-f]{40}$",
            )
        self.assertIn("environment: windows-signing", self.workflow)
        self.assertIn("environment: release", self.workflow)
        self.assertNotIn("id-token: write", self.workflow)
        self.assertNotIn("azure/", self.workflow)
        self.assertNotIn("AZURE_", self.workflow)
        self.assertIn(
            "secrets.WINDOWS_SELF_SIGNED_PFX_BASE64",
            self.workflow,
        )
        self.assertIn(
            "secrets.WINDOWS_SELF_SIGNED_PFX_PASSWORD",
            self.workflow,
        )
        self.assertIn("vars.WINDOWS_AUTHENTICODE_PUBLISHER", self.workflow)
        self.assertIn(
            "vars.WINDOWS_SELF_SIGNED_CERTIFICATE_SHA256",
            self.workflow,
        )
        self.assertEqual(self.workflow.count("contents: write"), 1)

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
            "Self-sign and RFC 3161 timestamp the native host"
        )
        setup_build = self.workflow.index(
            "Verify the native host and build the embedded setup"
        )
        setup_sign = self.workflow.index(
            "Self-sign and RFC 3161 timestamp Setup"
        )
        self.assertLess(native_sign, setup_build)
        self.assertLess(setup_build, setup_sign)
        self.assertEqual(
            self.workflow.count("scripts/sign-self-signed-windows.ps1"),
            2,
        )
        self.assertGreaterEqual(self.workflow.count("-AllowSelfSigned"), 2)
        self.assertGreaterEqual(
            self.workflow.count(
                "source/release/windows-self-signed-code-signing.cer"
            ),
            4,
        )
        self.assertNotIn(
            "--windows-self-signed-authenticode",
            self.workflow,
        )
        self.assertEqual(self.workflow.count("-EvidenceOutput"), 2)
        self.assertEqual(
            self.workflow.count("--windows-signing-evidence"),
            2,
        )
        self.assertIn("-Path @($nativeHost)", self.workflow)
        self.assertIn("-EvidenceOutput $nativeEvidence", self.workflow)
        self.assertIn("-Path @($setup)", self.workflow)
        self.assertIn("-EvidenceOutput $setupEvidence", self.workflow)
        self.assertIn(
            "--windows-signing-evidence $nativeEvidence",
            self.workflow,
        )
        self.assertIn(
            "--windows-signing-evidence $setupEvidence",
            self.workflow,
        )
        self.assertIn("HNS_EXTENSION_IDS", self.workflow)
        self.assertIn("HNS_HEADER_SNAPSHOT_PATH", self.workflow)

    def test_imports_signer_and_timestamp_are_verified(self) -> None:
        self.assertIn("/dependents", self.verify_script)
        self.assertIn("allowedSystemImports", self.verify_script)
        self.assertIn("non-allowlisted DLL", self.verify_script)
        self.assertIn("dynamic Microsoft CRT", self.verify_script)
        self.assertIn("Get-AuthenticodeSignature", self.verify_script)
        self.assertIn("TimeStamperCertificate", self.verify_script)
        self.assertIn("SignerCertificate.Subject", self.verify_script)
        self.assertIn("signtool verify /pa /all /v /tw", self.verify_script)
        self.assertIn("SignatureType.ToString() -ne 'Authenticode'", self.verify_script)
        self.assertIn("ExpectedCertificateSha256", self.verify_script)
        self.assertIn("SelfSignedCertificate", self.verify_script)
        self.assertIn("Test-ByteArraysEqual", self.verify_script)
        self.assertIn("SignerCertificate.RawData", self.verify_script)
        self.assertIn("1.3.6.1.5.5.7.3.3", self.verify_script)
        self.assertIn("1.3.6.1.5.5.7.3.8", self.verify_script)
        self.assertIn("KeySize -lt 3072", self.verify_script)
        self.assertIn("Certificate.Issuer -ne $ExpectedPublisher", self.verify_script)
        self.assertIn(
            "CertResyncCertificateChainEngine",
            self.verify_script,
        )
        self.assertGreaterEqual(
            self.verify_script.count(
                "Sync-CurrentUserCertificateChainEngine"
            ),
            3,
        )
        trust = self.verify_script.index("$selfSignedRootStore.Add")
        trust_resync = self.verify_script.index(
            "Sync-CurrentUserCertificateChainEngine",
            trust,
        )
        trusted_verify = self.verify_script.index("signtool verify /pa /all /v /tw")
        remove = self.verify_script.index("$selfSignedRootStore.Remove")
        removal_resync = self.verify_script.index(
            "Sync-CurrentUserCertificateChainEngine",
            remove,
        )
        untrusted_verify = self.verify_script.index(
            "$untrustedSignature = Get-AuthenticodeSignature"
        )
        self.assertLess(trust, trust_resync)
        self.assertLess(trust_resync, trusted_verify)
        self.assertLess(trust, trusted_verify)
        self.assertLess(trusted_verify, remove)
        self.assertLess(remove, removal_resync)
        self.assertLess(removal_resync, untrusted_verify)
        self.assertLess(remove, untrusted_verify)
        self.assertIn("acceptableUntrustedStatuses", self.verify_script)
        self.assertIn("[string]$EvidenceOutput", self.verify_script)
        self.assertIn("schemaVersion = 1", self.verify_script)
        self.assertIn("files = @($signingEvidenceFiles)", self.verify_script)
        self.assertIn("WINDOWS_SELF_SIGNED_PFX_BASE64", self.sign_script)
        self.assertIn("WINDOWS_SELF_SIGNED_PFX_PASSWORD", self.sign_script)
        self.assertIn("Test-ByteArraysEqual", self.sign_script)
        self.assertIn("$certificate.RawData", self.sign_script)
        self.assertIn("SignatureType.ToString() -ne 'Authenticode'", self.sign_script)
        self.assertIn("TimeStamperCertificate", self.sign_script)
        self.assertIn("KeySize -lt 3072", self.sign_script)
        self.assertIn("1.3.6.1.5.5.7.3.3", self.sign_script)
        self.assertIn("$Certificate.Issuer -ne $expectedPublisher", self.sign_script)
        self.assertIn(
            "$pfxCertificates.Count -ne 1",
            self.sign_script,
        )
        self.assertGreaterEqual(
            self.sign_script.count(
                "Get-AuthenticodeSignature -LiteralPath"
            ),
            2,
        )
        self.assertIn(
            "$certificateImportedByThisRun -and",
            self.sign_script,
        )
        self.assertIn(
            "private key was not removed from CurrentUser\\My",
            self.sign_script,
        )
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
        self.assertIn("selfSignedAuthenticode", self.replace_script)
        self.assertIn("notPubliclyTrusted", self.replace_script)
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
