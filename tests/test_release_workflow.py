from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/release.yml"
WINDOWS_VERIFY = ROOT / "scripts/verify-windows-binaries.ps1"
WINDOWS_SIGN = ROOT / "scripts/sign-self-signed-windows.ps1"
MACOS_VERIFY = ROOT / "scripts/verify-macos-binaries.sh"
CANONICAL_ID = json.loads(
    (ROOT / "release/extension-identity.json").read_text(encoding="utf-8")
)["canonicalId"]


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.windows_verify = WINDOWS_VERIFY.read_text(encoding="utf-8")
        cls.windows_sign = WINDOWS_SIGN.read_text(encoding="utf-8")
        cls.macos_verify = MACOS_VERIFY.read_text(encoding="utf-8")

    def test_external_actions_are_pinned_and_allowlisted(self) -> None:
        references = re.findall(r"^\s*uses:\s*([^#\s]+)", self.source, re.MULTILINE)
        self.assertTrue(references)
        for reference in references:
            self.assertRegex(
                reference,
                r"^actions/(?:checkout|setup-node|upload-artifact|download-artifact|"
                r"attest-build-provenance)"
                r"@[0-9a-f]{40}$",
            )
        self.assertNotRegex(self.source, r"uses:\s*softprops/")

    def test_matrix_covers_current_standard_runner_architectures(self) -> None:
        expected = {
            (
                "linux",
                "x64",
                "ubuntu-24.04",
                "x86_64-unknown-linux-musl",
                "x86_64-unknown-linux-gnu",
            ),
            (
                "linux",
                "arm64",
                "ubuntu-24.04-arm",
                "aarch64-unknown-linux-musl",
                "aarch64-unknown-linux-gnu",
            ),
        }
        rows = set(
            re.findall(
                r"- platform: (\w+)\n"
                r"\s+architecture: (\w+)\n"
                r"\s+runner: ([\w.-]+)\n"
                r"\s+native-rust-target: ([\w.-]+)\n"
                r"\s+setup-rust-target: ([\w.-]+)",
                self.source,
            )
        )
        self.assertEqual(rows, expected)

    def test_release_is_draft_until_all_builds_and_checks_succeed(self) -> None:
        self.assertIn('tags:\n      - "v*"', self.source)
        self.assertIn('gh release create "$RELEASE_TAG" \\\n              --draft', self.source)
        self.assertIn(
            "needs: [prepare, quality, extension, native, signed_macos, signed_windows]",
            self.source,
        )
        self.assertIn("resolve_release_json", self.source)
        self.assertIn(
            '"repos/${GH_REPO}/releases/${release_id}"',
            self.source,
        )
        self.assertIn("-F draft=false", self.source)
        self.assertIn("QUALITY_RESULT: ${{ needs.quality.result }}", self.source)
        self.assertIn("EXTENSION_RESULT: ${{ needs.extension.result }}", self.source)
        self.assertIn("NATIVE_RESULT: ${{ needs.native.result }}", self.source)
        self.assertIn(
            "SIGNED_MACOS_RESULT: ${{ needs.signed_macos.result }}",
            self.source,
        )
        self.assertIn(
            "SIGNED_WINDOWS_RESULT: ${{ needs.signed_windows.result }}",
            self.source,
        )
        self.assertIn("environment: release", self.source)
        self.assertNotIn("--latest", self.source)

    def test_build_jobs_are_read_only_and_publisher_checks_exact_assets(self) -> None:
        self.assertEqual(self.source.count("contents: write"), 1)
        self.assertIn("actions/upload-artifact@", self.source)
        self.assertIn("actions/download-artifact@", self.source)
        self.assertIn("GH_REPO: ${{ github.repository }}", self.source)
        self.assertIn("sha256sum --check", self.source)
        self.assertIn("verify_exact_remote_assets", self.source)
        self.assertIn(
            'hns-dane-browser-extension-v${VERSION}-mv3-store.zip',
            self.source,
        )
        self.assertIn(
            "Release assets do not exactly match the expected archive, sidecar, "
            "and aggregate-checksum set.",
            self.source,
        )
        archive_block = re.search(
            r"archives=\(\n(?P<archives>.*?)\n\s+\)\n\s+build_assets=",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(archive_block)
        archives = re.findall(
            r'"(hns-dane-browser-[^"]+\.(?:zip|tar\.gz))"',
            archive_block.group("archives"),
        )
        self.assertEqual(len(archives), 14)
        self.assertEqual(len(set(archives)), 14)
        self.assertEqual(
            len([name for name in archives if "browser-setup-" in name]),
            6,
        )
        self.assertIn(
            'release_assets=("${build_assets[@]}" "SHA256SUMS")',
            self.source,
        )

    def test_remote_assets_match_local_names_sizes_and_digests_before_publish(
        self,
    ) -> None:
        self.assertIn(
            '"repos/${GH_REPO}/releases/${release_id}/assets?per_page=100"',
            self.source,
        )
        self.assertNotIn(
            '"repos/${GH_REPO}/releases/tags/${RELEASE_TAG}"',
            self.source,
        )
        self.assertIn(
            ".[] | [.name, .size, (.digest // \"\")] | @tsv",
            self.source,
        )
        self.assertIn('local_size="$(stat --format=%s "$local_path")"', self.source)
        self.assertIn(
            'local_digest="sha256:$(sha256sum "$local_path" | cut -d \' \' -f 1)"',
            self.source,
        )
        final_verify = self.source.rfind("verify_exact_remote_assets")
        publish = self.source.rfind("-F draft=false")
        self.assertGreater(final_verify, 0)
        self.assertGreater(publish, final_verify)

    def test_draft_releases_are_resolved_from_authenticated_release_lists(
        self,
    ) -> None:
        self.assertGreaterEqual(
            self.source.count("releases?per_page=100"),
            2,
        )
        self.assertIn(
            "'[.[][] | select(.tag_name == $tag)]'",
            self.source,
        )
        self.assertIn(
            "Existing release source does not match the current tag commit.",
            self.source,
        )

    def test_linux_release_is_static_musl_with_runtime_smoke_check(self) -> None:
        self.assertIn(
            "sudo apt-get install --no-install-recommends --yes \\",
            self.source,
        )
        self.assertIn("musl-tools", self.source)
        self.assertIn("readelf --program-headers", self.source)
        self.assertIn("readelf --dynamic", self.source)
        self.assertIn('ldd "$setup"', self.source)
        self.assertIn("--print-host-manifest", self.source)
        self.assertIn("scripts/package-release.py linux-runtime", self.source)
        self.assertIn("libnss3-tools", self.source)
        self.assertIn("libwayland-client0", self.source)
        self.assertIn("libx11-6", self.source)
        self.assertIn("HNS-DANE-Browser-Setup.AppDir", self.source)
        self.assertIn(
            '[[ -n "$(find "$app/usr/lib" -type f -print -quit)" ]]',
            self.source,
        )
        self.assertIn(
            "must not bundle GUI shared libraries",
            self.source,
        )
        self.assertIn(
            "must not override the host GUI library path",
            self.source,
        )
        self.assertIn('"$app/usr/libexec/certutil"', self.source)
        self.assertIn('"${clean_helper[@]}" \\\n            -N', self.source)
        self.assertIn('"$app/AppRun" --status', self.source)

    def test_setup_embeds_exact_host_and_enforces_platform_runtime_policy(
        self,
    ) -> None:
        self.assertIn("$env:HNS_NATIVE_HOST_PATH", self.source)
        self.assertIn("matrix.native-rust-target", self.source)
        self.assertIn("matrix.setup-rust-target", self.source)
        self.assertIn("-p hns-browser-setup", self.source)
        self.assertIn("--features embedded-host", self.source)
        self.assertIn("--embedded-native-host", self.source)
        self.assertIn("--linux-runtime", self.source)
        self.assertIn("-C target-feature=+crt-static", self.source)
        self.assertIn("scripts/verify-windows-binaries.ps1", self.source)
        self.assertIn("/dependents", self.windows_verify)
        self.assertIn("allowedSystemImports", self.windows_verify)
        self.assertIn("'bcryptprimitives.dll'", self.windows_verify)
        self.assertIn("'combase.dll'", self.windows_verify)
        self.assertIn("'shlwapi.dll'", self.windows_verify)
        self.assertIn("'uiautomationcore.dll'", self.windows_verify)
        self.assertIn("nonAllowlistedImports", self.windows_verify)
        self.assertIn("non-allowlisted DLL", self.windows_verify)
        self.assertIn("dynamic Microsoft CRT", self.windows_verify)
        self.assertIn("scripts/verify-macos-binaries.sh", self.source)
        self.assertIn("LC_BUILD_VERSION", self.macos_verify)
        self.assertIn("/System/Library/* | /usr/lib/*", self.macos_verify)
        self.assertIn('MACOSX_DEPLOYMENT_TARGET: "11.0"', self.source)
        self.assertGreaterEqual(self.source.count("--gui-smoke-test"), 2)
        self.assertIn("WaitForExit(30000)", self.source)
        self.assertIn("smoke_pid=", self.source)
        setup_main = (
            ROOT / "rust" / "crates" / "hns-browser-setup" / "src" / "main.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("run_windows_gui_smoke", setup_main)
        self.assertIn("WindowEvent::RedrawRequested", setup_main)
        self.assertIn(".with_visible(true)", setup_main)

    def test_store_identity_and_source_metadata_are_mandatory(self) -> None:
        self.assertIn("vars.CHROMIUM_EXTENSION_ID", self.source)
        self.assertIn("vars.CHROME_EXTENSION_ID", self.source)
        self.assertIn("vars.EDGE_EXTENSION_ID", self.source)
        self.assertIn("vars.OPERA_EXTENSION_ID", self.source)
        self.assertIn(
            "jq -er '.canonicalId' release/extension-identity.json",
            self.source,
        )
        self.assertNotIn(
            CANONICAL_ID,
            self.source,
        )
        self.assertIn(
            "EXTENSION_ID: ${{ needs.prepare.outputs.extension-id }}",
            self.source,
        )
        self.assertIn('! "$extension_id" =~ ^[a-p]{32}$', self.source)
        self.assertIn('[[ "$RELEASE_TAG" != "v$version" ]]', self.source)
        self.assertIn(
            "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
            self.source,
        )
        self.assertIn(
            'default_branch_ref="refs/remotes/origin/$DEFAULT_BRANCH"',
            self.source,
        )
        self.assertIn(
            '[[ "$SOURCE_COMMIT" != "$default_branch_commit" ]]',
            self.source,
        )
        self.assertIn("--source-commit", self.source)
        self.assertIn("--source-tag", self.source)
        self.assertIn("--extension-id", self.source)
        self.assertIn("SHA256SUMS", self.source)
        self.assertIn("GitHub Sponsors: https://github.com/sponsors/denuoweb", self.source)

    def test_finalized_installers_are_signed_attested_and_bundled(self) -> None:
        self.assertIn("environment: macos-signing", self.source)
        self.assertIn("environment: windows-signing", self.source)
        self.assertNotIn("azure/", self.source)
        self.assertNotIn("AZURE_", self.source)
        self.assertEqual(
            self.source.count("scripts/sign-self-signed-windows.ps1"),
            2,
        )
        self.assertNotIn("--windows-self-signed-authenticode", self.source)
        self.assertEqual(self.source.count("-EvidenceOutput"), 2)
        self.assertEqual(self.source.count("--windows-signing-evidence"), 2)
        self.assertIn("-Path @($nativeHost)", self.source)
        self.assertIn("-EvidenceOutput $nativeEvidence", self.source)
        self.assertIn("-Path @($setup)", self.source)
        self.assertIn("-EvidenceOutput $setupEvidence", self.source)
        self.assertIn(
            "--windows-signing-evidence $nativeEvidence",
            self.source,
        )
        self.assertIn(
            "--windows-signing-evidence $setupEvidence",
            self.source,
        )
        self.assertGreaterEqual(self.source.count("-AllowSelfSigned"), 2)
        self.assertGreaterEqual(
            self.source.count("release/windows-self-signed-code-signing.cer"),
            4,
        )
        self.assertIn("secrets.WINDOWS_SELF_SIGNED_PFX_BASE64", self.source)
        self.assertIn("secrets.WINDOWS_SELF_SIGNED_PFX_PASSWORD", self.source)
        self.assertIn("vars.WINDOWS_AUTHENTICODE_PUBLISHER", self.source)
        self.assertIn(
            "vars.WINDOWS_SELF_SIGNED_CERTIFICATE_SHA256",
            self.source,
        )
        self.assertIn("scripts/build-signed-macos-release.sh", self.source)
        self.assertIn("actions/attest-build-provenance@", self.source)
        self.assertIn("gh attestation verify", self.source)
        self.assertIn("--linux-attestations-verified", self.source)
        self.assertIn("attestations: write", self.source)
        self.assertIn("id-token: write", self.source)
        self.assertIn(
            "needs: [prepare, native, signed_macos, signed_windows]",
            self.source,
        )
        self.assertIn("--setup-dir dist/platform-assets", self.source)
        self.assertIn("HNS_HEADER_SNAPSHOT_PATH", self.source)
        self.assertIn("HNS_EXTENSION_IDS", self.source)

    def test_self_signed_windows_certificate_policy_is_pinned_and_reversible(
        self,
    ) -> None:
        for script in (self.windows_sign, self.windows_verify):
            self.assertIn("Get-CertificateSha256", script)
            self.assertIn("RawData", script)
            self.assertIn("KeySize -lt 3072", script)
            self.assertIn("1.3.6.1.5.5.7.3.3", script)
            self.assertIn("DigitalSignature", script)
            self.assertIn("CertificateAuthority", script)
        self.assertIn(
            "$Certificate.Subject -ne $expectedPublisher -or\n"
            "      $Certificate.Issuer -ne $expectedPublisher",
            self.windows_sign,
        )
        self.assertIn("WINDOWS_SELF_SIGNED_PFX_BASE64", self.windows_sign)
        self.assertIn("WINDOWS_SELF_SIGNED_PFX_PASSWORD", self.windows_sign)
        self.assertIn("SignatureType.ToString() -ne 'Authenticode'", self.windows_sign)
        self.assertIn("TimeStamperCertificate", self.windows_sign)
        self.assertIn("SignatureType.ToString() -ne 'Authenticode'", self.windows_verify)
        self.assertIn("1.3.6.1.5.5.7.3.8", self.windows_verify)
        trust = self.windows_verify.index("$selfSignedRootStore.Add")
        trusted_verify = self.windows_verify.index("signtool verify /pa /all /v /tw")
        remove = self.windows_verify.index("$selfSignedRootStore.Remove")
        untrusted_verify = self.windows_verify.index(
            "$untrustedSignature = Get-AuthenticodeSignature"
        )
        self.assertLess(trust, trusted_verify)
        self.assertLess(trusted_verify, remove)
        self.assertLess(remove, untrusted_verify)
        self.assertIn("acceptableUntrustedStatuses", self.windows_verify)
        self.assertIn("[string]$EvidenceOutput", self.windows_verify)
        self.assertIn("schemaVersion = 1", self.windows_verify)
        self.assertIn("files = @($signingEvidenceFiles)", self.windows_verify)

    def test_release_notes_disclose_windows_self_signed_trust(self) -> None:
        self.assertIn("project self-signed Authenticode", self.source)
        self.assertIn("not publicly", self.source)
        self.assertIn("SmartScreen", self.source)
        self.assertIn("Unknown Publisher", self.source)
        self.assertIn("archive SHA-256 against SHA256SUMS", self.source)
        self.assertIn(
            "release/windows-self-signed-code-signing.json",
            self.source,
        )
        self.assertIn("jq -er '.certificateSha256'", self.source)
        self.assertIn("windows_certificate_fingerprint", self.source)


if __name__ == "__main__":
    unittest.main()
