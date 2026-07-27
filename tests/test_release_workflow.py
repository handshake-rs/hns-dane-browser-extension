from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/release.yml"
CANONICAL_ID = json.loads(
    (ROOT / "release/extension-identity.json").read_text(encoding="utf-8")
)["canonicalId"]


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_external_actions_are_pinned_and_first_party(self) -> None:
        references = re.findall(r"^\s*uses:\s*([^#\s]+)", self.source, re.MULTILINE)
        self.assertTrue(references)
        for reference in references:
            self.assertRegex(
                reference,
                r"^actions/(?:checkout|setup-node|upload-artifact|download-artifact)"
                r"@[0-9a-f]{40}$",
            )
        self.assertNotRegex(self.source, r"uses:\s*softprops/")

    def test_matrix_covers_current_standard_runner_architectures(self) -> None:
        expected = {
            ("linux", "x64", "ubuntu-24.04", "x86_64-unknown-linux-musl"),
            (
                "linux",
                "arm64",
                "ubuntu-24.04-arm",
                "aarch64-unknown-linux-musl",
            ),
            ("windows", "x64", "windows-2025", "x86_64-pc-windows-msvc"),
            (
                "windows",
                "arm64",
                "windows-11-arm",
                "aarch64-pc-windows-msvc",
            ),
            ("macos", "x64", "macos-15-intel", "x86_64-apple-darwin"),
            ("macos", "arm64", "macos-15", "aarch64-apple-darwin"),
        }
        rows = set(
            re.findall(
                r"- platform: (\w+)\n"
                r"\s+architecture: (\w+)\n"
                r"\s+runner: ([\w.-]+)\n"
                r"\s+rust-target: ([\w.-]+)",
                self.source,
            )
        )
        self.assertEqual(rows, expected)

    def test_release_is_draft_until_all_builds_and_checks_succeed(self) -> None:
        self.assertIn('tags:\n      - "v*"', self.source)
        self.assertIn('gh release create "$RELEASE_TAG" \\\n              --draft', self.source)
        self.assertIn(
            "needs: [prepare, quality, extension, native]",
            self.source,
        )
        self.assertIn('gh release edit "$RELEASE_TAG" --draft=false', self.source)
        self.assertIn("QUALITY_RESULT: ${{ needs.quality.result }}", self.source)
        self.assertIn("EXTENSION_RESULT: ${{ needs.extension.result }}", self.source)
        self.assertIn("NATIVE_RESULT: ${{ needs.native.result }}", self.source)
        self.assertIn("environment: release", self.source)
        self.assertNotIn("--latest", self.source)

    def test_build_jobs_are_read_only_and_publisher_checks_exact_assets(self) -> None:
        self.assertEqual(self.source.count("contents: write"), 1)
        self.assertIn("actions/upload-artifact@", self.source)
        self.assertIn("actions/download-artifact@", self.source)
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

    def test_linux_release_is_static_musl_with_runtime_smoke_check(self) -> None:
        self.assertIn("sudo apt-get install --no-install-recommends --yes musl-tools", self.source)
        self.assertIn("readelf --program-headers", self.source)
        self.assertIn("readelf --dynamic", self.source)
        self.assertIn("--print-host-manifest", self.source)

    def test_store_identity_and_source_metadata_are_mandatory(self) -> None:
        self.assertIn("vars.CHROMIUM_EXTENSION_ID", self.source)
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
        self.assertIn("unsigned and not notarized", self.source)


if __name__ == "__main__":
    unittest.main()
