from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from verify_cargo_git_policy import (  # noqa: E402
    CRATES_IO_SOURCE,
    ENGINE_GIT_URL,
    ENGINE_PACKAGES,
    ENGINE_REQUIREMENTS,
    ENGINE_REVISION,
    ENGINE_VERSIONS,
    MIGRATED_LOCAL_CRATES,
    CargoSourcePolicyError,
    verify_repository,
)


class CargoSourcePolicyTests(unittest.TestCase):
    def test_qualified_engine_package_set_is_explicit(self) -> None:
        self.assertEqual(
            ENGINE_PACKAGES,
            {
                "hns-browser-observability",
                "hns-browser-runtime",
                "hns-icann-dane",
                "hns-namespace-resolution",
                "hns-resolution-policy",
            },
        )

    def create_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "rust/fuzz").mkdir(parents=True)
        (root / "tools/hns-header-snapshot-exporter").mkdir(parents=True)

        dependencies = "\n".join(
            f'{package} = "{ENGINE_REQUIREMENTS[package]}"'
            for package in sorted(ENGINE_PACKAGES)
        )
        (root / "rust/Cargo.toml").write_text(f"[workspace.dependencies]\n{dependencies}\n")
        locked = "\n".join(
            f'[[package]]\nname = "{package}"\nversion = "{ENGINE_VERSIONS[package]}"\n'
            f'source = "{CRATES_IO_SOURCE}"\nchecksum = "{"a" * 64}"\n'
            for package in sorted(ENGINE_PACKAGES)
        )
        (root / "rust/Cargo.lock").write_text("version = 4\n\n" + locked)
        (root / "rust/fuzz/Cargo.toml").write_text(
            '[dependencies]\nhns-dane = { version = "=0.2.1", '
            f'git = "{ENGINE_GIT_URL}", rev = "{ENGINE_REVISION}" }}\n'
        )
        (root / "rust/fuzz/Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "hns-browser-dane"\nversion = "0.2.1"\n'
            f'source = "git+{ENGINE_GIT_URL}?rev={ENGINE_REVISION}#{ENGINE_REVISION}"\n'
        )
        (root / "tools/hns-header-snapshot-exporter/Cargo.toml").write_text(
            '[dependencies]\nhns-sync = { version = "=0.2.1", '
            f'git = "{ENGINE_GIT_URL}", rev = "{ENGINE_REVISION}" }}\n'
        )
        (root / "tools/hns-header-snapshot-exporter/Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "hns-browser-sync"\nversion = "0.2.1"\n'
            f'source = "git+{ENGINE_GIT_URL}?rev={ENGINE_REVISION}#{ENGINE_REVISION}"\n'
        )
        return temporary, root

    def verify_fixture(self, root: Path) -> None:
        verify_repository(root, [Path("rust/Cargo.toml"), Path("rust/fuzz/Cargo.toml"), Path("tools/hns-header-snapshot-exporter/Cargo.toml")])

    def test_accepts_exact_reviewed_engine_revision(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            self.verify_fixture(root)

    def test_rejects_git_source_in_shipping_manifest(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            manifest = root / "rust/Cargo.toml"
            manifest.write_text(manifest.read_text() + f'\nhns-core = {{ version = "=0.2.1", git = "{ENGINE_GIT_URL}", rev = "{ENGINE_REVISION}" }}\n')
            with self.assertRaisesRegex(CargoSourcePolicyError, "not an exact reviewed"):
                self.verify_fixture(root)

    def test_rejects_changed_tooling_revision(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            manifest = root / "tools/hns-header-snapshot-exporter/Cargo.toml"
            manifest.write_text(manifest.read_text().replace(ENGINE_REVISION, "a" * 40))
            with self.assertRaisesRegex(CargoSourcePolicyError, "not an exact reviewed"):
                self.verify_fixture(root)

    def test_rejects_restored_product_local_engine_crate(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            package = sorted(MIGRATED_LOCAL_CRATES)[0]
            (root / "rust/crates" / package).mkdir(parents=True)
            with self.assertRaisesRegex(CargoSourcePolicyError, "must not be restored locally"):
                self.verify_fixture(root)

    def test_rejects_git_manifest_dependency(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            manifest = root / "rust/fuzz/Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    ENGINE_GIT_URL,
                    "https://example.invalid/engine.git",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                CargoSourcePolicyError, "not an exact reviewed"
            ):
                self.verify_fixture(root)

    def test_rejects_moving_engine_requirement(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            manifest = root / "rust/Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    ENGINE_REQUIREMENTS["hns-browser-observability"],
                    ENGINE_VERSIONS["hns-browser-observability"],
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "exact reviewed"):
                self.verify_fixture(root)

    def test_rejects_split_manifest_revision(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            manifest = root / "rust/fuzz/Cargo.toml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    ENGINE_REVISION,
                    "a" * 40,
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "exact reviewed"):
                self.verify_fixture(root)

    def test_rejects_wrong_locked_version(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            lockfile = root / "rust/Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace(
                    f'version = "{ENGINE_VERSIONS["hns-browser-observability"]}"',
                    'version = "9.9.9"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "registry version and checksum"):
                self.verify_fixture(root)

    def test_rejects_split_locked_revision(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            lockfile = root / "rust/fuzz/Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8").replace(
                    ENGINE_REVISION,
                    "a" * 40,
                    2,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "not allowed"):
                self.verify_fixture(root)

    def test_rejects_missing_registry_checksum(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            lockfile = root / "rust/Cargo.lock"
            lockfile.write_text(lockfile.read_text().replace(f'checksum = "{"a" * 64}"\n', "", 1))
            with self.assertRaisesRegex(CargoSourcePolicyError, "registry version and checksum"):
                self.verify_fixture(root)

    def test_rejects_any_locked_git_package(self) -> None:
        temporary, root = self.create_fixture()
        with temporary:
            lockfile = root / "rust/fuzz/Cargo.lock"
            lockfile.write_text(
                lockfile.read_text(encoding="utf-8")
                + "\n[[package]]\n"
                + 'name = "unreviewed-git-crate"\n'
                + 'version = "1.0.0"\n'
                + 'source = "git+https://example.invalid/crate#deadbeef"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CargoSourcePolicyError, "not allowed"):
                self.verify_fixture(root)


if __name__ == "__main__":
    unittest.main()
