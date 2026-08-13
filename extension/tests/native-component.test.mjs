import test from "node:test";
import assert from "node:assert/strict";
import {
  formatInstallerSize,
  inspectNativeComponent,
  nativeSetupPromptRequired,
  normalizeChromiumPlatform,
  platformLabel,
  selectEmbeddedInstaller
} from "../src/native-component.js";
import { validateWindowsInstallerTrust } from "../src/setup.js";

const version = "0.5.9";
const digest = "a".repeat(64);

function installerIndex(overrides = {}) {
  return {
    schemaVersion: 1,
    version,
    snapshot: {
      targetHeight: 300_000,
      compressedSha256: "b".repeat(64)
    },
    installers: [
      {
        platform: "linux",
        architecture: "x64",
        path: "installers/hns-dane-browser-setup-linux-x64.tar.gz",
        fileName: "hns-dane-browser-setup-linux-x64.tar.gz",
        size: 42 * 1024 * 1024,
        sha256: digest,
        signingStatus: "attested"
      }
    ],
    ...overrides
  };
}

test("native component inspection requires an exact extension version", () => {
  assert.deepEqual(inspectNativeComponent({ nativeHost: version }, version), {
    state: "ready",
    extensionVersion: version,
    nativeHostVersion: version
  });
  assert.deepEqual(inspectNativeComponent({ nativeHost: "0.5.8" }, version), {
    state: "versionMismatch",
    extensionVersion: version,
    nativeHostVersion: "0.5.8"
  });
  assert.equal(
    inspectNativeComponent({ nativeHost: "0.5.9.0" }, version).state,
    "versionMismatch"
  );
  assert.deepEqual(inspectNativeComponent({}, version), {
    state: "incompatible",
    extensionVersion: version,
    nativeHostVersion: null
  });
});

test("native Setup prompt marker is once per required version", () => {
  assert.equal(nativeSetupPromptRequired(null, version), true);
  assert.equal(nativeSetupPromptRequired("0.5.8", version), true);
  assert.equal(nativeSetupPromptRequired(version, version), false);
  assert.equal(nativeSetupPromptRequired(null, "invalid"), false);
});

test("Chromium platform information maps to release archive names", () => {
  assert.deepEqual(normalizeChromiumPlatform({ os: "linux", arch: "x86-64" }), {
    platform: "linux",
    architecture: "x64"
  });
  assert.deepEqual(normalizeChromiumPlatform({ os: "mac", arch: "arm64" }), {
    platform: "macos",
    architecture: "arm64"
  });
  assert.deepEqual(normalizeChromiumPlatform({ os: "win", arch: "x86-64" }), {
    platform: "windows",
    architecture: "x64"
  });
  assert.equal(normalizeChromiumPlatform({ os: "cros", arch: "x86-64" }), null);
  assert.equal(normalizeChromiumPlatform({ os: "linux", arch: "x86-32" }), null);
});

test("embedded Setup selection is exact, local, and carries snapshot metadata", () => {
  const selected = selectEmbeddedInstaller(
    installerIndex(),
    { os: "linux", arch: "x86-64" },
    version
  );
  assert.deepEqual(selected, {
    platform: "linux",
    architecture: "x64",
    version,
    path: "installers/hns-dane-browser-setup-linux-x64.tar.gz",
    fileName: "hns-dane-browser-setup-linux-x64.tar.gz",
    size: 42 * 1024 * 1024,
    sha256: digest,
    signingStatus: "attested",
    snapshot: { height: 300_000, sha256: "b".repeat(64) }
  });
  assert.equal(platformLabel(selected), "Linux, Intel/AMD 64-bit");
  assert.equal(formatInstallerSize(selected.size), "42 MiB");
  assert.equal(
    selectEmbeddedInstaller(
      installerIndex(),
      { os: "linux", arch: "arm64" },
      version
    ),
    null
  );
});

test("embedded Setup selection rejects stale, unsafe, and ambiguous indexes", () => {
  assert.throws(
    () =>
      selectEmbeddedInstaller(
        installerIndex({ version: "0.5.8" }),
        { os: "linux", arch: "x86-64" },
        version
      ),
    /does not match/
  );
  assert.throws(
    () =>
      selectEmbeddedInstaller(
        installerIndex({
          installers: [
            {
              ...installerIndex().installers[0],
              path: "installers/../outside.tar.gz"
            }
          ]
        }),
        { os: "linux", arch: "x86-64" },
        version
      ),
    /entry is invalid/
  );
  assert.throws(
    () =>
      selectEmbeddedInstaller(
        installerIndex({
          installers: [
            installerIndex().installers[0],
            { ...installerIndex().installers[0] }
          ]
        }),
        { os: "linux", arch: "x86-64" },
        version
      ),
    /duplicate/
  );
});

test("Windows Setup requires explicit self-signed trust and signer fingerprint metadata", () => {
  const archiveSha256 = "c".repeat(64);
  const signerCertificateSha256 = "D".repeat(64);
  const selection = {
    platform: "windows",
    path: "installers/hns-dane-browser-setup-windows-x64.zip",
    sha256: archiveSha256
  };
  const metadata = {
    platform: "windows",
    path: selection.path,
    signingStatus: "selfSignedAuthenticodeAndTimestamped",
    certificateTrust: "notPubliclyTrusted",
    signerCertificateSha256
  };
  assert.deepEqual(
    validateWindowsInstallerTrust({ installers: [metadata] }, selection),
    {
      certificateTrust: "notPubliclyTrusted",
      signerCertificateSha256: signerCertificateSha256.toLowerCase()
    }
  );
  assert.equal(
    validateWindowsInstallerTrust({}, { platform: "linux" }),
    null
  );
});

test("Windows Setup fails closed for missing or malformed trust metadata", () => {
  const selection = {
    platform: "windows",
    path: "installers/hns-dane-browser-setup-windows-x64.zip",
    sha256: "c".repeat(64)
  };
  const valid = {
    platform: "windows",
    path: selection.path,
    signingStatus: "selfSignedAuthenticodeAndTimestamped",
    certificateTrust: "notPubliclyTrusted",
    signerCertificateSha256: "d".repeat(64)
  };
  for (const [field, value] of [
    ["signingStatus", "authenticodeSignedAndTimestamped"],
    ["certificateTrust", "publiclyTrusted"],
    ["signerCertificateSha256", "not-a-fingerprint"],
    ["signerCertificateSha256", null]
  ]) {
    assert.throws(
      () =>
        validateWindowsInstallerTrust(
          { installers: [{ ...valid, [field]: value }] },
          selection
        ),
      /Windows Setup/
    );
  }
  assert.throws(
    () => validateWindowsInstallerTrust({ installers: [] }, selection),
    /missing or ambiguous/
  );
  assert.throws(
    () =>
      validateWindowsInstallerTrust(
        { installers: [valid] },
        { ...selection, sha256: null }
      ),
    /archive SHA-256/
  );
});
