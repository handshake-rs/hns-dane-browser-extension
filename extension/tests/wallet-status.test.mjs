import test from "node:test";
import assert from "node:assert/strict";
import {
  projectWalletAbiStatus,
  unavailableWalletAbiStatus,
  walletReadinessView
} from "../src/wallet-status.js";

const digest = "a".repeat(64);
const manifestDigest = "b".repeat(64);

function walletAbi(overrides = {}) {
  return {
    manifestSchemaVersion: 2,
    requiredWalletAbiVersion: 2,
    requiredServiceProtocolVersion: 2,
    requiredProviderSchemaVersion: 1,
    requiredApprovalSchemaVersion: 3,
    maximumFrameBytes: 1_048_576,
    artifactState: "missing",
    artifactReleaseId: null,
    artifactReleaseLine: null,
    artifactReleaseSequence: null,
    artifactSha256: null,
    artifactManifestSha256: null,
    artifactSignerKeyId: null,
    artifactAuthenticityVerified: false,
    artifactReleaseQualified: false,
    artifactAntiRollbackCommitted: false,
    artifactLaunchAdmitted: false,
    serviceTransportAvailable: false,
    runtimeNegotiated: false,
    providerAuthorityContextAvailable: false,
    available: false,
    reason: "walletArtifactMissing",
    ...overrides
  };
}

function artifactSummary() {
  return {
    artifactReleaseId: "wallet-service-0.1.0",
    artifactReleaseLine: "wallet-service-v1",
    artifactReleaseSequence: 7,
    artifactSha256: digest,
    artifactManifestSha256: manifestDigest,
    artifactSignerKeyId: "wallet-release-key-v1"
  };
}

test("wallet readiness projects the exact missing-artifact status", () => {
  const projected = projectWalletAbiStatus(walletAbi());
  assert.equal(projected.artifactState, "missing");
  assert.equal(projected.reason, "walletArtifactMissing");
  assert.equal(projected.available, false);
  assert.equal(projected.serviceTransportAvailable, false);
  assert.ok(Object.isFrozen(projected));
  assert.deepEqual(walletReadinessView(projected), {
    detail: "No wallet service artifact is staged. No wallet process is started.",
    artifact: "Not staged",
    release: "—",
    service: "Not connected",
    lockState: "Unavailable",
    activeWallet: "Not exposed",
    modules: "Unavailable",
    provider: "Disabled",
    value: "Disabled"
  });
});

test("wallet readiness accepts only internally consistent admission stages", () => {
  const stages = [
    {
      artifactState: "integrityChecked",
      reason: "walletArtifactAuthenticityUnavailable"
    },
    {
      artifactState: "authenticityVerified",
      reason: "walletArtifactQualificationUnavailable",
      artifactAuthenticityVerified: true
    },
    {
      artifactState: "launchAdmitted",
      reason: "walletServiceTransportUnavailable",
      artifactAuthenticityVerified: true,
      artifactReleaseQualified: true,
      artifactAntiRollbackCommitted: true,
      artifactLaunchAdmitted: true
    }
  ];
  for (const stage of stages) {
    const projected = projectWalletAbiStatus(
      walletAbi({ ...artifactSummary(), ...stage })
    );
    assert.equal(projected.artifactState, stage.artifactState);
    assert.equal(projected.artifactReleaseId, "wallet-service-0.1.0");
    assert.equal(projected.serviceTransportAvailable, false);
    assert.equal(projected.runtimeNegotiated, false);
    assert.equal(projected.providerAuthorityContextAvailable, false);
    assert.equal(projected.available, false);
  }
});

test("wallet readiness accepts bounded rejection codes without native text", () => {
  for (const reason of [
    "walletArtifactDirectoryUnsafe",
    "walletArtifactSignatureInvalid",
    "walletArtifactRollbackRejected",
    "walletArtifactLaunchFailed",
    "walletArtifactPlatformUnsupported"
  ]) {
    const projected = projectWalletAbiStatus(
      walletAbi({ artifactState: "rejected", reason })
    );
    assert.equal(projected.artifactState, "rejected");
    assert.equal(projected.reason, reason);
    assert.equal(
      walletReadinessView(projected).detail.includes(reason),
      false
    );
  }
});

test("wallet readiness fails closed on schema, key, summary, and stage mismatches", () => {
  const invalid = [
    walletAbi({ manifestSchemaVersion: 3 }),
    walletAbi({ unexpected: "field" }),
    walletAbi({ artifactReleaseId: "stale-release" }),
    walletAbi({ artifactState: "rejected", reason: "attacker supplied text" }),
    walletAbi({ artifactAuthenticityVerified: true }),
    walletAbi({
      ...artifactSummary(),
      artifactState: "integrityChecked",
      artifactSha256: "A".repeat(64),
      reason: "walletArtifactAuthenticityUnavailable"
    })
  ];
  for (const candidate of invalid) {
    const projected = projectWalletAbiStatus(candidate);
    assert.equal(projected.artifactState, "unavailable");
    assert.equal(projected.reason, "walletStatusInvalid");
    assert.equal(projected.artifactReleaseId, null);
    assert.equal(projected.available, false);
  }
});

test("every runtime, provider, and value availability assertion fails closed", () => {
  for (const field of [
    "serviceTransportAvailable",
    "runtimeNegotiated",
    "providerAuthorityContextAvailable",
    "available"
  ]) {
    const projected = projectWalletAbiStatus(walletAbi({ [field]: true }));
    assert.equal(projected.artifactState, "unavailable", field);
    assert.equal(projected.reason, "walletStatusInvalid", field);
    assert.equal(projected.serviceTransportAvailable, false, field);
    assert.equal(projected.runtimeNegotiated, false, field);
    assert.equal(projected.providerAuthorityContextAvailable, false, field);
    assert.equal(projected.available, false, field);
  }
});

test("local unavailable states remain bounded and the popup revalidates them", () => {
  const disconnected = unavailableWalletAbiStatus(
    "walletNativeHostDisconnected"
  );
  assert.equal(
    walletReadinessView(disconnected).detail,
    "Native wallet readiness is unavailable because the browser host disconnected."
  );
  assert.equal(
    unavailableWalletAbiStatus("attacker supplied text").reason,
    "walletStatusUnavailable"
  );
  assert.equal(
    walletReadinessView({ ...disconnected, available: true }).detail,
    "Native wallet readiness failed its exact schema and disabled-gate checks."
  );
});
