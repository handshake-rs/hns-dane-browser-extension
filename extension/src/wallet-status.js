const EXPECTED_CONTRACT = Object.freeze({
  manifestSchemaVersion: 2,
  requiredWalletAbiVersion: 2,
  requiredServiceProtocolVersion: 2,
  requiredProviderSchemaVersion: 1,
  requiredApprovalSchemaVersion: 3,
  maximumFrameBytes: 1_048_576
});

const WALLET_ABI_KEYS = Object.freeze([
  "artifactAntiRollbackCommitted",
  "artifactAuthenticityVerified",
  "artifactLaunchAdmitted",
  "artifactManifestSha256",
  "artifactReleaseId",
  "artifactReleaseLine",
  "artifactReleaseQualified",
  "artifactReleaseSequence",
  "artifactSha256",
  "artifactSignerKeyId",
  "artifactState",
  "available",
  "manifestSchemaVersion",
  "maximumFrameBytes",
  "providerAuthorityContextAvailable",
  "reason",
  "requiredApprovalSchemaVersion",
  "requiredProviderSchemaVersion",
  "requiredServiceProtocolVersion",
  "requiredWalletAbiVersion",
  "runtimeNegotiated",
  "serviceTransportAvailable"
]);

const REJECTION_REASONS = new Set([
  "walletArtifactContractMismatch",
  "walletArtifactDigestMismatch",
  "walletArtifactDirectoryUnsafe",
  "walletArtifactManifestInvalid",
  "walletArtifactManifestNotCanonical",
  "walletArtifactManifestSize",
  "walletArtifactManifestUnsafe",
  "walletArtifactMissing",
  "walletArtifactMutable",
  "walletArtifactPathBindingChanged",
  "walletArtifactPlatformMismatch",
  "walletArtifactPlatformUnsupported",
  "walletArtifactReleaseBelowFloor",
  "walletArtifactReleaseTimeInvalid",
  "walletArtifactRollbackRejected",
  "walletArtifactSignatureInvalid",
  "walletArtifactSignaturePayloadMismatch",
  "walletArtifactSize",
  "walletArtifactUnreadable",
  "walletArtifactUnsafe",
  "walletArtifactVerifierConfigurationInvalid",
  "walletArtifactLaunchFailed"
]);

const LOCAL_UNAVAILABLE_REASONS = new Set([
  "walletNativeHostDisconnected",
  "walletStatusChecking",
  "walletStatusInvalid",
  "walletStatusUnavailable"
]);

const ARTIFACT_STATE_LABELS = Object.freeze({
  authenticityVerified: "Authenticity verified; release not enabled",
  integrityChecked: "Integrity checked; signer not trusted",
  launchAdmitted: "Launch admitted; transport disabled",
  missing: "Not staged",
  rejected: "Rejected",
  unavailable: "Unavailable"
});

export function unavailableWalletAbiStatus(reason = "walletStatusUnavailable") {
  const safeReason = LOCAL_UNAVAILABLE_REASONS.has(reason)
    ? reason
    : "walletStatusUnavailable";
  return Object.freeze({
    manifestSchemaVersion: null,
    requiredWalletAbiVersion: null,
    requiredServiceProtocolVersion: null,
    requiredProviderSchemaVersion: null,
    requiredApprovalSchemaVersion: null,
    maximumFrameBytes: null,
    artifactState: "unavailable",
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
    reason: safeReason
  });
}

export function projectWalletAbiStatus(candidate) {
  if (!validNativeWalletAbiStatus(candidate)) {
    return unavailableWalletAbiStatus("walletStatusInvalid");
  }
  return Object.freeze({
    manifestSchemaVersion: candidate.manifestSchemaVersion,
    requiredWalletAbiVersion: candidate.requiredWalletAbiVersion,
    requiredServiceProtocolVersion: candidate.requiredServiceProtocolVersion,
    requiredProviderSchemaVersion: candidate.requiredProviderSchemaVersion,
    requiredApprovalSchemaVersion: candidate.requiredApprovalSchemaVersion,
    maximumFrameBytes: candidate.maximumFrameBytes,
    artifactState: candidate.artifactState,
    artifactReleaseId: candidate.artifactReleaseId,
    artifactReleaseLine: candidate.artifactReleaseLine,
    artifactReleaseSequence: candidate.artifactReleaseSequence,
    artifactSha256: candidate.artifactSha256,
    artifactManifestSha256: candidate.artifactManifestSha256,
    artifactSignerKeyId: candidate.artifactSignerKeyId,
    artifactAuthenticityVerified: candidate.artifactAuthenticityVerified,
    artifactReleaseQualified: candidate.artifactReleaseQualified,
    artifactAntiRollbackCommitted: candidate.artifactAntiRollbackCommitted,
    artifactLaunchAdmitted: candidate.artifactLaunchAdmitted,
    serviceTransportAvailable: false,
    runtimeNegotiated: false,
    providerAuthorityContextAvailable: false,
    available: false,
    reason: candidate.reason
  });
}

export function walletReadinessView(candidate) {
  const status = validProjectedWalletAbiStatus(candidate)
    ? candidate
    : unavailableWalletAbiStatus("walletStatusInvalid");
  return Object.freeze({
    detail: readinessDetail(status),
    artifact: ARTIFACT_STATE_LABELS[status.artifactState] ?? "Unavailable",
    release: status.artifactReleaseId ?? "—",
    service: "Not connected",
    lockState: "Unavailable",
    activeWallet: "Not exposed",
    modules: "Unavailable",
    provider: "Disabled",
    value: "Disabled"
  });
}

function validNativeWalletAbiStatus(candidate) {
  if (!exactRecord(candidate, WALLET_ABI_KEYS)) return false;
  for (const [key, expected] of Object.entries(EXPECTED_CONTRACT)) {
    if (candidate[key] !== expected) return false;
  }
  if (
    candidate.serviceTransportAvailable !== false ||
    candidate.runtimeNegotiated !== false ||
    candidate.providerAuthorityContextAvailable !== false ||
    candidate.available !== false
  ) {
    return false;
  }
  const admission = admissionContract(candidate.artifactState);
  if (!admission || !admission.reasons.has(candidate.reason)) return false;
  if (
    candidate.artifactAuthenticityVerified !== admission.authenticity ||
    candidate.artifactReleaseQualified !== admission.qualified ||
    candidate.artifactAntiRollbackCommitted !== admission.antiRollback ||
    candidate.artifactLaunchAdmitted !== admission.launch
  ) {
    return false;
  }
  return admission.summary
    ? validArtifactSummary(candidate)
    : absentArtifactSummary(candidate);
}

function validProjectedWalletAbiStatus(candidate) {
  return (
    validNativeWalletAbiStatus(candidate) ||
    (exactRecord(candidate, WALLET_ABI_KEYS) &&
      candidate.artifactState === "unavailable" &&
      LOCAL_UNAVAILABLE_REASONS.has(candidate.reason) &&
      Object.keys(EXPECTED_CONTRACT).every((key) => candidate[key] === null) &&
      absentArtifactSummary(candidate) &&
      candidate.artifactAuthenticityVerified === false &&
      candidate.artifactReleaseQualified === false &&
      candidate.artifactAntiRollbackCommitted === false &&
      candidate.artifactLaunchAdmitted === false &&
      candidate.serviceTransportAvailable === false &&
      candidate.runtimeNegotiated === false &&
      candidate.providerAuthorityContextAvailable === false &&
      candidate.available === false)
  );
}

function admissionContract(state) {
  switch (state) {
    case "missing":
      return {
        reasons: new Set(["walletArtifactMissing"]),
        summary: false,
        authenticity: false,
        qualified: false,
        antiRollback: false,
        launch: false
      };
    case "rejected":
      return {
        reasons: REJECTION_REASONS,
        summary: false,
        authenticity: false,
        qualified: false,
        antiRollback: false,
        launch: false
      };
    case "integrityChecked":
      return {
        reasons: new Set(["walletArtifactAuthenticityUnavailable"]),
        summary: true,
        authenticity: false,
        qualified: false,
        antiRollback: false,
        launch: false
      };
    case "authenticityVerified":
      return {
        reasons: new Set(["walletArtifactQualificationUnavailable"]),
        summary: true,
        authenticity: true,
        qualified: false,
        antiRollback: false,
        launch: false
      };
    case "launchAdmitted":
      return {
        reasons: new Set(["walletServiceTransportUnavailable"]),
        summary: true,
        authenticity: true,
        qualified: true,
        antiRollback: true,
        launch: true
      };
    default:
      return null;
  }
}

function validArtifactSummary(candidate) {
  return (
    validToken(candidate.artifactReleaseId) &&
    validToken(candidate.artifactReleaseLine) &&
    Number.isSafeInteger(candidate.artifactReleaseSequence) &&
    candidate.artifactReleaseSequence > 0 &&
    lowerHexDigest(candidate.artifactSha256) &&
    lowerHexDigest(candidate.artifactManifestSha256) &&
    validToken(candidate.artifactSignerKeyId)
  );
}

function absentArtifactSummary(candidate) {
  return (
    candidate.artifactReleaseId === null &&
    candidate.artifactReleaseLine === null &&
    candidate.artifactReleaseSequence === null &&
    candidate.artifactSha256 === null &&
    candidate.artifactManifestSha256 === null &&
    candidate.artifactSignerKeyId === null
  );
}

function readinessDetail(status) {
  switch (status.reason) {
    case "walletStatusChecking":
      return "Checking the native wallet admission boundary. No wallet process is started.";
    case "walletNativeHostDisconnected":
      return "Native wallet readiness is unavailable because the browser host disconnected.";
    case "walletStatusInvalid":
      return "Native wallet readiness failed its exact schema and disabled-gate checks.";
    case "walletArtifactMissing":
      return status.artifactState === "missing"
        ? "No wallet service artifact is staged. No wallet process is started."
        : "The staged wallet service artifact is incomplete and was rejected.";
    case "walletArtifactAuthenticityUnavailable":
      return "Local integrity passed, but this build has no trusted wallet signer admission.";
    case "walletArtifactQualificationUnavailable":
      return "Artifact authenticity passed, but this build enables no qualified wallet release.";
    case "walletServiceTransportUnavailable":
      return "Artifact launch admission passed, but the private wallet transport remains disabled.";
    case "walletArtifactPlatformUnsupported":
      return "Wallet artifact admission is unavailable on this platform.";
    case "walletStatusUnavailable":
      return "Native wallet readiness is unavailable. No wallet process is started.";
    default:
      return "The staged wallet service artifact failed the local admission boundary.";
  }
}

function validToken(value) {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9._:+-]{1,128}$/.test(value)
  );
}

function lowerHexDigest(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function exactRecord(value, expectedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value).sort();
  return (
    keys.length === expectedKeys.length &&
    keys.every((key, index) => key === expectedKeys[index])
  );
}
