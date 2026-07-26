const SYNC_STATES = new Set([
  "idle",
  "syncing",
  "synced",
  "up_to_date",
  "attempted",
  "peer_failed",
  "seed_failed",
  "error"
]);
const FRESHNESS_STATES = new Set(["current", "stale", "unknown"]);
const TARGET_SOURCES = new Set(["corroboratedPeers", "unknown"]);
const REQUIRED_FRESHNESS_THRESHOLD_BLOCKS = 2;
const REQUIRED_TARGET_PEER_GROUPS = 3;

export function currentHeaderSync(candidate) {
  if (
    !isRecord(candidate) ||
    typeof candidate.network !== "string" ||
    candidate.network.length === 0 ||
    !SYNC_STATES.has(candidate.status) ||
    !optionalHeight(candidate.bestHeight) ||
    !optionalHeight(candidate.bestPeerHeight) ||
    !optionalHeight(candidate.estimatedTipHeight) ||
    (candidate.targetPeerGroups !== undefined &&
      !optionalHeight(candidate.targetPeerGroups)) ||
    (candidate.targetEvidenceExpired !== undefined &&
      typeof candidate.targetEvidenceExpired !== "boolean")
  ) {
    return null;
  }

  const freshnessFields = [
    "effectiveTargetHeight",
    "lagBlocks",
    "freshness",
    "freshnessThresholdBlocks",
    "targetSource"
  ];
  const present = freshnessFields.filter((field) => candidate[field] !== undefined);
  if (present.length === 0) return candidate;
  if (present.length !== freshnessFields.length || !validFreshness(candidate)) return null;
  return candidate;
}

export function authoritativeHeaderSync(candidate) {
  const sync = currentHeaderSync(candidate);
  if (
    !sync ||
    typeof sync.freshness !== "string" ||
    sync.freshnessThresholdBlocks !== REQUIRED_FRESHNESS_THRESHOLD_BLOCKS ||
    !isHeight(sync.targetPeerGroups) ||
    typeof sync.targetEvidenceExpired !== "boolean" ||
    (sync.freshness !== "unknown" &&
      sync.targetPeerGroups < REQUIRED_TARGET_PEER_GROUPS)
  ) {
    return null;
  }
  return sync;
}

export function validHeaderSyncEnvelope(candidate) {
  if (!isRecord(candidate)) return false;
  if (candidate.headerSync != null) {
    return authoritativeHeaderSync(candidate.headerSync) != null;
  }
  return (
    candidate.headerSync === null &&
    typeof candidate.headerSyncUnavailableReason === "string" &&
    candidate.headerSyncUnavailableReason.length > 0 &&
    candidate.headerSyncUnavailableReason.length <= 512
  );
}

export function headerChainView(candidate, operation = {}) {
  const sync = currentHeaderSync(candidate);
  const syncing = operation.syncing === true;
  const operationError =
    typeof operation.error === "string" && operation.error.length > 0
      ? operation.error
      : null;
  if (!sync) {
    return {
      bestHeight: "—",
      peerHeight: "—",
      estimatedHeight: "—",
      targetHeight: "—",
      targetPeerGroups: "—",
      lag: "—",
      threshold: "—",
      state: syncing ? "Syncing" : "Unavailable",
      detail: syncing
        ? "Synchronizing validated headers with Handshake peers…"
        : operationError ?? "Validated header status is unavailable."
    };
  }

  const syncError =
    operationError ??
    (typeof sync.error === "string" && sync.error.length > 0 ? sync.error : null);
  const authoritative = authoritativeHeaderSync(sync) != null;
  const state = syncing
    ? "Syncing"
    : authoritative
      ? freshnessLabel(sync.freshness)
      : "Unknown";

  return {
    bestHeight: formatHeight(sync.bestHeight),
    peerHeight: formatHeight(sync.bestPeerHeight),
    estimatedHeight: formatHeight(sync.estimatedTipHeight),
    targetHeight: authoritative ? formatHeight(sync.effectiveTargetHeight) : "—",
    targetPeerGroups: formatCount(sync.targetPeerGroups),
    lag: authoritative ? formatBlocks(sync.lagBlocks) : "—",
    threshold: authoritative ? formatBlocks(sync.freshnessThresholdBlocks) : "—",
    state,
    detail: headerDetail(sync, { authoritative, syncing, syncError })
  };
}

export function pageProofAnchor(security) {
  const height = security?.chainAnchor?.localBestHeight;
  return isHeight(height) ? formatHeight(height) : "—";
}

function validFreshness(candidate) {
  if (
    !optionalHeight(candidate.effectiveTargetHeight) ||
    !optionalHeight(candidate.lagBlocks) ||
    !isHeight(candidate.freshnessThresholdBlocks) ||
    !FRESHNESS_STATES.has(candidate.freshness) ||
    !TARGET_SOURCES.has(candidate.targetSource)
  ) {
    return false;
  }

  if (candidate.freshness === "unknown") {
    return (
      candidate.effectiveTargetHeight == null &&
      candidate.lagBlocks == null &&
      candidate.targetSource === "unknown"
    );
  }
  if (
    candidate.bestHeight == null ||
    candidate.bestHeight < 1 ||
    candidate.effectiveTargetHeight == null ||
    candidate.lagBlocks == null ||
    candidate.targetSource !== "corroboratedPeers" ||
    candidate.targetEvidenceExpired === true
  ) {
    return false;
  }
  const lag = Math.max(0, candidate.effectiveTargetHeight - candidate.bestHeight);
  if (candidate.lagBlocks !== lag) return false;
  return candidate.freshness === "stale"
    ? lag > candidate.freshnessThresholdBlocks
    : lag <= candidate.freshnessThresholdBlocks;
}

function headerDetail(sync, { authoritative, syncing, syncError }) {
  const diagnosticNote =
    "The highest peer claim and schedule estimate are diagnostic only.";
  if (syncing) return "Synchronizing validated headers with Handshake peers…";
  if (syncError) return `The last header sync failed: ${syncError}`;
  if (!authoritative || sync.freshness === "unknown") {
    const reason =
      sync.targetEvidenceExpired === true
        ? "Corroborated target evidence expired."
        : "No corroborated multi-peer target is available.";
    return `${reason} ${diagnosticNote}`;
  }
  if (sync.freshness === "stale") {
    return `The validated tip is ${formatBlocks(
      sync.lagBlocks
    )} behind the corroborated target. ${diagnosticNote}`;
  }
  return `Current means within ${formatBlocks(
    sync.freshnessThresholdBlocks
  )} of the corroborated peer target; current lag is ${formatBlocks(
    sync.lagBlocks
  )}. ${diagnosticNote}`;
}

function freshnessLabel(freshness) {
  if (freshness === "current") return "Current";
  if (freshness === "stale") return "Stale";
  return "Unknown";
}

function formatHeight(height) {
  return isHeight(height) ? `#${height.toLocaleString("en-US")}` : "—";
}

function formatBlocks(blocks) {
  if (!isHeight(blocks)) return "—";
  return `${blocks.toLocaleString("en-US")} ${blocks === 1 ? "block" : "blocks"}`;
}

function formatCount(value) {
  return isHeight(value) ? value.toLocaleString("en-US") : "—";
}

function optionalHeight(value) {
  return value == null || isHeight(value);
}

function isHeight(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
