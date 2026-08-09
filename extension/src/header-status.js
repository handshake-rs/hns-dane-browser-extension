const SYNC_STATES = new Set([
  "idle",
  "syncing",
  "synced",
  "up_to_date",
  "coalesced",
  "attempted",
  "peer_failed",
  "seed_failed",
  "error"
]);
const FRESHNESS_STATES = new Set(["current", "stale", "unknown"]);
const TARGET_SOURCES = new Set(["corroboratedPeers", "unknown"]);
const SUCCESSFUL_REFRESH_STATES = new Set([
  "syncing",
  "synced",
  "up_to_date"
]);
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
      typeof candidate.targetEvidenceExpired !== "boolean") ||
    (candidate.targetEvidenceValidUntilUnix !== undefined &&
      !optionalUnixSeconds(candidate.targetEvidenceValidUntilUnix))
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
    (sync.freshness === "unknown"
      ? sync.targetEvidenceValidUntilUnix !== null
      : !isUnixSeconds(sync.targetEvidenceValidUntilUnix)) ||
    (sync.freshness !== "unknown" &&
      sync.targetPeerGroups < REQUIRED_TARGET_PEER_GROUPS) ||
    !validNameTreeCurrentness(sync)
  ) {
    return null;
  }
  return sync;
}

export function headerSyncReadyForProxyActivation(
  candidate,
  nowUnixSeconds = Math.floor(Date.now() / 1000)
) {
  if (!Number.isSafeInteger(nowUnixSeconds) || nowUnixSeconds < 0) return false;
  const sync = authoritativeHeaderSync(candidate);
  return (
    sync?.treeRootReady === true &&
    sync.blocksUntilAuthoritativeTreeRoot === 0 &&
    sync.targetEvidenceExpired === false &&
    Number.isSafeInteger(sync.targetEvidenceValidUntilUnix) &&
    sync.targetEvidenceValidUntilUnix > nowUnixSeconds
  );
}

export function headerSyncRefreshError(candidate) {
  const sync = authoritativeHeaderSync(candidate);
  if (!sync) return "native host returned invalid header sync status";
  if (sync.error != null) {
    return typeof sync.error === "string" && sync.error.length > 0
      ? sync.error
      : "native host returned invalid header sync error";
  }
  if (sync.status === "coalesced") {
    return (
      sync.attempted === 0 &&
      sync.successful === 0 &&
      sync.accepted === 0 &&
      sync.failed === 0 &&
      Array.isArray(sync.failures) &&
      sync.failures.length === 0
    )
      ? null
      : "native host returned invalid coalesced header sync envelope";
  }
  if (!SUCCESSFUL_REFRESH_STATES.has(sync.status)) {
    return `header synchronization reported ${sync.status}`;
  }
  if (
    !Number.isSafeInteger(sync.attempted) ||
    sync.attempted < 1 ||
    !Number.isSafeInteger(sync.successful) ||
    sync.successful < 1 ||
    sync.successful > sync.attempted
  ) {
    return "header synchronization completed without a successful peer";
  }
  return null;
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
    : authoritative && sync.treeRootReady === true
      ? sync.freshness === "current"
        ? "Current"
        : "Name state ready"
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
      candidate.targetSource === "unknown" &&
      candidate.targetEvidenceValidUntilUnix == null
    );
  }
  if (
    candidate.bestHeight == null ||
    candidate.bestHeight < 1 ||
    candidate.effectiveTargetHeight == null ||
    candidate.lagBlocks == null ||
    candidate.targetSource !== "corroboratedPeers" ||
    (candidate.targetEvidenceValidUntilUnix !== undefined &&
      !isUnixSeconds(candidate.targetEvidenceValidUntilUnix)) ||
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

function validNameTreeCurrentness(candidate) {
  if (
    !isHeight(candidate.treeIntervalBlocks) ||
    candidate.treeIntervalBlocks === 0 ||
    !optionalHeight(candidate.authoritativeTreeRootHeight) ||
    !optionalHeight(candidate.localTreeRootHeight) ||
    !optionalHeight(candidate.blocksUntilAuthoritativeTreeRoot) ||
    !optionalBoolean(candidate.treeRootReady)
  ) {
    return false;
  }
  if (candidate.freshness === "unknown") {
    return (
      candidate.authoritativeTreeRootHeight == null &&
      candidate.treeRootReady == null &&
      candidate.blocksUntilAuthoritativeTreeRoot == null
    );
  }
  if (
    candidate.bestHeight == null ||
    candidate.bestHeight < 1 ||
    candidate.localTreeRootHeight == null ||
    candidate.localTreeRootHeight < 1 ||
    candidate.localTreeRootHeight > candidate.bestHeight ||
    candidate.authoritativeTreeRootHeight == null ||
    candidate.authoritativeTreeRootHeight < 1 ||
    candidate.blocksUntilAuthoritativeTreeRoot == null
  ) {
    return false;
  }
  if (candidate.treeRootReady === true) {
    return (
      candidate.blocksUntilAuthoritativeTreeRoot === 0 &&
      candidate.localTreeRootHeight === candidate.authoritativeTreeRootHeight &&
      candidate.bestHeight >= candidate.authoritativeTreeRootHeight
    );
  }
  return (
    candidate.treeRootReady === false &&
    candidate.blocksUntilAuthoritativeTreeRoot > 0
  );
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
    if (sync.treeRootReady === true) {
      return `The authoritative HNS name state at ${formatHeight(
        sync.authoritativeTreeRootHeight
      )} is ready while validated headers continue catching up; the tip is ${formatBlocks(
        sync.lagBlocks
      )} behind the corroborated target. ${diagnosticNote}`;
    }
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

function optionalUnixSeconds(value) {
  return value == null || isUnixSeconds(value);
}

function optionalBoolean(value) {
  return value == null || typeof value === "boolean";
}

function isUnixSeconds(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isHeight(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
