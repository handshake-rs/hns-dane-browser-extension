import { authoritativeHeaderSync } from "./header-status.js";

export const AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS = 10 * 60 * 1000;

export function needsAutomaticHeaderSync(candidate) {
  const sync = authoritativeHeaderSync(candidate);
  if (!sync) return true;
  return (
    sync.freshness === "stale" ||
    sync.freshness === "unknown" ||
    sync.targetEvidenceExpired === true
  );
}

export function automaticHeaderSyncAllowed(
  lastAttemptAt,
  now = Date.now(),
  minimumInterval = AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS
) {
  if (!Number.isSafeInteger(now) || now < 0) return false;
  if (!Number.isSafeInteger(minimumInterval) || minimumInterval < 1) return false;
  if (!Number.isSafeInteger(lastAttemptAt) || lastAttemptAt < 0) return true;
  return now >= lastAttemptAt && now - lastAttemptAt >= minimumInterval;
}
