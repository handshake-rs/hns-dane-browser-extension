import { authoritativeHeaderSync } from "./header-status.js";

export const AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS = 10 * 60 * 1000;
export const HEADER_TARGET_REFRESH_LEAD_MS = 2 * 60 * 1000;
export const HEADER_TARGET_URGENT_RETRY_INTERVAL_MS = 60 * 1000;
export const HEADER_TARGET_URGENT_RETRY_GRACE_MS = 2 * 60 * 1000;

export function automaticHeaderSyncDueAt(
  candidate,
  leadTime = HEADER_TARGET_REFRESH_LEAD_MS
) {
  if (!Number.isSafeInteger(leadTime) || leadTime < 0) return null;
  const sync = authoritativeHeaderSync(candidate);
  if (
    !sync ||
    sync.freshness === "stale" ||
    sync.freshness === "unknown" ||
    sync.targetEvidenceExpired === true
  ) {
    return 0;
  }
  if (
    !Number.isSafeInteger(sync.targetEvidenceValidUntilUnix) ||
    sync.targetEvidenceValidUntilUnix < 0 ||
    sync.targetEvidenceValidUntilUnix >
      Math.floor(Number.MAX_SAFE_INTEGER / 1000)
  ) {
    return null;
  }
  return Math.max(0, sync.targetEvidenceValidUntilUnix * 1000 - leadTime);
}

export function needsAutomaticHeaderSync(
  candidate,
  now = Date.now(),
  leadTime = HEADER_TARGET_REFRESH_LEAD_MS
) {
  if (!Number.isSafeInteger(now) || now < 0) return false;
  const dueAt = automaticHeaderSyncDueAt(candidate, leadTime);
  return dueAt == null || now >= dueAt;
}

export function nextAutomaticHeaderSyncAllowedAt(
  lastAttemptAt,
  now = Date.now(),
  minimumInterval = AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS
) {
  if (!Number.isSafeInteger(now) || now < 0) return null;
  if (!Number.isSafeInteger(minimumInterval) || minimumInterval < 1) return null;
  if (!Number.isSafeInteger(lastAttemptAt) || lastAttemptAt < 0) return now;
  // A wall-clock rollback must not strand maintenance behind a timestamp that
  // cannot be reached. Treat a future attempt as unavailable, matching the
  // persisted-state loader's normalization.
  if (lastAttemptAt > now) return now;
  const allowedAt = lastAttemptAt + minimumInterval;
  if (!Number.isSafeInteger(allowedAt)) return null;
  return Math.max(now, allowedAt);
}

export function headerSyncUrgentRetryWindow(
  candidate,
  leadTime = HEADER_TARGET_REFRESH_LEAD_MS,
  graceTime = HEADER_TARGET_URGENT_RETRY_GRACE_MS
) {
  if (
    !Number.isSafeInteger(leadTime) ||
    leadTime < 0 ||
    !Number.isSafeInteger(graceTime) ||
    graceTime < 0
  ) {
    return null;
  }
  const sync = authoritativeHeaderSync(candidate);
  if (
    !sync ||
    sync.freshness !== "current" ||
    sync.targetEvidenceExpired === true ||
    sync.targetEvidenceValidUntilUnix >
      Math.floor((Number.MAX_SAFE_INTEGER - graceTime) / 1000)
  ) {
    return null;
  }
  const expiresAt = sync.targetEvidenceValidUntilUnix * 1000;
  return {
    network: sync.network,
    startsAt: Math.max(0, expiresAt - leadTime),
    endsAt: expiresAt + graceTime
  };
}

export function normalizedHeaderSyncUrgentRetryWindow(candidate, now = Date.now()) {
  if (
    !candidate ||
    typeof candidate !== "object" ||
    Array.isArray(candidate) ||
    typeof candidate.network !== "string" ||
    candidate.network.length === 0 ||
    !Number.isSafeInteger(candidate.startsAt) ||
    candidate.startsAt < 0 ||
    !Number.isSafeInteger(candidate.endsAt) ||
    candidate.endsAt < candidate.startsAt ||
    !Number.isSafeInteger(now) ||
    now < 0 ||
    candidate.endsAt < now
  ) {
    return null;
  }
  return {
    network: candidate.network,
    startsAt: candidate.startsAt,
    endsAt: candidate.endsAt
  };
}

export function nextAutomaticHeaderSyncAttemptAt(
  candidate,
  lastAttemptAt,
  retainedUrgentWindow = null,
  now = Date.now(),
  minimumInterval = AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS,
  urgentRetryInterval = HEADER_TARGET_URGENT_RETRY_INTERVAL_MS
) {
  if (
    !Number.isSafeInteger(now) ||
    now < 0 ||
    !Number.isSafeInteger(minimumInterval) ||
    minimumInterval < 1 ||
    !Number.isSafeInteger(urgentRetryInterval) ||
    urgentRetryInterval < 1
  ) {
    return null;
  }

  const dueAt = automaticHeaderSyncDueAt(candidate);
  if (Number.isSafeInteger(dueAt) && dueAt > now) return dueAt;

  const derivedWindow = normalizedHeaderSyncUrgentRetryWindow(
    headerSyncUrgentRetryWindow(candidate),
    now
  );
  const retainedWindow = normalizedHeaderSyncUrgentRetryWindow(
    retainedUrgentWindow,
    now
  );
  const candidateNetwork =
    candidate && typeof candidate.network === "string"
      ? candidate.network
      : null;
  const urgentWindow =
    derivedWindow ??
    (retainedWindow?.network === candidateNetwork ? retainedWindow : null);
  const normalizedLastAttempt =
    Number.isSafeInteger(lastAttemptAt) &&
    lastAttemptAt >= 0 &&
    lastAttemptAt <= now
      ? lastAttemptAt
      : null;
  const routineAllowedAt = nextAutomaticHeaderSyncAllowedAt(
    normalizedLastAttempt,
    now,
    minimumInterval
  );

  if (urgentWindow && now < urgentWindow.startsAt) {
    return routineAllowedAt == null
      ? urgentWindow.startsAt
      : Math.min(urgentWindow.startsAt, routineAllowedAt);
  }
  if (
    urgentWindow &&
    now >= urgentWindow.startsAt &&
    now <= urgentWindow.endsAt
  ) {
    if (normalizedLastAttempt == null) return now;
    const urgentAllowedAt = normalizedLastAttempt + urgentRetryInterval;
    if (
      Number.isSafeInteger(urgentAllowedAt) &&
      urgentAllowedAt <= urgentWindow.endsAt
    ) {
      return Math.max(now, urgentAllowedAt);
    }
  }

  return routineAllowedAt;
}

export function automaticHeaderSyncAllowed(
  lastAttemptAt,
  now = Date.now(),
  minimumInterval = AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS
) {
  const allowedAt = nextAutomaticHeaderSyncAllowedAt(
    lastAttemptAt,
    now,
    minimumInterval
  );
  return allowedAt != null && now >= allowedAt;
}
