import test from "node:test";
import assert from "node:assert/strict";
import {
  AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS,
  HEADER_TARGET_REFRESH_LEAD_MS,
  HEADER_TARGET_URGENT_RETRY_GRACE_MS,
  HEADER_TARGET_URGENT_RETRY_INTERVAL_MS,
  automaticHeaderSyncDueAt,
  automaticHeaderSyncAllowed,
  headerSyncUrgentRetryWindow,
  needsAutomaticHeaderSync,
  nextAutomaticHeaderSyncAllowedAt,
  nextAutomaticHeaderSyncAttemptAt,
  normalizedHeaderSyncUrgentRetryWindow
} from "../src/header-sync-schedule.js";

function status(freshness, overrides = {}) {
  const current = freshness === "current";
  return {
    network: "mainnet",
    status: current ? "up_to_date" : "syncing",
    bestHeight: 339_927,
    bestPeerHeight: 339_929,
    estimatedTipHeight: 339_930,
    effectiveTargetHeight: freshness === "unknown" ? null : 339_929,
    lagBlocks: freshness === "unknown" ? null : 2,
    freshness,
    freshnessThresholdBlocks: 2,
    treeIntervalBlocks: 36,
    authoritativeTreeRootHeight: freshness === "unknown" ? null : 339_913,
    localTreeRootHeight: 339_913,
    treeRootReady: freshness === "unknown" ? null : true,
    blocksUntilAuthoritativeTreeRoot: freshness === "unknown" ? null : 0,
    targetSource: freshness === "unknown" ? "unknown" : "corroboratedPeers",
    targetPeerGroups: freshness === "unknown" ? 0 : 3,
    targetEvidenceExpired: freshness === "unknown",
    targetEvidenceValidUntilUnix:
      freshness === "unknown" ? null : 2_000_000,
    ...overrides
  };
}

test("automatic maintenance syncs stale, unknown, expired, or deadline-due state", () => {
  const dueAt = 2_000_000_000 - HEADER_TARGET_REFRESH_LEAD_MS;
  assert.equal(needsAutomaticHeaderSync(status("current"), dueAt - 1), false);
  assert.equal(needsAutomaticHeaderSync(status("current"), dueAt), true);
  assert.equal(
    needsAutomaticHeaderSync(
      status("stale", { effectiveTargetHeight: 339_930, lagBlocks: 3 }),
      dueAt - 1
    ),
    true
  );
  assert.equal(needsAutomaticHeaderSync(status("unknown"), dueAt - 1), true);
  assert.equal(
    needsAutomaticHeaderSync(
      status("current", { targetEvidenceExpired: true }),
      dueAt - 1
    ),
    true
  );
  assert.equal(needsAutomaticHeaderSync(null, dueAt - 1), true);
});

test("automatic deadline reserves ten minutes before quorum evidence expires", () => {
  assert.equal(HEADER_TARGET_REFRESH_LEAD_MS, 10 * 60 * 1000);
  assert.equal(
    automaticHeaderSyncDueAt(status("current")),
    2_000_000_000 - HEADER_TARGET_REFRESH_LEAD_MS
  );
  assert.equal(automaticHeaderSyncDueAt(status("unknown")), 0);
  assert.equal(
    automaticHeaderSyncDueAt(
      status("current", {
        targetEvidenceValidUntilUnix:
          Math.floor(Number.MAX_SAFE_INTEGER / 1000) + 1
      })
    ),
    null
  );
});

test("known quorum deadlines get a bounded one-minute urgent retry window", () => {
  const expiresAt = 2_000_000_000;
  const dueAt = expiresAt - HEADER_TARGET_REFRESH_LEAD_MS;
  const window = headerSyncUrgentRetryWindow(status("current"));

  assert.equal(HEADER_TARGET_URGENT_RETRY_INTERVAL_MS, 60_000);
  assert.equal(HEADER_TARGET_URGENT_RETRY_GRACE_MS, 120_000);
  assert.deepEqual(window, {
    network: "mainnet",
    startsAt: dueAt,
    endsAt: expiresAt + HEADER_TARGET_URGENT_RETRY_GRACE_MS
  });
  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("current"),
      dueAt - 1,
      null,
      dueAt
    ),
    dueAt + HEADER_TARGET_URGENT_RETRY_INTERVAL_MS - 1
  );
  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("current"),
      dueAt,
      null,
      expiresAt
    ),
    expiresAt
  );
});

test("retained deadline context bounds retries after quorum becomes unknown", () => {
  const expiresAt = 2_000_000_000;
  const window = headerSyncUrgentRetryWindow(status("current"));
  const afterExpiry = expiresAt + 30_000;

  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("unknown"),
      window.startsAt - 30_000,
      window,
      window.startsAt - 30_000
    ),
    window.startsAt
  );
  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("unknown"),
      expiresAt,
      window,
      afterExpiry
    ),
    expiresAt + HEADER_TARGET_URGENT_RETRY_INTERVAL_MS
  );
  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("unknown"),
      expiresAt,
      window,
      window.endsAt + 1
    ),
    expiresAt + AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS
  );
  assert.deepEqual(
    normalizedHeaderSyncUrgentRetryWindow(window, window.endsAt),
    window
  );
  assert.equal(
    normalizedHeaderSyncUrgentRetryWindow(window, window.endsAt + 1),
    null
  );
  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("unknown", { network: "testnet" }),
      expiresAt,
      window,
      afterExpiry
    ),
    expiresAt + AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS
  );
});

test("a retained future window never postpones a normally due retry after clock rollback", () => {
  const window = headerSyncUrgentRetryWindow(status("current"));
  const rolledBackNow = window.startsAt - 5 * 60_000;
  const preRollbackAttempt = window.startsAt + 1;

  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("unknown"),
      preRollbackAttempt,
      window,
      rolledBackNow
    ),
    rolledBackNow
  );
  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("unknown"),
      rolledBackNow - 9 * 60_000,
      window,
      rolledBackNow
    ),
    rolledBackNow + 60_000
  );
});

test("a newly current later deadline supersedes retained retry context", () => {
  const oldWindow = headerSyncUrgentRetryWindow(status("current"));
  const later = status("current", {
    targetEvidenceValidUntilUnix: 2_001_000
  });
  const now = oldWindow.startsAt;

  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(later, now - 1, oldWindow, now),
    automaticHeaderSyncDueAt(later)
  );
});

test("stale and unknown state without retained deadline keeps the ten-minute floor", () => {
  const now = 2_000_000;
  const lastAttemptAt = now - 1;

  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("stale", { effectiveTargetHeight: 339_930, lagBlocks: 3 }),
      lastAttemptAt,
      null,
      now
    ),
    lastAttemptAt + AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS
  );
  assert.equal(
    nextAutomaticHeaderSyncAttemptAt(
      status("unknown"),
      lastAttemptAt,
      null,
      now
    ),
    lastAttemptAt + AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS
  );
});

test("automatic maintenance enforces a ten-minute attempt floor", () => {
  const now = 2_000_000;
  assert.equal(AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS, 600_000);
  assert.equal(automaticHeaderSyncAllowed(null, now), true);
  assert.equal(
    automaticHeaderSyncAllowed(
      now - AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS + 1,
      now
    ),
    false
  );
  assert.equal(
    automaticHeaderSyncAllowed(
      now - AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS,
      now
    ),
    true
  );
  assert.equal(automaticHeaderSyncAllowed(now + 1, now), true);
  assert.equal(nextAutomaticHeaderSyncAllowedAt(null, now), now);
  assert.equal(
    nextAutomaticHeaderSyncAllowedAt(
      now - AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS + 1,
      now
    ),
    now + 1
  );
  assert.equal(nextAutomaticHeaderSyncAllowedAt(now + 1, now), now);
});
