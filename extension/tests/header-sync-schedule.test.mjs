import test from "node:test";
import assert from "node:assert/strict";
import {
  AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS,
  automaticHeaderSyncAllowed,
  needsAutomaticHeaderSync
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
    targetSource: freshness === "unknown" ? "unknown" : "corroboratedPeers",
    targetPeerGroups: freshness === "unknown" ? 0 : 3,
    targetEvidenceExpired: freshness === "unknown",
    ...overrides
  };
}

test("automatic maintenance syncs only stale, unknown, or expired target state", () => {
  assert.equal(needsAutomaticHeaderSync(status("current")), false);
  assert.equal(
    needsAutomaticHeaderSync(
      status("stale", { effectiveTargetHeight: 339_930, lagBlocks: 3 })
    ),
    true
  );
  assert.equal(needsAutomaticHeaderSync(status("unknown")), true);
  assert.equal(
    needsAutomaticHeaderSync(status("current", { targetEvidenceExpired: true })),
    true
  );
  assert.equal(needsAutomaticHeaderSync(null), true);
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
  assert.equal(automaticHeaderSyncAllowed(now + 1, now), false);
});
