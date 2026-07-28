import test from "node:test";
import assert from "node:assert/strict";
import {
  authoritativeHeaderSync,
  currentHeaderSync,
  headerChainView,
  headerSyncRefreshError,
  headerSyncReadyForProxyActivation,
  pageProofAnchor,
  validHeaderSyncEnvelope
} from "../src/header-status.js";

function headerSync(overrides = {}) {
  return {
    network: "mainnet",
    status: "up_to_date",
    attempted: 3,
    successful: 3,
    accepted: 3,
    failed: 0,
    failures: [],
    bestHeight: 339_927,
    bestPeerHeight: 339_929,
    estimatedTipHeight: 339_930,
    effectiveTargetHeight: 339_929,
    lagBlocks: 2,
    freshness: "current",
    freshnessThresholdBlocks: 2,
    targetSource: "corroboratedPeers",
    targetPeerGroups: 3,
    targetEvidenceExpired: false,
    targetEvidenceValidUntilUnix: 1_753_400_000,
    error: null,
    ...overrides
  };
}

test("header UI distinguishes validated, untrusted, estimated, and corroborated heights", () => {
  const view = headerChainView(headerSync());

  assert.equal(view.bestHeight, "#339,927");
  assert.equal(view.peerHeight, "#339,929");
  assert.equal(view.estimatedHeight, "#339,930");
  assert.equal(view.targetHeight, "#339,929");
  assert.equal(view.targetPeerGroups, "3");
  assert.equal(view.lag, "2 blocks");
  assert.equal(view.threshold, "2 blocks");
  assert.equal(view.state, "Current");
  assert.match(view.detail, /corroborated peer target/);
  assert.match(view.detail, /diagnostic only/);
});

test("header UI uses authoritative freshness and exposes active synchronization", () => {
  const stale = headerChainView(
    headerSync({
      status: "syncing",
      bestHeight: 339_925,
      lagBlocks: 4,
      freshness: "stale"
    })
  );
  assert.equal(stale.state, "Stale");
  assert.match(stale.detail, /4 blocks behind/);

  const syncing = headerChainView(headerSync(), { syncing: true });
  assert.equal(syncing.state, "Syncing");
  assert.match(syncing.detail, /Synchronizing validated headers/);
});

test("raw peer claims and schedule estimates never synthesize authoritative freshness", () => {
  const legacy = headerSync();
  delete legacy.effectiveTargetHeight;
  delete legacy.lagBlocks;
  delete legacy.freshness;
  delete legacy.freshnessThresholdBlocks;
  delete legacy.targetSource;

  assert.equal(currentHeaderSync(legacy), legacy);
  assert.equal(authoritativeHeaderSync(legacy), null);
  const view = headerChainView(legacy);
  assert.equal(view.peerHeight, "#339,929");
  assert.equal(view.estimatedHeight, "#339,930");
  assert.equal(view.targetHeight, "—");
  assert.equal(view.lag, "—");
  assert.equal(view.state, "Unknown");
  assert.match(view.detail, /diagnostic only/);
});

test("header UI rejects inconsistent freshness and keeps page proof anchors separate", () => {
  assert.equal(
    currentHeaderSync(headerSync({ freshness: "current", lagBlocks: 3 })),
    null
  );
  assert.equal(
    currentHeaderSync(headerSync({ targetSource: "highestPeerClaim" })),
    null
  );
  assert.equal(
    pageProofAnchor({ chainAnchor: { localBestHeight: 339_915 } }),
    "#339,915"
  );
  assert.equal(pageProofAnchor({ chainAnchor: { localBestHeight: -1 } }), "—");
});

test("unknown freshness requires an unconfirmed target and lag", () => {
  const unknown = headerSync({
    effectiveTargetHeight: null,
    lagBlocks: null,
    freshness: "unknown",
    targetSource: "unknown",
    targetEvidenceValidUntilUnix: null
  });

  assert.equal(currentHeaderSync(unknown), unknown);
  const view = headerChainView(unknown);
  assert.equal(view.targetHeight, "—");
  assert.equal(view.lag, "—");
  assert.equal(view.state, "Unknown");
});

test("native lifecycle envelope rejects old hosts without authoritative freshness", () => {
  const legacy = headerSync();
  delete legacy.effectiveTargetHeight;
  delete legacy.lagBlocks;
  delete legacy.freshness;
  delete legacy.freshnessThresholdBlocks;
  delete legacy.targetSource;
  delete legacy.targetPeerGroups;
  delete legacy.targetEvidenceExpired;
  delete legacy.targetEvidenceValidUntilUnix;

  assert.equal(validHeaderSyncEnvelope({ headerSync: legacy }), false);
  assert.equal(validHeaderSyncEnvelope({}), false);
  assert.equal(validHeaderSyncEnvelope({ headerSync: headerSync() }), true);
  assert.equal(
    validHeaderSyncEnvelope({
      headerSync: null,
      headerSyncUnavailableReason: "headerSyncStatusUnavailable"
    }),
    true
  );
});

test("native lifecycle rejects weak freshness policy or insufficient corroboration", () => {
  assert.equal(
    authoritativeHeaderSync(headerSync({ freshnessThresholdBlocks: 144 })),
    null
  );
  assert.equal(
    authoritativeHeaderSync(headerSync({ targetPeerGroups: 2 })),
    null
  );
  assert.equal(
    authoritativeHeaderSync(
      headerSync({ targetEvidenceValidUntilUnix: null })
    ),
    null
  );
  const oldNative = headerSync();
  delete oldNative.targetEvidenceValidUntilUnix;
  assert.equal(authoritativeHeaderSync(oldNative), null);
  assert.equal(
    authoritativeHeaderSync(
      headerSync({
        bestHeight: 0,
        effectiveTargetHeight: 0,
        lagBlocks: 0
      })
    ),
    null
  );
  assert.equal(
    validHeaderSyncEnvelope({
      headerSync: headerSync({ freshnessThresholdBlocks: 144 })
    }),
    false
  );
  assert.equal(
    validHeaderSyncEnvelope({
      headerSync: headerSync({ targetPeerGroups: 2 })
    }),
    false
  );
});

test("proxy activation requires current target evidence beyond the current second", () => {
  const now = 1_753_399_900;
  assert.equal(headerSyncReadyForProxyActivation(headerSync(), now), true);
  assert.equal(
    headerSyncReadyForProxyActivation(
      headerSync({ targetEvidenceValidUntilUnix: now }),
      now
    ),
    false
  );
  assert.equal(
    headerSyncReadyForProxyActivation(
      headerSync({
        bestHeight: 339_925,
        lagBlocks: 4,
        freshness: "stale"
      }),
      now
    ),
    false
  );
  assert.equal(
    headerSyncReadyForProxyActivation(
      headerSync({
        effectiveTargetHeight: null,
        lagBlocks: null,
        freshness: "unknown",
        targetSource: "unknown",
        targetPeerGroups: 0,
        targetEvidenceExpired: true,
        targetEvidenceValidUntilUnix: null
      }),
      now
    ),
    false
  );
  assert.equal(
    headerSyncReadyForProxyActivation(headerSync(), Number.NaN),
    false
  );
});

test("explicit sync rejects peer-failed and zero-success result envelopes", () => {
  assert.equal(headerSyncRefreshError(headerSync()), null);
  assert.equal(
    headerSyncRefreshError(
      headerSync({
        status: "coalesced",
        attempted: 0,
        successful: 0,
        accepted: 0,
        failed: 0,
        failures: []
      })
    ),
    null
  );
  assert.equal(
    headerSyncRefreshError(
      headerSync({
        status: "syncing",
        attempted: 3,
        successful: 2
      })
    ),
    null
  );
  assert.equal(
    headerSyncRefreshError(
      headerSync({
        status: "coalesced",
        attempted: 1,
        successful: 1,
        accepted: 1,
        failed: 0,
        failures: []
      })
    ),
    "native host returned invalid coalesced header sync envelope"
  );
  for (const invalid of [
    { accepted: 1 },
    { failed: 1 },
    { failures: [{ address: "peer" }] },
    { failures: null }
  ]) {
    assert.equal(
      headerSyncRefreshError(
        headerSync({
          status: "coalesced",
          attempted: 0,
          successful: 0,
          accepted: 0,
          failed: 0,
          failures: [],
          ...invalid
        })
      ),
      "native host returned invalid coalesced header sync envelope"
    );
  }
  assert.equal(
    headerSyncRefreshError(
      headerSync({
        status: "coalesced",
        attempted: 0,
        successful: 0,
        accepted: 0,
        failed: 0,
        failures: [],
        error: "coalesced refresh failed"
      })
    ),
    "coalesced refresh failed"
  );
  assert.equal(
    headerSyncRefreshError(
      headerSync({
        status: "peer_failed",
        attempted: 3,
        successful: 0,
        error: "all attempted sync peers failed"
      })
    ),
    "all attempted sync peers failed"
  );
  assert.equal(
    headerSyncRefreshError(
      headerSync({
        attempted: 3,
        successful: 0
      })
    ),
    "header synchronization completed without a successful peer"
  );
  assert.equal(
    headerSyncRefreshError(
      headerSync({
        status: "seed_failed",
        attempted: 0,
        successful: 0
      })
    ),
    "header synchronization reported seed_failed"
  );
});
