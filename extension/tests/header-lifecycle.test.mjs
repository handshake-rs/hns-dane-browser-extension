import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const popup = readFileSync("extension/src/popup.html", "utf8");
const worker = readFileSync("extension/src/service-worker.js", "utf8");

test("popup distinguishes the global header tip from the page proof anchor", () => {
  for (const label of [
    "Validated header tip",
    "Highest peer claim",
    "Schedule estimate",
    "Corroborated target",
    "Target peer groups",
    "Currentness limit",
    "Page proof anchor"
  ]) {
    assert.match(popup, new RegExp(label));
  }
  assert.match(popup, /id="sync-headers"[^>]*>Sync headers now</);
});

test("manual and automatic header sync share one bounded native operation", () => {
  assert.match(
    worker,
    /case "syncHeadersNow": \{[\s\S]*?await synchronizeHeaders\(\)[\s\S]*?statusForTab\(status, message\.tabId\)/
  );
  assert.match(
    worker,
    /function synchronizeHeaders\(\) \{\s*if \(headerSyncOperation\) return headerSyncOperation;/
  );
  assert.match(
    worker,
    /client\.request\(\s*"syncOnce",\s*\{\},\s*\{ timeoutMs: MAX_REQUEST_TIMEOUT_MS \}/
  );
});

test("runtime lifecycle rejects legacy native status without authoritative freshness", () => {
  assert.match(worker, /validateStartResult[\s\S]*?!validHeaderSyncEnvelope\(result\)/);
  assert.match(worker, /validateStatusResult[\s\S]*?!validHeaderSyncEnvelope\(result\)/);
  assert.match(
    worker,
    /validateStartResult[\s\S]*?result\.securityMaintenanceEpoch[\s\S]*?result\.recentConnectSecurityDecisions/
  );
  assert.match(
    worker,
    /validateStatusResult[\s\S]*?result\.securityMaintenanceEpoch[\s\S]*?result\.recentConnectSecurityDecisions/
  );
});

test("maintenance refreshes before evidence expiry with bounded urgent retries", () => {
  assert.match(
    worker,
    /const HEADER_SYNC_DEADLINE_ALARM = "hns-header-sync-deadline"/
  );
  assert.match(
    worker,
    /const status = refreshStatus \? await refreshNativeStatus\(\) : publicStatus/
  );
  assert.match(worker, /needsAutomaticHeaderSync\(status\.headerSync\)/);
  assert.match(worker, /nextAutomaticHeaderSyncAttemptAt\(/);
  assert.match(worker, /headerSyncUrgentRetryWindow\(attemptedAgainst\)/);
  assert.match(worker, /headerSyncUrgentRetryWindow/);
  assert.match(worker, /automaticHeaderSyncDueAt\(candidate\)/);
  assert.match(
    worker,
    /const lastAttemptAt = await loadLastHeaderSyncAttempt\(\);[\s\S]*?const retainedUrgentWindow =\s*await loadRetainedHeaderSyncUrgentRetryWindow\(\);[\s\S]*?nextAutomaticHeaderSyncAttemptAt\(\s*status\.headerSync,\s*lastAttemptAt,\s*retainedUrgentWindow/
  );
  assert.match(
    worker,
    /chrome\.alarms\.create\(HEADER_SYNC_DEADLINE_ALARM, \{\s*when:/
  );
  assert.match(
    worker,
    /alarm\.name === HEALTH_ALARM[\s\S]*?maintainHeaderFreshness\(true\)/
  );
  assert.match(worker, /chrome\.alarms\.clear\(LEGACY_HEADER_SYNC_ALARM\)/);
  assert.doesNotMatch(worker, /HEADER_SYNC_PERIOD_MINUTES/);
  assert.match(worker, /headerSyncLastAttemptAt/);
  assert.match(worker, /headerSyncUrgentRetryWindow/);
  assert.match(worker, /clearSupersededHeaderSyncUrgentRetryWindow/);
  const suspendHandler = worker.match(
    /chrome\.runtime\.onSuspend\.addListener\(\(\) => \{[\s\S]*?\n\}\);/
  )?.[0];
  assert.ok(suspendHandler, "suspend handler");
  assert.doesNotMatch(suspendHandler, /HEADER_SYNC_DEADLINE_ALARM/);
  const disconnectHandler = worker.match(
    /client\.onDisconnect\(\(\) => \{[\s\S]*?\n\}\);/
  )?.[0];
  assert.ok(disconnectHandler, "native disconnect handler");
  assert.doesNotMatch(disconnectHandler, /HEADER_SYNC_DEADLINE_ALARM/);
});

test("status requests do not queue behind sync and sync failure leaves the PAC active", () => {
  assert.match(
    worker,
    /async function refreshNativeStatus\(allowDuringHeaderSync = false\) \{[\s\S]*?if \(headerSyncOperation && !allowDuringHeaderSync\) return publicStatus;[\s\S]*?client\.request\("status"\)/
  );
  const synchronization = worker.match(
    /function synchronizeHeaders\(\) \{[\s\S]*?\n\}\n\nasync function scheduleHeaderSyncRetry/
  )?.[0];
  assert.ok(synchronization, "synchronizeHeaders function");
  assert.doesNotMatch(synchronization, /clearProxy|client\.disconnect/);
  assert.match(synchronization, /await refreshNativeStatus\(true\)/);
  assert.match(synchronization, /store\.ensureRuntime\(authoritativeStatus\)/);
  assert.match(synchronization, /headerSyncError: boundedError\(syncError\)/);
  assert.match(synchronization, /scheduleHeaderSyncRetry\(/);
  assert.match(
    worker,
    /rememberHeaderSyncUrgentRetryWindow[\s\S]*?try \{[\s\S]*?await storageSet[\s\S]*?catch \{/
  );
  assert.match(
    worker,
    /scheduleHeaderSyncRetry[\s\S]*?scheduleHeaderSyncDeadline\(/
  );
});
