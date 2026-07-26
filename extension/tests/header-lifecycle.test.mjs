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
  assert.match(worker, /case "syncHeadersNow":\s*\n\s*return synchronizeHeaders\(\)/);
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
});

test("maintenance reads local status, checks authoritative freshness, and rate limits attempts", () => {
  assert.match(worker, /const HEADER_SYNC_ALARM = "hns-header-sync"/);
  assert.match(worker, /HEADER_SYNC_PERIOD_MINUTES/);
  assert.match(
    worker,
    /const status = refreshStatus \? await refreshNativeStatus\(\) : publicStatus/
  );
  assert.match(worker, /needsAutomaticHeaderSync\(status\.headerSync\)/);
  assert.match(worker, /automaticHeaderSyncAllowed\(lastAttemptAt\)/);
  assert.match(worker, /headerSyncLastAttemptAt/);
});

test("status requests do not queue behind sync and sync failure leaves the PAC active", () => {
  assert.match(
    worker,
    /async function refreshNativeStatus\(\) \{[\s\S]*?if \(headerSyncOperation\) return publicStatus;[\s\S]*?client\.request\("status"\)/
  );
  const synchronization = worker.match(
    /function synchronizeHeaders\(\) \{[\s\S]*?\n\}\n\nasync function loadLastHeaderSyncAttempt/
  )?.[0];
  assert.ok(synchronization, "synchronizeHeaders function");
  assert.doesNotMatch(synchronization, /clearProxy|client\.disconnect/);
  assert.match(synchronization, /headerSyncError: boundedError\(error\)/);
});
