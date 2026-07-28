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

test("worker delegates lifecycle races to the executable controls", () => {
  assert.match(worker, /new SerializedMandatoryPacController\(/);
  assert.match(worker, /new SerializedEpochMutationController\(/);
  assert.match(worker, /runtimeControlToken\(/);
  assert.match(worker, /runtimeControlTokenIsCurrent\(/);
  assert.match(worker, /headerSyncReadyForProxyActivation\(/);
  assert.match(worker, /headerSyncRefreshError\(/);
  assert.match(worker, /deactivateIfHeaderEvidenceExpired\(/);
  assert.match(worker, /client\.disconnectIfCurrent\(/);
  assert.match(worker, /chrome\.proxy\.settings\.get/);
  assert.match(worker, /createAlarmForControl\(\s*HEADER_SYNC_DEADLINE_ALARM/);
  assert.match(worker, /createAlarmForControl\(\s*HEADER_EVIDENCE_EXPIRY_ALARM/);
  assert.match(
    worker,
    /const maintenanceControl = captureHeaderMaintenanceControl\(\)/
  );
  assert.match(
    worker,
    /await loadLastHeaderSyncAttempt\(\);[\s\S]{0,120}requireHeaderMaintenanceControl\(maintenanceControl\)/
  );
  assert.match(
    worker,
    /async function scheduleHeaderSyncRetry\([\s\S]{0,180}expectedRuntimeControl[\s\S]*?scheduleHeaderSyncDeadline\([\s\S]{0,180}expectedRuntimeControl\.controlEpoch/
  );
  assert.doesNotMatch(worker, /proxy\.settings\.clear/);
});
