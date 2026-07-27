import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const worker = readFileSync("extension/src/service-worker.js", "utf8");
const buildScript = readFileSync("extension/scripts/build.mjs", "utf8");
const options = readFileSync("extension/src/options.html", "utf8");
const optionsScript = readFileSync("extension/src/options.js", "utf8");
const popup = readFileSync("extension/src/popup.html", "utf8");

test("manifest is MV3 with native messaging, mandatory proxy, and auth permissions", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "src/service-worker.js");
  assert.equal(manifest.background.type, "module");
  for (const permission of [
    "nativeMessaging",
    "proxy",
    "storage",
    "webRequest",
    "webRequestAuthProvider"
  ]) {
    assert.ok(manifest.permissions.includes(permission), permission);
  }
});

test("service worker installs only Rust-generated mandatory PAC and fails closed without CA", () => {
  assert.match(worker, /mandatory:\s*true/);
  assert.match(worker, /result\.ca\.state !== "installed"/);
  assert.match(worker, /client\.request\("stop"\)/);
  assert.doesNotMatch(worker, /dnsResolve\s*\(/);
  assert.doesNotMatch(worker, /sha(?:1|256|512)/i);
  assert.doesNotMatch(worker, /route.*record/i);
});

test("health checks preserve a live generation and reconnect only after failure", () => {
  assert.match(
    worker,
    /alarm\.name === HEALTH_ALARM\)[\s\S]*?refreshNativeStatus\(\)[\s\S]*?alarm\.name === RECONNECT_ALARM\)[\s\S]*?recover\(\)/
  );
  assert.doesNotMatch(
    worker,
    /alarm\.name === HEALTH_ALARM \|\| alarm\.name === RECONNECT_ALARM/
  );
});

test("a rejected native policy is never persisted", () => {
  const setPolicyCase = worker.match(
    /case "setPolicy": \{[\s\S]*?\n    \}\n    case "diagnostics":/
  )?.[0];
  assert.ok(setPolicyCase, "setPolicy handler");
  assert.ok(
    setPolicyCase.indexOf("await startRuntime(policy)") <
      setPolicyCase.indexOf("await storageSet({ policy })"),
    "native activation must succeed before persistent storage changes"
  );
});

test("interception recovery controls are explicit, clearable, and privacy-disclosed", () => {
  assert.match(options, /id="recursive-hns-doh-url"/);
  assert.match(options, /placeholder="https:\/\/hnsdoh\.com\/dns-query"/);
  assert.doesNotMatch(options, /value="https:\/\/hnsdoh\.com\/dns-query"/);
  assert.match(options, /qnames and qtypes/);
  assert.match(options, /source IP/);
  assert.match(options, /sends nothing[\s\S]*field is blank/);
  assert.match(options, /requester-only/);
  assert.match(options, /DNSSEC and DANE[\s\S]*verified locally/);
  assert.match(optionsScript, /clear-recursive-hns-doh[\s\S]*value = ""/);
  assert.match(popup, /requester-only P2P DNS relay/);
  assert.match(popup, /explicit recursive HNS DoH recovery URL/);
});

test("latest main-frame security details precede the complete header-chain panel", () => {
  const latestMainFrame = popup.indexOf("<h2>Latest browser main frame</h2>");
  const headerChain = popup.indexOf("<h2>Header chain</h2>");
  const retry = popup.indexOf('id="retry"');
  const recoveryGuidance = popup.indexOf("Network intercepting port 53?");
  const syncHeaders = popup.indexOf('id="sync-headers"');

  assert.ok(latestMainFrame >= 0, "latest main-frame section");
  assert.ok(retry > latestMainFrame, "main-frame actions follow page status");
  assert.ok(recoveryGuidance > retry, "recovery guidance stays with page status");
  assert.ok(headerChain > recoveryGuidance, "header-chain section is the final panel");
  assert.ok(syncHeaders > headerChain, "header sync control stays inside the lower section");
});

test("the unpacked Chromium build carries the generated dependency notices", () => {
  assert.match(
    buildScript,
    /extension\/THIRD_PARTY_NOTICES\.txt[\s\S]*output.*THIRD_PARTY_NOTICES\.txt/
  );
});
