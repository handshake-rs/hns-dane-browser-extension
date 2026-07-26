import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const worker = readFileSync("extension/src/service-worker.js", "utf8");
const buildScript = readFileSync("extension/scripts/build.mjs", "utf8");

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

test("the unpacked Chromium build carries the generated dependency notices", () => {
  assert.match(
    buildScript,
    /extension\/THIRD_PARTY_NOTICES\.txt[\s\S]*output.*THIRD_PARTY_NOTICES\.txt/
  );
});
