import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const worker = readFileSync("extension/src/service-worker.js", "utf8");
const buildScript = readFileSync("extension/scripts/build.mjs", "utf8");
const options = readFileSync("extension/src/options.html", "utf8");
const optionsScript = readFileSync("extension/src/options.js", "utf8");
const popup = readFileSync("extension/src/popup.html", "utf8");
const popupScript = readFileSync("extension/src/popup.js", "utf8");
const setup = readFileSync("extension/src/setup.html", "utf8");
const setupScript = readFileSync("extension/src/setup.js", "utf8");

test("manifest is MV3 with native messaging, mandatory proxy, and auth permissions", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "src/service-worker.js");
  assert.equal(manifest.background.type, "module");
  for (const permission of [
    "nativeMessaging",
    "proxy",
    "storage",
    "webNavigation",
    "webRequest",
    "webRequestAuthProvider"
  ]) {
    assert.ok(manifest.permissions.includes(permission), permission);
  }
  for (const size of ["16", "32", "48", "128"]) {
    assert.equal(manifest.icons[size], `assets/icons/icon-${size}.png`);
    assert.equal(
      manifest.action.default_icon[size],
      `assets/icons/icon-${size}.png`
    );
    assert.ok(existsSync(`extension/assets/icons/icon-${size}.png`), size);
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
    /alarm\.name === HEALTH_ALARM\)[\s\S]*?maintainHeaderFreshness\(true\)[\s\S]*?alarm\.name === RECONNECT_ALARM\)[\s\S]*?recover\(\)/
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

test("popup security status is scoped to the active Chromium tab", () => {
  assert.match(popupScript, /chrome\.tabs\.query\(\{ active: true, currentWindow: true \}\)/);
  assert.match(
    popupScript,
    /type: "getStatus",[\s\S]*?tabId: await activeTabId\(\)/
  );
  assert.match(worker, /store\.receiptForTab\(validTabId, status\)/);
  assert.match(worker, /latestMainFrameSecurity: scoped\.receipt/);
  assert.match(
    worker,
    /latestMainFrameConnectDecisionReceipt: scoped\.connectDecisionReceipt/
  );
  assert.match(worker, /chrome\.storage\.session\.set/);
  assert.match(worker, /store\.beginMaintenance\(publicStatus\)/);
  assert.match(worker, /securityMaintenanceEpoch/);
  assert.match(
    worker,
    /captureCompletedMainFrame[\s\S]*?await refreshNativeStatus\(\)[\s\S]*?store\.completeRequest\(details, status\)/
  );
  assert.match(popup, /id="security-receipt-source"/);
  assert.match(popupScript, /Chromium owns end-to-end WebPKI for this document/);
});

test("the unpacked Chromium build carries the generated dependency notices", () => {
  assert.match(
    buildScript,
    /extension\/THIRD_PARTY_NOTICES\.txt[\s\S]*output.*THIRD_PARTY_NOTICES\.txt/
  );
  assert.match(buildScript, /cpSync\("LICENSE", `\$\{output\}\/LICENSE`\)/);
  assert.match(
    buildScript,
    /docs\/privacy-policy\.md[\s\S]*output.*PRIVACY\.md/
  );
  assert.match(buildScript, /sourceRepository/);
  assert.match(buildScript, /github\.com\/sponsors\/denuoweb/);
});

test("first install opens a complete bundled Setup flow and project disclosure", () => {
  assert.match(
    worker,
    /details\.reason === "install"[\s\S]*?chrome\.runtime\.getURL\("src\/setup\.html"\)/
  );
  assert.match(setup, /matching local Rust native host/);
  assert.match(setup, /HNS DANE Browser Setup/);
  assert.match(setup, /contains the matching Rust native host/);
  assert.match(setup, /non-system runtime dependencies/);
  assert.match(setup, /Copy extension ID/);
  assert.match(setup, /select every Chromium flavor/);
  assert.match(setup, /Complete Uninstall/);
  assert.match(setup, /per-user local CA/);
  assert.match(setup, /releases\/latest/);
  assert.match(setup, /handshake-rs\/hns-dane-browser-extension/);
  assert.match(setup, /blob\/main\/LICENSE/);
  assert.match(setup, /blob\/main\/docs\/privacy-policy\.md/);
  assert.match(setup, /github\.com\/sponsors\/denuoweb/);
  assert.match(setup, /Donations do not unlock features/);
  assert.match(setup, /ChromeOS and mobile Chromium do not/);
  assert.match(setupScript, /\^\[a-p\]\{32\}\$/);
  assert.match(setupScript, /runtime\?\.getManifest\?\.\(\)/);
  assert.match(setupScript, /navigator\.clipboard\.writeText\(extensionId\)/);
  assert.match(
    setupScript,
    /releases\/tag\/v\$\{extensionVersion\}/
  );
  assert.match(setup, /Manual native-host packages/);
  assert.match(setup, /Latest release \(fallback only\)/);
  assert.match(popup, /id="setup"/);
  assert.match(popupScript, /src\/setup\.html/);
});
