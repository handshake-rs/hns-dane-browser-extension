import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const inpage = readFileSync("extension/src/provider-inpage.js", "utf8");
const bridge = readFileSync("extension/src/provider-content-bridge.js", "utf8");
const worker = readFileSync("extension/src/service-worker.js", "utf8");
const router = readFileSync("extension/src/wallet-provider-router.js", "utf8");

test("MV3 bridge starts at document start and MAIN-world provider is authority gated", () => {
  assert.ok(manifest.permissions.includes("scripting"));
  assert.deepEqual(manifest.content_scripts, [
    {
      matches: ["https://*/*"],
      js: ["src/provider-content-bridge.js"],
      run_at: "document_start",
      all_frames: false
    }
  ]);
  assert.match(worker, /providerAuthorityForDocument/);
  assert.match(worker, /walletProviderCapabilities/);
  assert.match(worker, /documentIds: \[sender\.documentId\]/);
  assert.match(worker, /world: "MAIN"/);
  assert.match(worker, /walletProviderBootstrapReady/);
  assert.match(worker, /notifyWalletProviderBootstrap\(details\)/);
  assert.match(bridge, /MAX_INITIALIZE_RETRIES/);
  assert.match(bridge, /boundedJson\(value\)/);
  assert.ok(
    worker.indexOf("await walletProviderRouter.initialize") <
      worker.indexOf("chrome.scripting.executeScript"),
    "native capability and browser authority precede MAIN-world injection"
  );
});

test("discovery is event based, Handshake-specific, and never installs Ethereum globals", () => {
  assert.match(inpage, /hns:requestProvider/);
  assert.match(inpage, /hns:announceProvider/);
  assert.match(inpage, /request\(args\)/);
  assert.match(inpage, /removeListener\(event, listener\)/);
  assert.doesNotMatch(inpage, /window\.ethereum/);
  assert.doesNotMatch(inpage, /private.?key|seed|mnemonic/i);
});

test("isolated bridge binds messages to the same window and exact origin", () => {
  assert.match(bridge, /event\.source !== window/);
  assert.match(bridge, /event\.origin !== location\.origin/);
  assert.match(bridge, /origin: location\.origin/);
  assert.match(bridge, /sameBinding\(message\.binding, binding\)/);
  assert.match(bridge, /pending\.size >= MAX_PENDING/);
  assert.match(bridge, /message\.type === "walletProviderInvalidate"/);
  assert.match(bridge, /binding = null;\s*}\s*postToPage\(/);
  assert.doesNotMatch(
    bridge,
    /staleContext[\s\S]{0,300}await initialize\(\)/,
    "a stale response must be returned without retrying a possibly-mutating request"
  );
});

test("header maintenance invalidates wallet authority before native synchronization", () => {
  const synchronization = worker.indexOf("function synchronizeHeaders()");
  const invalidate = worker.indexOf(
    "walletProviderRouter.invalidateAuthority()",
    synchronization
  );
  const invalidateApprovals = worker.indexOf(
    'invalidateAllWalletApprovals("headerMaintenanceStarted")',
    synchronization
  );
  const beginMaintenance = worker.indexOf(
    "store.beginMaintenance(publicStatus)",
    synchronization
  );
  const nativeSync = worker.indexOf('"syncOnce"', beginMaintenance);
  assert.ok(synchronization >= 0);
  assert.ok(invalidate > synchronization && invalidate < beginMaintenance);
  assert.ok(
    invalidateApprovals > synchronization && invalidateApprovals < beginMaintenance
  );
  assert.ok(beginMaintenance < nativeSync);
  assert.match(
    router,
    /await this\.nativeRequest\("walletProviderRequest"[\s\S]*await this\.revalidateOperation/
  );
  assert.match(worker, /completeApproval\(dispatch, result\)/);
});
