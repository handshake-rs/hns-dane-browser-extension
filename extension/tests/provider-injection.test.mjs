import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const inpage = readFileSync("extension/src/provider-inpage.js", "utf8");
const bridge = readFileSync("extension/src/provider-content-bridge.js", "utf8");
const worker = readFileSync("extension/src/service-worker.js", "utf8");

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
});
