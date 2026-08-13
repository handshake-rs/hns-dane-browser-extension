import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const popup = readFileSync("extension/src/popup.html", "utf8");
const popupScript = readFileSync("extension/src/popup.js", "utf8");
const worker = readFileSync("extension/src/service-worker.js", "utf8");

test("popup wallet readiness is display-only and has no wallet actions", () => {
  for (const id of [
    "wallet-detail",
    "wallet-artifact",
    "wallet-release",
    "wallet-service",
    "wallet-lock-state",
    "wallet-active",
    "wallet-modules",
    "wallet-provider",
    "wallet-value"
  ]) {
    assert.match(popup, new RegExp(`id=["']${id}["']`), id);
    assert.match(
      popupScript,
      new RegExp(`querySelector\\(["']#${id}["']\\)`),
      id
    );
  }
  assert.match(popupScript, /walletReadinessView\(walletAbi\)/);
  assert.doesNotMatch(popup, /<button[^>]+(?:wallet|unlock|send|receive)/i);
  assert.doesNotMatch(
    popupScript,
    /walletProvider(?:Initialize|Request)|unlockWallet|sendTransaction/
  );
});

test("service worker publishes only sanitized wallet admission status", () => {
  assert.match(worker, /walletAbi: unavailableWalletAbiStatus\(\)/);
  assert.match(
    worker,
    /walletAbi: unavailableWalletAbiStatus\("walletStatusChecking"\)/
  );
  assert.match(
    worker,
    /walletAbi: unavailableWalletAbiStatus\("walletNativeHostDisconnected"\)/
  );
  assert.match(worker, /projectWalletAbiStatus\(hello\?\.walletAbi\)/);
  assert.match(worker, /projectWalletAbiStatus\(result\.walletAbi\)/);
  assert.match(worker, /projectWalletAbiStatus\(activationStatus\.walletAbi\)/);
  assert.doesNotMatch(worker, /client\.request\("walletReadOnlyStatus"/);
});

test("controlled activation failure clears adopted wallet readiness", () => {
  const startup = worker.match(
    /async function startRuntime\(policyOverride\) \{[\s\S]*?\n\}\n\nasync function establishStartupHeaderReadiness/
  )?.[0];
  assert.ok(startup, "startRuntime implementation");

  const disconnect = startup.indexOf(
    "client.disconnectIfCurrent(activationConnectionEpoch)"
  );
  const reset = startup.indexOf(
    'const disconnectedWalletAbi = unavailableWalletAbiStatus('
  );
  const classifyFailure = startup.indexOf("const localCaRequired =");

  assert.ok(disconnect >= 0, "controlled native disconnect");
  assert.ok(reset > disconnect, "wallet readiness reset follows disconnect");
  assert.ok(
    classifyFailure > reset,
    "wallet readiness resets before activation failures are classified"
  );
  assert.equal(
    startup.match(/walletAbi: disconnectedWalletAbi/g)?.length,
    3,
    "every post-disconnect activation failure publishes unavailable readiness"
  );
});
