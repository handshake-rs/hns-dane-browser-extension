import test from "node:test";
import assert from "node:assert/strict";
import {
  FORBIDDEN_WALLET_METHODS,
  WALLET_NATIVE_ABI_VERSION,
  WALLET_PROVIDER_EVENTS,
  WALLET_PROVIDER_METHODS,
  validateNativeCapabilities,
  validateNativeResult,
  validatePageRequest,
  validateProviderEvent
} from "../src/wallet-provider-protocol.js";

test("the Handshake provider exposes the complete narrow method and event surface", () => {
  assert.equal(WALLET_PROVIDER_METHODS.length, 43);
  assert.deepEqual(WALLET_PROVIDER_METHODS.slice(0, 9), [
    "wallet_getCapabilities",
    "wallet_getEnabledModules",
    "wallet_enableModule",
    "wallet_disableModule",
    "wallet_requestPermissions",
    "wallet_getPermissions",
    "wallet_revokePermissions",
    "wallet_lock",
    "wallet_getStatus"
  ]);
  assert.ok(WALLET_PROVIDER_METHODS.includes("nameMarket_createFixedPriceOffer"));
  assert.ok(WALLET_PROVIDER_METHODS.includes("swap_refund"));
  assert.equal(WALLET_PROVIDER_EVENTS.length, 13);
  assert.ok(WALLET_PROVIDER_EVENTS.includes("walletLocked"));
});

test("native results and events reject secret-bearing fields", () => {
  assert.throws(
    () => validateNativeResult({ account: "hs1qpublic", privateKey: "secret" }),
    (error) => error.code === "invalidResult"
  );
  assert.throws(
    () => validateProviderEvent({
      event: "accountsChanged",
      payload: { recovery_phrase: "secret words" }
    }),
    (error) => error.code === "invalidResult"
  );
  assert.throws(
    () => validateNativeResult({ authorityHandle: "opaque-private-handle" }),
    (error) => error.code === "invalidResult"
  );
  assert.throws(
    () => validateProviderEvent({
      event: "walletLocked",
      payload: { authority_revision: 7 }
    }),
    (error) => error.code === "invalidResult"
  );
  assert.throws(
    () => validateProviderEvent({
      event: "walletLocked",
      authorityHandle: "opaque-private-handle",
      payload: null
    }),
    (error) => error.code === "invalidResult"
  );
});

test("generic Ethereum and Bitcoin signer methods are explicitly forbidden", () => {
  for (const method of FORBIDDEN_WALLET_METHODS) {
    assert.throws(
      () => validatePageRequest(request(method, {})),
      (error) => error.code === "forbiddenMethod"
    );
  }
});

test("external asset calls require one of the two audited modules", () => {
  assert.equal(
    validatePageRequest(request("asset_getBalance", { module: "bitcoin" })).method,
    "asset_getBalance"
  );
  assert.throws(
    () => validatePageRequest(request("asset_send", { module: "arbitrary-chain" })),
    (error) => error.code === "invalidParams"
  );
  assert.throws(
    () => validatePageRequest(request("wallet_getStatus", { discloseSeed: true })),
    (error) => error.code === "invalidParams"
  );
});

test("provider frames reject unsafe numbers, prototype keys, depth, and size", () => {
  assert.throws(
    () => validatePageRequest(request("hns_send", { amount: 0.1 })),
    (error) => error.code === "invalidRequest"
  );
  assert.throws(
    () =>
      validatePageRequest(
        request("hns_send", JSON.parse('{"__proto__":{"admin":true}}'))
      ),
    (error) => error.code === "invalidRequest"
  );
  let nested = { value: "1" };
  for (let index = 0; index < 14; index += 1) nested = { nested };
  assert.throws(
    () => validatePageRequest(request("hns_send", nested)),
    (error) => error.code === "requestTooLarge"
  );
  assert.throws(
    () => validatePageRequest(request("hns_send", { memo: "x".repeat(17_000) })),
    (error) => error.code === "requestTooLarge"
  );
});

test("native capability and event envelopes are versioned and allowlisted", () => {
  const capabilities = validateNativeCapabilities({
    abiVersion: WALLET_NATIVE_ABI_VERSION,
    available: true,
    walletSession: "wallet-session-a",
    permissionGeneration: 2,
    methods: ["hns_accounts", "wallet_getStatus"]
  });
  assert.deepEqual(capabilities.methods, ["hns_accounts", "wallet_getStatus"]);
  assert.throws(
    () =>
      validateNativeCapabilities({
        abiVersion: WALLET_NATIVE_ABI_VERSION,
        available: true,
        walletSession: "wallet-session-a",
        permissionGeneration: 2,
        methods: ["hns_accounts", "hns_accounts"]
      }),
    (error) => error.code === "walletUnavailable"
  );
  assert.throws(
    () =>
      validateNativeCapabilities({
        abiVersion: WALLET_NATIVE_ABI_VERSION,
        available: true,
        walletSession: "wallet-session-a",
        permissionGeneration: 2,
        methods: ["eth_call"]
      }),
    (error) => error.code === "walletUnavailable"
  );
  assert.throws(
    () =>
      validateNativeCapabilities({
        abiVersion: WALLET_NATIVE_ABI_VERSION,
        available: true,
        walletSession: "wallet-session-a",
        permissionGeneration: 2,
        methods: ["hns_accounts"],
        futureField: true
      }),
    (error) => error.code === "walletUnavailable"
  );
  assert.throws(
    () => validateNativeCapabilities({ abiVersion: 1, available: true }),
    (error) => error.code === "walletUnavailable"
  );
  assert.equal(
    validateProviderEvent({ event: "accountsChanged", payload: [] }).event,
    "accountsChanged"
  );
  assert.throws(
    () => validateProviderEvent({ event: "privateKeysChanged", payload: [] }),
    (error) => error.code === "invalidEvent"
  );
});

function request(method, params) {
  return {
    schemaVersion: 1,
    kind: "request",
    requestId: "request-1",
    sequence: 1,
    method,
    params
  };
}
