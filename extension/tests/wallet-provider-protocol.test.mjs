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

test("native results and events reject secret and private envelope fields", () => {
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
  const privateEnvelopeFields = [
    "protocolVersion",
    "requestNonce",
    "walletSession",
    "authorityHandle",
    "authorityRevision",
    "hostSessionId",
    "serviceSessionId",
    "runtimeSessionId",
    "browserRuntimeSessionId",
    "browserAuthoritySession",
    "restartGeneration",
    "channelSequence",
    "eventSequence",
    "runtimeGeneration",
    "policyGeneration",
    "navigationGeneration",
    "decisionFingerprint",
    "validUntilUnixMs",
    "engineContext"
  ];
  for (const field of privateEnvelopeFields) {
    assert.throws(
      () => validateNativeResult({ public: { [field]: "private-native-state" } }),
      (error) => error.code === "invalidResult",
      field
    );
    assert.throws(
      () => validateProviderEvent({ event: "walletLocked", payload: { [field]: 1 } }),
      (error) => error.code === "invalidResult",
      `event ${field}`
    );
  }
});

test("native result routing stays private except the exact root approval handoff", () => {
  for (const result of [
    { event: "walletLocked" },
    { nested: [{ events: [] }] },
    { nested: { approvalRequired: true } },
    {
      nested: {
        approvalId: "AQIDBAUGBwgJCgsMDQ4PEA",
        expiresAtUnixMs: 1,
        summary: {}
      }
    }
  ]) {
    assert.throws(
      () => validateNativeResult(result),
      (error) => error.code === "invalidResult"
    );
  }

  const handoff = {
    approvalRequired: {
      schemaVersion: 3,
      approvalId: "AQIDBAUGBwgJCgsMDQ4PEA",
      method: "wallet_lock",
      origin: "https://welcome",
      expiresAtUnixMs: 2_000_000_000_000,
      summary: { kind: "permissions" }
    }
  };
  assert.equal(
    validateNativeResult(handoff, { allowApprovalRoute: true }),
    handoff
  );
  for (const invalid of [
    { ...handoff, publicResult: true },
    { nested: handoff },
    { approvalRequired: handoff.approvalRequired, events: [] },
    { approvalRequired: null }
  ]) {
    assert.throws(
      () => validateNativeResult(invalid, { allowApprovalRoute: true }),
      (error) => error.code === "invalidResult"
    );
  }
});

test("permission generations have the same exact public projection as mobile", () => {
  const result = { permissionGeneration: 7, capabilities: [] };
  assert.equal(
    validateNativeResult(result, { resultMethod: "wallet_getPermissions" }),
    result
  );
  for (const invalid of [
    () => validateNativeResult(result),
    () => validateNativeResult(result, { resultMethod: "wallet_getStatus" }),
    () => validateNativeResult(
      { nested: { permissionGeneration: 7 } },
      { resultMethod: "wallet_getPermissions" }
    ),
    () => validateProviderEvent({
      event: "walletLocked",
      payload: { permissionGeneration: 7 }
    }),
    () => validateProviderEvent({
      event: "connect",
      payload: { nested: { permissionGeneration: 7 } }
    })
  ]) {
    assert.throws(invalid, (error) => error.code === "invalidResult");
  }
  assert.deepEqual(
    validateProviderEvent({
      event: "connect",
      payload: { permissionGeneration: 7 }
    }),
    { event: "connect", payload: { permissionGeneration: 7 } }
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
  const neverAuthorized = validateNativeCapabilities({
    abiVersion: WALLET_NATIVE_ABI_VERSION,
    available: true,
    walletSession: "wallet-session-fresh",
    permissionGeneration: 0,
    methods: ["wallet_getCapabilities", "wallet_requestPermissions"]
  });
  assert.equal(neverAuthorized.permissionGeneration, 0);
  assert.deepEqual(neverAuthorized.methods, [
    "wallet_getCapabilities",
    "wallet_requestPermissions"
  ]);
  assert.throws(
    () =>
      validateNativeCapabilities({
        abiVersion: WALLET_NATIVE_ABI_VERSION,
        available: true,
        walletSession: "wallet-session-a",
        permissionGeneration: -1,
        methods: ["wallet_requestPermissions"]
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
