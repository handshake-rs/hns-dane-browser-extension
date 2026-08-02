import test from "node:test";
import assert from "node:assert/strict";
import { WalletProviderRouter } from "../src/wallet-provider-router.js";

const sender = Object.freeze({
  id: "extension-id",
  origin: "https://welcome",
  url: "https://welcome/wallet-demo",
  frameId: 0,
  documentId: "document-a",
  tab: { id: 7 }
});

function authority(overrides = {}) {
  return {
    origin: "https://welcome",
    namespace: "hns",
    network: "mainnet",
    browserAuthoritySession: "browser-a",
    runtimeGeneration: 3,
    policyGeneration: 4,
    navigationGeneration: 5,
    documentId: "document-a",
    decisionFingerprint: "12".repeat(32),
    ...overrides
  };
}

test("router binds every typed request to browser, wallet, permission, and navigation generations", async () => {
  const commands = [];
  const events = [];
  const router = new WalletProviderRouter({
    authorityForSender: async () => authority(),
    nativeRequest: async (command, fields) => {
      commands.push({ command, fields });
      if (command === "walletProviderCapabilities") {
        return {
          abiVersion: 1,
          available: true,
          walletSession: "wallet-a",
          permissionGeneration: 9,
          methods: ["wallet_getStatus"]
        };
      }
      return {
        status: { locked: false },
        events: [{ event: "connect", payload: { network: "mainnet" } }]
      };
    },
    deliverEvent: async (_sender, binding, event) => events.push({ binding, event })
  });
  const initialized = await router.initialize(
    { schemaVersion: 1, origin: "https://welcome" },
    sender
  );
  assert.equal(initialized.binding.browserAuthoritySession, "browser-a");
  assert.equal(initialized.binding.walletSession, "wallet-a");
  assert.equal(initialized.binding.permissionGeneration, 9);
  assert.equal(initialized.binding.navigationGeneration, 5);

  const result = await router.request(
    bridgeRequest(initialized.binding, 1, "wallet_getStatus", null),
    sender
  );
  assert.deepEqual(result, { status: { locked: false } });
  assert.equal(commands[1].command, "walletProviderRequest");
  assert.equal(commands[1].fields.request.method, "wallet_getStatus");
  assert.deepEqual(commands[1].fields.authority, {
    ...authority(),
    walletSession: "wallet-a",
    permissionGeneration: 9
  });
  assert.equal(events[0].event.event, "connect");

  await assert.rejects(
    router.request(
      bridgeRequest(initialized.binding, 1, "wallet_getStatus", null),
      sender
    ),
    (error) => error.code === "replay"
  );
});

test("router rejects origin, navigation, and forbidden-method substitution before native dispatch", async () => {
  let currentAuthority = authority();
  let requestCalls = 0;
  const router = new WalletProviderRouter({
    authorityForSender: async () => currentAuthority,
    nativeRequest: async (command) => {
      if (command === "walletProviderRequest") requestCalls += 1;
      return command === "walletProviderCapabilities"
        ? {
            abiVersion: 1,
            available: true,
            walletSession: "wallet-a",
            permissionGeneration: 1,
            methods: ["wallet_getStatus"]
          }
        : {};
    },
    deliverEvent: async () => {}
  });
  const initialized = await router.initialize({ origin: "https://welcome" }, sender);
  currentAuthority = authority({ navigationGeneration: 6 });
  await assert.rejects(
    router.request(
      bridgeRequest(initialized.binding, 1, "wallet_getStatus", null),
      sender
    ),
    (error) => error.code === "staleContext"
  );
  await assert.rejects(
    router.request(
      bridgeRequest(initialized.binding, 2, "eth_call", {}),
      sender
    ),
    (error) => error.code === "forbiddenMethod"
  );
  assert.equal(requestCalls, 0);

  await assert.rejects(
    router.initialize(
      { origin: "https://attacker.example" },
      sender
    ),
    (error) => error.code === "originMismatch"
  );
});

test("parallel authority completion cannot turn an earlier sequence into a replay", async () => {
  const gates = [];
  let authorityCalls = 0;
  const router = new WalletProviderRouter({
    authorityForSender: async () => {
      authorityCalls += 1;
      if (authorityCalls === 1) return authority();
      return new Promise((resolve) => gates.push(resolve));
    },
    nativeRequest: async (command) => command === "walletProviderCapabilities"
      ? {
          abiVersion: 1,
          available: true,
          walletSession: "wallet-a",
          permissionGeneration: 1,
          methods: ["wallet_getStatus"]
        }
      : { ok: true },
    deliverEvent: async () => {}
  });
  const initialized = await router.initialize({ origin: "https://welcome" }, sender);
  const first = router.request(
    bridgeRequest(initialized.binding, 1, "wallet_getStatus", null),
    sender
  );
  const second = router.request(
    bridgeRequest(initialized.binding, 2, "wallet_getStatus", null),
    sender
  );
  await Promise.resolve();
  assert.equal(gates.length, 2);
  gates[1](authority());
  gates[0](authority());
  assert.deepEqual(await Promise.all([first, second]), [{ ok: true }, { ok: true }]);
});

test("completed request identifiers and unnegotiated methods cannot be reused", async () => {
  const router = new WalletProviderRouter({
    authorityForSender: async () => authority(),
    nativeRequest: async (command) => command === "walletProviderCapabilities"
      ? {
          abiVersion: 1,
          available: true,
          walletSession: "wallet-a",
          permissionGeneration: 1,
          methods: ["wallet_getStatus"]
        }
      : { ok: true },
    deliverEvent: async () => {}
  });
  const initialized = await router.initialize({ origin: "https://welcome" }, sender);
  await router.request(
    bridgeRequest(initialized.binding, 1, "wallet_getStatus", null),
    sender
  );
  const reused = bridgeRequest(initialized.binding, 2, "wallet_getStatus", null);
  reused.request.requestId = "request-1";
  await assert.rejects(
    router.request(reused, sender),
    (error) => error.code === "replay"
  );
  await assert.rejects(
    router.request(
      bridgeRequest(initialized.binding, 3, "hns_accounts", null),
      sender
    ),
    (error) => error.code === "unsupportedMethod"
  );
});

function bridgeRequest(binding, sequence, method, params) {
  return {
    schemaVersion: 1,
    type: "walletProviderRequest",
    origin: "https://welcome",
    binding,
    request: {
      schemaVersion: 1,
      kind: "request",
      requestId: `request-${sequence}`,
      sequence,
      method,
      params
    }
  };
}
