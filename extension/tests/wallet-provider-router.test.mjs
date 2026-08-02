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
      if (authorityCalls === 3 || authorityCalls === 4) {
        return new Promise((resolve) => gates.push(resolve));
      }
      return authority();
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

test("repeated initialization with the same authority cannot reset replay state", async () => {
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

  const repeated = await router.initialize({ origin: "https://welcome" }, sender);
  assert.equal(repeated.binding, initialized.binding);
  const reusedIdentifier = bridgeRequest(
    repeated.binding,
    2,
    "wallet_getStatus",
    null
  );
  reusedIdentifier.request.requestId = "request-1";
  await assert.rejects(
    router.request(reusedIdentifier, sender),
    (error) => error.code === "replay"
  );
  await assert.rejects(
    router.request(
      bridgeRequest(repeated.binding, 1, "wallet_getStatus", null),
      sender
    ),
    (error) => error.code === "replay"
  );
});

test("capabilities cannot change without an authority or wallet generation change", async () => {
  let capabilityCalls = 0;
  const router = new WalletProviderRouter({
    authorityForSender: async () => authority(),
    nativeRequest: async () => {
      capabilityCalls += 1;
      return {
        abiVersion: 1,
        available: true,
        walletSession: "wallet-a",
        permissionGeneration: 1,
        methods: capabilityCalls === 1
          ? ["wallet_getStatus"]
          : ["wallet_getStatus", "hns_accounts"]
      };
    },
    deliverEvent: async () => {}
  });
  await router.initialize({ origin: "https://welcome" }, sender);
  await assert.rejects(
    router.initialize({ origin: "https://welcome" }, sender),
    (error) => error.code === "staleContext"
  );
});

test("an authority generation change creates a fresh replay domain", async () => {
  let currentAuthority = authority();
  const router = new WalletProviderRouter({
    authorityForSender: async () => currentAuthority,
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
  const first = await router.initialize({ origin: "https://welcome" }, sender);
  await router.request(
    bridgeRequest(first.binding, 1, "wallet_getStatus", null),
    sender
  );

  currentAuthority = authority({ navigationGeneration: 6 });
  const second = await router.initialize({ origin: "https://welcome" }, sender);
  assert.equal(second.binding.navigationGeneration, 6);
  assert.deepEqual(
    await router.request(
      bridgeRequest(second.binding, 1, "wallet_getStatus", null),
      sender
    ),
    { ok: true }
  );
});

test("loopback HTTP documents are rejected before authority or native lookup", async () => {
  let authorityCalls = 0;
  const router = new WalletProviderRouter({
    authorityForSender: async () => {
      authorityCalls += 1;
      return authority();
    },
    nativeRequest: async () => {
      throw new Error("native lookup must not run");
    },
    deliverEvent: async () => {}
  });
  const loopbackSender = {
    ...sender,
    origin: "http://127.0.0.1",
    url: "http://127.0.0.1/wallet-demo"
  };
  await assert.rejects(
    router.initialize({ origin: "http://127.0.0.1" }, loopbackSender),
    (error) => error.code === "insecureOrigin"
  );
  assert.equal(authorityCalls, 0);
});

test("a request completing after document authority replacement is stale", async () => {
  let currentAuthority = authority();
  let finishRequest;
  const router = new WalletProviderRouter({
    authorityForSender: async () => currentAuthority,
    nativeRequest: async (command) => {
      if (command === "walletProviderCapabilities") {
        return {
          abiVersion: 1,
          available: true,
          walletSession: "wallet-a",
          permissionGeneration: 1,
          methods: ["wallet_getStatus"]
        };
      }
      return new Promise((resolve) => {
        finishRequest = resolve;
      });
    },
    deliverEvent: async () => {}
  });
  const first = await router.initialize({ origin: "https://welcome" }, sender);
  const pending = router.request(
    bridgeRequest(first.binding, 1, "wallet_getStatus", null),
    sender
  );
  await Promise.resolve();
  currentAuthority = authority({ navigationGeneration: 6 });
  await router.initialize({ origin: "https://welcome" }, sender);
  finishRequest({ ok: true });
  await assert.rejects(pending, (error) => error.code === "staleContext");
});

test("a native result is stale when browser authority changes without document replacement", async () => {
  let currentAuthority = authority();
  let finishRequest;
  let markRequestStarted;
  const requestStarted = new Promise((resolve) => {
    markRequestStarted = resolve;
  });
  let delivered = 0;
  const router = new WalletProviderRouter({
    authorityForSender: async () => currentAuthority,
    nativeRequest: async (command) => {
      if (command === "walletProviderCapabilities") {
        return {
          abiVersion: 1,
          available: true,
          walletSession: "wallet-a",
          permissionGeneration: 1,
          methods: ["wallet_getStatus"]
        };
      }
      return new Promise((resolve) => {
        finishRequest = resolve;
        markRequestStarted();
      });
    },
    deliverEvent: async () => {
      delivered += 1;
    }
  });
  const initialized = await router.initialize({ origin: "https://welcome" }, sender);
  const pending = router.request(
    bridgeRequest(initialized.binding, 1, "wallet_getStatus", null),
    sender
  );
  await requestStarted;
  currentAuthority = authority({ navigationGeneration: 6 });
  finishRequest({
    ok: true,
    events: [{ event: "connect", payload: { network: "mainnet" } }]
  });
  await assert.rejects(pending, (error) => error.code === "staleContext");
  assert.equal(delivered, 0);
});

test("explicit authority invalidation makes pending requests and approvals stale", async () => {
  let finishRequest;
  let markRequestStarted;
  const requestStarted = new Promise((resolve) => {
    markRequestStarted = resolve;
  });
  const router = new WalletProviderRouter({
    authorityForSender: async () => authority(),
    nativeRequest: async (command) => {
      if (command === "walletProviderCapabilities") {
        return {
          abiVersion: 1,
          available: true,
          walletSession: "wallet-a",
          permissionGeneration: 1,
          methods: ["wallet_getStatus"]
        };
      }
      return new Promise((resolve) => {
        finishRequest = resolve;
        markRequestStarted();
      });
    },
    deliverEvent: async () => {}
  });
  const initialized = await router.initialize({ origin: "https://welcome" }, sender);
  const pending = router.request(
    bridgeRequest(initialized.binding, 1, "wallet_getStatus", null),
    sender
  );
  await requestStarted;
  router.invalidateAuthority();
  finishRequest({ ok: true });
  await assert.rejects(pending, (error) => error.code === "staleContext");
  await assert.rejects(
    router.revalidateApproval({
      sender,
      binding: initialized.binding,
      request: { method: "wallet_getStatus" }
    }),
    (error) => error.code === "staleContext"
  );
});

test("approval completion revalidates browser authority after native dispatch", async () => {
  let currentAuthority = authority();
  const router = new WalletProviderRouter({
    authorityForSender: async () => currentAuthority,
    nativeRequest: async () => ({
      abiVersion: 1,
      available: true,
      walletSession: "wallet-a",
      permissionGeneration: 1,
      methods: ["wallet_getStatus"]
    }),
    deliverEvent: async () => {}
  });
  const initialized = await router.initialize({ origin: "https://welcome" }, sender);
  const dispatch = await router.revalidateApproval({
    sender,
    binding: initialized.binding,
    request: { method: "wallet_getStatus" }
  });
  currentAuthority = authority({ navigationGeneration: 6 });
  await assert.rejects(
    router.completeApproval(dispatch, { ok: true }),
    (error) => error.code === "staleContext"
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
