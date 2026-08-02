import test from "node:test";
import assert from "node:assert/strict";
import { NavigationReceiptStore } from "../src/navigation-receipts.js";

const runtime = Object.freeze({
  runtimeSession: "session-a",
  runtimeGeneration: 7,
  policyGeneration: 3,
  securityMaintenanceEpoch: 1
});
const activeRuntime = Object.freeze({ ...runtime, state: "active", proxyActive: true });

test("wallet provider authority is issued only for the exact current trusted document", () => {
  const store = completedStore();
  const authority = store.providerAuthorityForDocument(
    4,
    "document-1",
    "https://welcome",
    activeRuntime
  );
  assert.deepEqual(authority, {
    origin: "https://welcome",
    namespace: "hns",
    network: "mainnet",
    browserAuthoritySession: "session-a",
    runtimeGeneration: 7,
    policyGeneration: 3,
    navigationGeneration: authority.navigationGeneration,
    documentId: "document-1",
    decisionFingerprint: "12".repeat(32)
  });
  assert.equal(
    store.providerAuthorityForDocument(
      4,
      "document-1",
      "https://lookalike.example",
      activeRuntime
    ),
    null
  );
  assert.equal(
    store.providerAuthorityForDocument(4, "other-document", "https://welcome", activeRuntime),
    null
  );
  assert.equal(
    store.providerAuthorityForDocument(
      4,
      "document-1",
      "https://welcome",
      activeRuntime,
      "https://welcome/changed-before-history-event"
    ),
    null
  );
  assert.equal(
    store.providerAuthorityForDocument(4, "document-1", "https://welcome", {
      ...activeRuntime,
      state: "degraded"
    }),
    null
  );
});

test("restored and maintenance-stale documents must obtain fresh authority", () => {
  const restored = completedStore();
  restored.commitDocument({
    tabId: 4,
    frameId: 0,
    documentId: "document-1",
    url: "https://welcome/",
    transitionQualifiers: ["forward_back"]
  });
  assert.equal(
    restored.providerAuthorityForDocument(4, "document-1", "https://welcome", activeRuntime),
    null
  );

  const maintenance = completedStore();
  maintenance.beginMaintenance(activeRuntime);
  assert.equal(
    maintenance.providerAuthorityForDocument(
      4,
      "document-1",
      "https://welcome",
      activeRuntime
    ),
    null
  );
});

function completedStore() {
  const store = new NavigationReceiptStore();
  const request = {
    requestId: "request-1",
    tabId: 4,
    documentId: "document-1",
    type: "main_frame",
    method: "GET",
    timeStamp: Date.now() - 200,
    url: "https://welcome/"
  };
  const result = {
    schemaVersion: 3,
    eventSequence: 11,
    runtimeSession: "session-a",
    runtimeGeneration: 7,
    policyGeneration: 3,
    network: "mainnet",
    host: "welcome",
    statusCode: 200,
    mainFrame: true,
    canonicalStatus: "available",
    canonicalStatusUnavailableReason: null,
    namespaceOutcome: "hnsOnly",
    selectedNamespace: "hns",
    namespaceSelectionReason: "onlyAvailableRoot",
    decisionFingerprint: "12".repeat(32),
    hnsResolutionState: "securePresent",
    icannResolutionState: "absent",
    actualSelectedTransport: "localHnsProof",
    transportPolicy: { directAuthoritativeFirst: true },
    providerReadiness: { dnsRelay: "disabled" },
    registryProfile: "denuoV1"
  };
  assert.equal(store.beginRequest(request, runtime), true);
  assert.equal(
    store.commitDocument({
      tabId: 4,
      frameId: 0,
      documentId: "document-1",
      url: "https://welcome/",
      transitionQualifiers: []
    }),
    true
  );
  assert.equal(
    store.completeRequest(
      { ...request, statusCode: 200, fromCache: false },
      { ...runtime, latestMainFrameSecurity: result }
    ),
    true
  );
  return store;
}
