import test from "node:test";
import assert from "node:assert/strict";
import {
  NavigationReceiptStore,
  canonicalNavigationUrl,
  registerNavigationLifecycle
} from "../src/navigation-receipts.js";

const runtime = Object.freeze({
  runtimeSession: "session-a",
  runtimeGeneration: 7,
  policyGeneration: 3,
  securityMaintenanceEpoch: 1,
  state: "active",
  proxyActive: true,
  headerSync: {
    treeRootReady: true,
    blocksUntilAuthoritativeTreeRoot: 0,
    targetEvidenceExpired: false,
    targetEvidenceValidUntilUnix: 10
  }
});

function securityResult(host, eventSequence, overrides = {}) {
  return {
    schemaVersion: 3,
    eventSequence,
    runtimeSession: runtime.runtimeSession,
    runtimeGeneration: runtime.runtimeGeneration,
    policyGeneration: runtime.policyGeneration,
    host,
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
    registryProfile: "denuoV1",
    ...overrides
  };
}

function connectDecision(host, eventSequence, observedAtUnixMs, overrides = {}) {
  return {
    schemaVersion: 1,
    observationKind: "browserWebPkiPassthrough",
    httpStatusObserved: false,
    observedAtUnixMs,
    maintenanceEpoch: runtime.securityMaintenanceEpoch,
    eventSequence,
    runtimeSession: runtime.runtimeSession,
    runtimeGeneration: runtime.runtimeGeneration,
    policyGeneration: runtime.policyGeneration,
    network: "mainnet",
    host,
    port: 443,
    canonicalStatus: "available",
    namespaceOutcome: "icannOnly",
    selectedNamespace: "icann",
    namespaceSelectionReason: "onlyAvailableRoot",
    decisionFingerprint: "34".repeat(32),
    hnsRootFailure: null,
    icannRootFailure: null,
    hnsResolutionState: "authenticatedAbsent",
    icannResolutionState: "present",
    icannTlsAction: "webPkiAuthenticatedAbsence",
    icannDnssecStatus: "secure",
    chainAnchor: {
      localBestHeight: null,
      targetHeight: null,
      estimatedTargetHeight: null,
      stale: null
    },
    transportPolicy: { directAuthoritativeFirst: true },
    actualSelectedTransport: "icannDoh",
    nameserverAuthority: "validatingIcannResolver",
    localHnsProofState: "notAttempted",
    localDnssecState: "verified",
    localTlsaState: "unavailable",
    localDaneState: "notAttempted",
    peerIdentity: null,
    proxyIdentity: null,
    targetIdentity: null,
    proxyTargetSeparation: "notApplicable",
    directRelayFallback: false,
    providerReadiness: { dnsRelay: "disabled" },
    registryProfile: "denuoV1",
    registryFingerprint: null,
    protocolVersion: null,
    ...overrides
  };
}

function request(overrides = {}) {
  return {
    requestId: "request-1",
    tabId: 4,
    documentId: "document-1",
    type: "main_frame",
    method: "GET",
    timeStamp: Date.now() - 200,
    url: "https://welcome/",
    ...overrides
  };
}

function commit(overrides = {}) {
  return {
    tabId: 4,
    frameId: 0,
    documentId: "document-1",
    url: "https://welcome/",
    transitionQualifiers: [],
    ...overrides
  };
}

function completeNetworkNavigation(store, options = {}) {
  const begin = request(options.request);
  const committed = commit(options.commit);
  const result =
    options.result ??
    securityResult(canonicalNavigationUrl(committed.url).host, options.eventSequence ?? 11);
  assert.equal(store.beginRequest(begin, runtime), true);
  assert.equal(store.commitDocument(committed), true);
  assert.equal(
    store.completeRequest(
      {
        ...begin,
        documentId: committed.documentId,
        url: committed.url,
        statusCode: result.statusCode,
        fromCache: false
      },
      { ...runtime, latestMainFrameSecurity: result }
    ),
    true
  );
  return result;
}

test("a network main frame is bound only to its committed tab and document", () => {
  const store = new NavigationReceiptStore();
  const result = completeNetworkNavigation(store);

  assert.equal(store.receiptForTab(4, runtime).receipt, result);
  assert.equal(store.receiptForTab(4, runtime).state, "currentDocument");
  assert.equal(store.receiptForTab(8, runtime).receipt, null);
  assert.equal(
    store.receiptForTab(8, runtime).unavailableReason,
    "activeDocumentReceiptUnavailable"
  );
});

test("BFCache and same-document history retain only the exact document receipt", () => {
  const store = new NavigationReceiptStore();
  const result = completeNetworkNavigation(store);

  store.commitDocument(
    commit({ transitionQualifiers: ["forward_back"] }),
    "historyDocumentReceiptUnavailable"
  );
  assert.equal(store.receiptForTab(4, runtime).receipt, result);
  assert.equal(store.receiptForTab(4, runtime).state, "restoredDocument");

  store.updateDocumentUrl(
    commit({
      url: "https://welcome/docs?section=security#ignored",
      transitionQualifiers: []
    })
  );
  assert.equal(store.receiptForTab(4, runtime).receipt, result);
  assert.equal(
    store.snapshot().documents["document-1"].url,
    "https://welcome/docs?section=security"
  );
});

test("prerender and failed navigation cannot replace the active document receipt", () => {
  const store = new NavigationReceiptStore();
  completeNetworkNavigation(store);
  assert.equal(
    store.commitDocument(
      commit({
        documentId: "prerender-document",
        url: "https://prerender.example/",
        documentLifecycle: "prerender"
      })
    ),
    false
  );
  assert.equal(store.receiptForTab(4, runtime).receipt?.host, "welcome");

  assert.equal(
    store.failNavigation({
      tabId: 4,
      frameId: 0,
      url: "https://failed.example/"
    }),
    true
  );
  assert.equal(store.receiptForTab(4, runtime).receipt, null);
  assert.equal(
    store.receiptForTab(4, runtime).unavailableReason,
    "mainFrameNavigationFailed"
  );
});

test("header maintenance keeps the committed receipt but bars cache reuse", () => {
  const store = new NavigationReceiptStore();
  const original = completeNetworkNavigation(store);
  assert.equal(store.beginMaintenance(runtime), true);

  const existing = store.receiptForTab(4, runtime);
  assert.equal(existing.receipt, original);
  assert.equal(existing.state, "committedBeforeHeaderMaintenance");

  const afterMaintenance = {
    ...runtime,
    securityMaintenanceEpoch: runtime.securityMaintenanceEpoch + 1
  };
  assert.equal(store.ensureRuntime(afterMaintenance), true);
  assert.equal(store.completeMaintenance(afterMaintenance, 0), true);
  const cached = request({
    requestId: "cached-after-sync",
    tabId: 5,
    documentId: "document-2"
  });
  assert.equal(store.beginRequest(cached, afterMaintenance), true);
  assert.equal(
    store.commitDocument(commit({ tabId: 5, documentId: "document-2" })),
    true
  );
  assert.equal(
    store.completeRequest(
      { ...cached, statusCode: 200, fromCache: true },
      afterMaintenance
    ),
    false
  );
  assert.equal(store.receiptForTab(5, afterMaintenance).receipt, null);
  assert.equal(
    store.receiptForTab(5, afterMaintenance).unavailableReason,
    "browserCacheReceiptUnavailable"
  );
});

test("successful same-root maintenance completes at an unchanged epoch", () => {
  const store = new NavigationReceiptStore();
  const original = completeNetworkNavigation(store);
  assert.equal(store.beginMaintenance(runtime), true);
  assert.equal(store.completeMaintenance(runtime, 0), true);

  const existing = store.receiptForTab(4, runtime);
  assert.equal(existing.receipt, original);
  assert.notEqual(existing.state, "committedBeforeHeaderMaintenance");
  assert.notEqual(
    store.providerAuthorityForDocument(
      4,
      "document-1",
      "https://welcome",
      runtime,
      "https://welcome/"
    ),
    null
  );
});

test("successful root-changing maintenance completes at an advanced epoch", () => {
  const store = new NavigationReceiptStore();
  completeNetworkNavigation(store);
  assert.equal(store.beginMaintenance(runtime), true);
  const advanced = {
    ...runtime,
    securityMaintenanceEpoch: runtime.securityMaintenanceEpoch + 1
  };
  // A webRequest or popup read can observe and adopt the new epoch before the
  // serialized sync path completes its explicit maintenance transaction.
  assert.equal(store.ensureRuntime(advanced), true);
  assert.equal(store.completeMaintenance(advanced, 0), true);
  assert.equal(
    store.receiptForTab(4, advanced).state,
    "committedBeforeHeaderMaintenance"
  );
});

test("degraded same-epoch maintenance remains fail-closed", () => {
  const store = new NavigationReceiptStore();
  completeNetworkNavigation(store);
  assert.equal(store.beginMaintenance(runtime), true);
  const degraded = {
    ...runtime,
    state: "degraded",
    headerSync: {
      treeRootReady: false,
      targetEvidenceExpired: false
    }
  };
  assert.equal(store.completeMaintenance(degraded, 0), false);
  assert.equal(
    store.receiptForTab(4, degraded).state,
    "committedBeforeHeaderMaintenance"
  );
});

test("expired target evidence cannot complete maintenance", () => {
  const store = new NavigationReceiptStore();
  completeNetworkNavigation(store);
  assert.equal(store.beginMaintenance(runtime), true);
  assert.equal(store.completeMaintenance(runtime, 10), false);
  assert.equal(
    store.receiptForTab(4, runtime).state,
    "committedBeforeHeaderMaintenance"
  );
});

test("an exact URL disk-cache hit can reuse a current-epoch receipt only", () => {
  const store = new NavigationReceiptStore();
  const original = completeNetworkNavigation(store);
  const cached = request({
    requestId: "cached-request",
    tabId: 5,
    documentId: "cached-document"
  });
  store.beginRequest(cached, runtime);
  store.commitDocument(
    commit({ tabId: 5, documentId: "cached-document" })
  );
  assert.equal(
    store.completeRequest(
      { ...cached, statusCode: 200, fromCache: true },
      runtime
    ),
    true
  );
  assert.equal(store.receiptForTab(5, runtime).receipt, original);
  assert.equal(store.receiptForTab(5, runtime).state, "browserCacheReceipt");

  const otherUrl = request({
    requestId: "different-cache-entry",
    tabId: 6,
    documentId: "different-document",
    url: "https://welcome/?different=1"
  });
  store.beginRequest(otherUrl, runtime);
  store.commitDocument(
    commit({
      tabId: 6,
      documentId: "different-document",
      url: otherUrl.url
    })
  );
  assert.equal(
    store.completeRequest(
      { ...otherUrl, statusCode: 200, fromCache: true },
      runtime
    ),
    false
  );
  assert.equal(
    store.receiptForTab(6, runtime).unavailableReason,
    "browserCacheReceiptUnavailable"
  );
});

test("an authoritative epoch advance during a cache navigation revokes reuse", () => {
  const store = new NavigationReceiptStore();
  completeNetworkNavigation(store);
  const cached = request({
    requestId: "cache-epoch-race",
    tabId: 5,
    documentId: "cache-epoch-race-document"
  });
  store.beginRequest(cached, runtime);
  store.commitDocument(
    commit({ tabId: 5, documentId: "cache-epoch-race-document" })
  );
  const advanced = {
    ...runtime,
    securityMaintenanceEpoch: runtime.securityMaintenanceEpoch + 1,
    recentConnectSecurityDecisions: []
  };
  assert.equal(
    store.completeRequest(
      { ...cached, statusCode: 200, fromCache: true },
      advanced
    ),
    false
  );
  assert.equal(store.snapshot().maintenanceEpoch, 2);
  assert.equal(store.receiptForTab(5, advanced).receipt, null);
});

test("redirect completion binds only a matching final host result", () => {
  const store = new NavigationReceiptStore();
  const started = request({ url: "https://first.example/" });
  store.beginRequest(started, runtime);
  store.redirectRequest({
    requestId: started.requestId,
    redirectUrl: "https://final.example/landing"
  });
  store.commitDocument(
    commit({ url: "https://final.example/landing" })
  );
  const result = securityResult("final.example", 12);
  assert.equal(
    store.completeRequest(
      {
        ...started,
        url: "https://final.example/landing",
        statusCode: 200,
        fromCache: false
      },
      { ...runtime, latestMainFrameSecurity: result }
    ),
    true
  );
  assert.equal(store.receiptForTab(4, runtime).receipt, result);
});

test("the committed document ID wins over stale webRequest document metadata", () => {
  const store = new NavigationReceiptStore();
  const started = request({ documentId: "initiating-document" });
  store.beginRequest(started, runtime);
  store.commitDocument(commit({ documentId: "committed-document" }));
  const result = securityResult("welcome", 12);

  assert.equal(
    store.completeRequest(
      {
        ...started,
        documentId: "initiating-document",
        statusCode: 200,
        fromCache: false
      },
      { ...runtime, latestMainFrameSecurity: result }
    ),
    true
  );
  assert.equal(store.receiptForTab(4, runtime).receipt, result);
  assert.equal(
    store.snapshot().tabs["4"].documentId,
    "committed-document"
  );
});

test("an ICANN WebPKI CONNECT decision binds only after matching browser completion", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 1_000;
  const started = request({
    url: "https://first.example/",
    timeStamp: startedAt
  });
  assert.equal(
    store.beginRequest(started, {
      ...runtime,
      recentConnectSecurityDecisions: []
    }),
    true
  );
  assert.equal(
    store.redirectRequest({
      requestId: started.requestId,
      redirectUrl: "https://developer.chrome.com/docs"
    }),
    true
  );
  store.commitDocument(
    commit({ url: "https://developer.chrome.com/docs" })
  );
  const decision = connectDecision(
    "developer.chrome.com",
    20,
    startedAt + 200
  );
  assert.equal(
    store.completeRequest(
      {
        ...started,
        url: "https://developer.chrome.com/docs",
        statusCode: 200,
        fromCache: false,
        timeStamp: startedAt + 600
      },
      {
        ...runtime,
        latestMainFrameSecurity: securityResult("previous.example", 19),
        recentConnectSecurityDecisions: [decision]
      }
    ),
    true
  );

  const scoped = store.receiptForTab(4, runtime);
  assert.equal(scoped.receipt, null);
  assert.equal(scoped.connectDecisionReceipt.nativeDecision, decision);
  assert.equal(scoped.connectDecisionReceipt.browserStatusCode, 200);
  assert.equal(scoped.source, "browserWebPkiPassthrough");
  assert.equal(Object.hasOwn(decision, "statusCode"), false);
  assert.equal(Object.hasOwn(decision, "mainFrame"), false);
  assert.equal(store.receiptForTab(8, runtime).connectDecisionReceipt, null);
});

test("same-host raw tunnel reuse retains explicit provenance", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 500;
  const decision = connectDecision(
    "developer.chrome.com",
    21,
    startedAt - 1_000
  );
  const started = request({
    url: "https://developer.chrome.com/docs",
    timeStamp: startedAt
  });
  const status = {
    ...runtime,
    latestMainFrameSecurity: null,
    recentConnectSecurityDecisions: [decision]
  };
  store.beginRequest(started, status);
  store.commitDocument(
    commit({ url: "https://developer.chrome.com/docs" })
  );
  assert.equal(
    store.completeRequest(
      {
        ...started,
        statusCode: 200,
        fromCache: false,
        timeStamp: startedAt + 200
      },
      status
    ),
    true
  );
  assert.equal(
    store.receiptForTab(4, runtime).source,
    "browserWebPkiConnectionReuse"
  );
});

test("WebPKI decision receipts survive BFCache, exact cache, and session restoration", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 800;
  const url = "https://developer.chrome.com/docs";
  const started = request({ url, timeStamp: startedAt });
  const decision = connectDecision(
    "developer.chrome.com",
    22,
    startedAt + 100
  );
  store.beginRequest(started, runtime);
  store.commitDocument(commit({ url }));
  store.completeRequest(
    {
      ...started,
      statusCode: 200,
      fromCache: false,
      timeStamp: startedAt + 300
    },
    {
      ...runtime,
      latestMainFrameSecurity: null,
      recentConnectSecurityDecisions: [decision]
    }
  );

  store.commitDocument(
    commit({ url, transitionQualifiers: ["forward_back"] })
  );
  assert.equal(store.receiptForTab(4, runtime).state, "restoredDocument");

  const cached = request({
    requestId: "cached-webpki",
    tabId: 5,
    documentId: "cached-webpki-document",
    url,
    timeStamp: startedAt + 400
  });
  store.beginRequest(cached, runtime);
  store.commitDocument(
    commit({
      tabId: 5,
      documentId: "cached-webpki-document",
      url
    })
  );
  assert.equal(
    store.completeRequest(
      {
        ...cached,
        statusCode: 200,
        fromCache: true,
        timeStamp: startedAt + 500
      },
      runtime
    ),
    true
  );
  assert.equal(
    store.receiptForTab(5, runtime).source,
    "browserWebPkiCacheReceipt"
  );

  const restored = new NavigationReceiptStore(store.snapshot());
  assert.equal(
    restored.receiptForTab(5, runtime).connectDecisionReceipt.nativeDecision.host,
    "developer.chrome.com"
  );
});

test("native maintenance epoch revokes WebPKI cache and tunnel reuse for new documents", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 800;
  const url = "https://developer.chrome.com/docs";
  const started = request({ url, timeStamp: startedAt });
  const decision = connectDecision(
    "developer.chrome.com",
    23,
    startedAt + 100
  );
  store.beginRequest(started, runtime);
  store.commitDocument(commit({ url }));
  store.completeRequest(
    {
      ...started,
      statusCode: 200,
      fromCache: false,
      timeStamp: startedAt + 300
    },
    {
      ...runtime,
      latestMainFrameSecurity: null,
      recentConnectSecurityDecisions: [decision]
    }
  );
  store.beginMaintenance(runtime);
  assert.equal(
    store.receiptForTab(4, runtime).state,
    "committedBeforeHeaderMaintenance"
  );
  const nextEpoch = {
    ...runtime,
    securityMaintenanceEpoch: 2,
    latestMainFrameSecurity: null,
    recentConnectSecurityDecisions: []
  };
  assert.equal(store.ensureRuntime(nextEpoch), true);
  assert.equal(
    store.receiptForTab(4, nextEpoch).connectDecisionReceipt.nativeDecision,
    decision
  );

  const cached = request({
    requestId: "post-sync-cache",
    tabId: 5,
    documentId: "post-sync-cache-document",
    url,
    timeStamp: startedAt + 400
  });
  store.beginRequest(cached, nextEpoch);
  store.commitDocument(
    commit({
      tabId: 5,
      documentId: "post-sync-cache-document",
      url
    })
  );
  assert.equal(
    store.completeRequest(
      {
        ...cached,
        statusCode: 200,
        fromCache: true,
        timeStamp: startedAt + 500
      },
      nextEpoch
    ),
    false
  );

  const reused = request({
    requestId: "post-sync-reuse",
    tabId: 6,
    documentId: "post-sync-reuse-document",
    url,
    timeStamp: startedAt + 600
  });
  store.beginRequest(reused, nextEpoch);
  store.commitDocument(
    commit({
      tabId: 6,
      documentId: "post-sync-reuse-document",
      url
    })
  );
  assert.equal(
    store.completeRequest(
      {
        ...reused,
        statusCode: 200,
        fromCache: false,
        timeStamp: startedAt + 700
      },
      {
        ...nextEpoch,
        recentConnectSecurityDecisions: [decision]
      }
    ),
    false
  );
});

test("multiple equivalent fresh CONNECT decisions collapse to the newest decision", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 500;
  const url = "https://developer.chrome.com/docs";
  const started = request({ url, timeStamp: startedAt });
  const first = connectDecision(
    "developer.chrome.com",
    24,
    startedAt + 100
  );
  const newest = connectDecision(
    "developer.chrome.com",
    25,
    startedAt + 200
  );
  store.beginRequest(started, runtime);
  store.commitDocument(commit({ url }));
  assert.equal(
    store.completeRequest(
      {
        ...started,
        statusCode: 200,
        fromCache: false,
        timeStamp: startedAt + 300
      },
      {
        ...runtime,
        latestMainFrameSecurity: null,
        recentConnectSecurityDecisions: [first, newest]
      }
    ),
    true
  );
  const scoped = store.receiptForTab(4, runtime);
  assert.equal(scoped.source, "browserWebPkiPassthrough");
  assert.equal(scoped.connectDecisionReceipt.nativeDecision, newest);
});

test("fresh CONNECT decisions with different fingerprints fail unavailable", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 500;
  const url = "https://developer.chrome.com/docs";
  const started = request({ url, timeStamp: startedAt });
  store.beginRequest(started, runtime);
  store.commitDocument(commit({ url }));
  assert.equal(
    store.completeRequest(
      {
        ...started,
        statusCode: 200,
        fromCache: false,
        timeStamp: startedAt + 300
      },
      {
        ...runtime,
        latestMainFrameSecurity: null,
        recentConnectSecurityDecisions: [
          connectDecision("developer.chrome.com", 26, startedAt + 100),
          connectDecision("developer.chrome.com", 27, startedAt + 200, {
            decisionFingerprint: "56".repeat(32)
          })
        ]
      }
    ),
    false
  );
  assert.equal(
    store.receiptForTab(4, runtime).unavailableReason,
    "ambiguousConnectSecurityDecision"
  );
});

test("fresh CONNECT decisions with matching fingerprints but different evidence fail unavailable", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 500;
  const url = "https://developer.chrome.com/docs";
  const started = request({ url, timeStamp: startedAt });
  store.beginRequest(started, runtime);
  store.commitDocument(commit({ url }));
  assert.equal(
    store.completeRequest(
      {
        ...started,
        statusCode: 200,
        fromCache: false,
        timeStamp: startedAt + 300
      },
      {
        ...runtime,
        latestMainFrameSecurity: null,
        recentConnectSecurityDecisions: [
          connectDecision("developer.chrome.com", 28, startedAt + 100),
          connectDecision("developer.chrome.com", 29, startedAt + 200, {
            icannTlsAction: "webPkiInsecureDelegation",
            icannDnssecStatus: "insecureDelegation"
          })
        ]
      }
    ),
    false
  );
  assert.equal(
    store.receiptForTab(4, runtime).unavailableReason,
    "ambiguousConnectSecurityDecision"
  );
});

test("a retained CONNECT decision unseen at request start can prove tunnel reuse", () => {
  const store = new NavigationReceiptStore();
  const startedAt = Date.now() - 500;
  const url = "https://developer.chrome.com/docs";
  const started = request({ url, timeStamp: startedAt });
  const unseen = connectDecision(
    "developer.chrome.com",
    30,
    startedAt - 100
  );
  store.beginRequest(started, {
    ...runtime,
    latestMainFrameSecurity: null,
    recentConnectSecurityDecisions: []
  });
  store.commitDocument(commit({ url }));
  assert.equal(
    store.completeRequest(
      {
        ...started,
        statusCode: 200,
        fromCache: false,
        timeStamp: startedAt + 300
      },
      {
        ...runtime,
        latestMainFrameSecurity: null,
        recentConnectSecurityDecisions: [unseen]
      }
    ),
    true
  );
  const scoped = store.receiptForTab(4, runtime);
  assert.equal(scoped.source, "browserWebPkiConnectionReuse");
  assert.equal(scoped.connectDecisionReceipt.nativeDecision, unseen);
});

test("overlapping same-host navigations fail unavailable instead of sharing a receipt", () => {
  const store = new NavigationReceiptStore();
  const first = request();
  const second = request({
    requestId: "request-2",
    tabId: 5,
    documentId: "document-2"
  });
  store.beginRequest(first, runtime);
  store.beginRequest(second, runtime);
  store.commitDocument(commit());
  store.commitDocument(commit({ tabId: 5, documentId: "document-2" }));
  const result = securityResult("welcome", 13);

  assert.equal(
    store.completeRequest(
      { ...first, statusCode: 200, fromCache: false },
      { ...runtime, latestMainFrameSecurity: result }
    ),
    false
  );
  assert.equal(
    store.receiptForTab(4, runtime).unavailableReason,
    "ambiguousMainFrameObservation"
  );
});

test("runtime changes and corrupt session snapshots cannot revive receipts", () => {
  const store = new NavigationReceiptStore();
  completeNetworkNavigation(store);
  const restored = new NavigationReceiptStore(store.snapshot());
  assert.equal(restored.receiptForTab(4, runtime).receipt?.host, "welcome");

  const nextRuntime = {
    runtimeSession: "session-b",
    runtimeGeneration: 8,
    policyGeneration: 4,
    securityMaintenanceEpoch: 1
  };
  assert.equal(restored.receiptForTab(4, nextRuntime).receipt, null);
  assert.deepEqual(new NavigationReceiptStore({ schemaVersion: 99 }).snapshot().runtime, null);
});

test("canonical navigation URLs reject credentials and preserve the effective port", () => {
  assert.equal(canonicalNavigationUrl("https://user:secret@example.com/"), null);
  assert.equal(canonicalNavigationUrl("https://127.0.0.1/"), null);
  assert.equal(canonicalNavigationUrl("https://example.com:0/"), null);
  assert.equal(canonicalNavigationUrl("chrome://settings/"), null);
  assert.equal(canonicalNavigationUrl("https://example.com/").port, 443);
  assert.equal(canonicalNavigationUrl("https://example.com:8443/").port, 8443);
  assert.equal(
    canonicalNavigationUrl("https://example.com/path#private-fragment").url,
    "https://example.com/path"
  );
});

test("session receipt state remains bounded under many tabs and URLs", () => {
  const store = new NavigationReceiptStore();
  for (let index = 0; index < 110; index += 1) {
    const host = `host-${index}.example`;
    completeNetworkNavigation(store, {
      request: {
        requestId: `request-${index}`,
        tabId: index,
        documentId: `document-${index}`,
        url: `https://${host}/page`
      },
      commit: {
        tabId: index,
        documentId: `document-${index}`,
        url: `https://${host}/page`
      },
      result: securityResult(host, index + 1)
    });
  }
  const snapshot = store.snapshot();
  assert.ok(Object.keys(snapshot.documents).length <= 96);
  assert.ok(Object.keys(snapshot.urlReceipts).length <= 96);
  assert.ok(Object.keys(snapshot.tabs).length <= 64);
});

test("navigation lifecycle registration filters main frames and main-frame commits", () => {
  const events = fakeChromeEvents();
  const calls = [];
  registerNavigationLifecycle(events.chrome, {
    beforeRequest: (details) => calls.push(["before", details]),
    beforeRedirect: (details) => calls.push(["redirect", details]),
    completed: (details) => calls.push(["completed", details]),
    requestError: (details) => calls.push(["error", details]),
    committed: (details) => calls.push(["committed", details]),
    historyUpdated: (details) => calls.push(["history", details]),
    navigationError: (details) => calls.push(["navigationError", details]),
    tabRemoved: (tabId) => calls.push(["removed", tabId]),
    tabReplaced: (added, removed) => calls.push(["replaced", added, removed])
  });

  assert.deepEqual(events.filters.before, {
    urls: ["<all_urls>"],
    types: ["main_frame"]
  });
  events.emit.committed({ frameId: 1 });
  events.emit.committed({ frameId: 0, documentId: "main" });
  events.emit.history({ frameId: 0, documentId: "main" });
  events.emit.fragment({ frameId: 0, documentId: "main" });
  events.emit.navigationError({ frameId: 0 });
  events.emit.removed(4);
  events.emit.replaced(5, 4);
  assert.deepEqual(
    calls.map(([kind]) => kind),
    ["committed", "history", "history", "navigationError", "removed", "replaced"]
  );
});

function fakeChromeEvents() {
  const listeners = {};
  const filters = {};
  function event(name, keepFilter = false) {
    return {
      addListener(listener, filter) {
        listeners[name] = listener;
        if (keepFilter) filters[name] = filter;
      }
    };
  }
  return {
    filters,
    emit: {
      committed: (details) => listeners.committed(details),
      history: (details) => listeners.history(details),
      fragment: (details) => listeners.fragment(details),
      navigationError: (details) => listeners.navigationError(details),
      removed: (tabId) => listeners.removed(tabId),
      replaced: (added, removed) => listeners.replaced(added, removed)
    },
    chrome: {
      webRequest: {
        onBeforeRequest: event("before", true),
        onBeforeRedirect: event("redirect", true),
        onCompleted: event("completed", true),
        onErrorOccurred: event("error", true)
      },
      webNavigation: {
        onCommitted: event("committed"),
        onHistoryStateUpdated: event("history"),
        onReferenceFragmentUpdated: event("fragment"),
        onErrorOccurred: event("navigationError")
      },
      tabs: {
        onRemoved: event("removed"),
        onReplaced: event("replaced")
      }
    }
  };
}
