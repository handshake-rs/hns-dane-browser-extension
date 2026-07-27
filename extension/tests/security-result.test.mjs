import test from "node:test";
import assert from "node:assert/strict";
import {
  currentConnectSecurityDecision,
  currentSecurityResult,
  namespaceLabel,
  namespaceOutcomeLabel,
  namespaceReasonLabel,
  stateLabel,
  transportLabel
} from "../src/security-result.js";

const runtime = Object.freeze({
  runtimeSession: "session-a",
  runtimeGeneration: 7,
  policyGeneration: 3,
  securityMaintenanceEpoch: 5
});

function result(overrides = {}) {
  return {
    schemaVersion: 3,
    eventSequence: 11,
    runtimeSession: "session-a",
    runtimeGeneration: 7,
    policyGeneration: 3,
    host: "welcome",
    canonicalStatus: "available",
    canonicalStatusUnavailableReason: null,
    namespaceOutcome: "hnsOnly",
    selectedNamespace: "hns",
    namespaceSelectionReason: "onlyAvailableRoot",
    decisionFingerprint: "12".repeat(32),
    hnsResolutionState: "securePresent",
    icannResolutionState: "absent",
    actualSelectedTransport: "directAuthoritativeTcp",
    transportPolicy: { directAuthoritativeFirst: true },
    providerReadiness: { dnsRelay: "disabled" },
    registryProfile: "denuoV1",
    ...overrides
  };
}

function connectDecision(overrides = {}) {
  return {
    schemaVersion: 1,
    observationKind: "browserWebPkiPassthrough",
    httpStatusObserved: false,
    observedAtUnixMs: Date.now() - 100,
    maintenanceEpoch: runtime.securityMaintenanceEpoch,
    eventSequence: 12,
    runtimeSession: runtime.runtimeSession,
    runtimeGeneration: runtime.runtimeGeneration,
    policyGeneration: runtime.policyGeneration,
    network: "mainnet",
    host: "developer.chrome.com",
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

test("security UI accepts only the current Rust runtime and policy generation", () => {
  assert.equal(currentSecurityResult(result(), runtime)?.host, "welcome");
  assert.equal(
    currentSecurityResult(result({ runtimeSession: "stale-session" }), runtime),
    null
  );
  assert.equal(
    currentSecurityResult(result({ runtimeGeneration: 6 }), runtime),
    null
  );
  assert.equal(
    currentSecurityResult(result({ policyGeneration: 2 }), runtime),
    null
  );
  assert.equal(
    currentSecurityResult(result({ eventSequence: 0 }), runtime),
    null
  );
  assert.equal(
    currentSecurityResult(result({ actualSelectedTransport: "publicRecursiveDoh" }), runtime),
    null
  );
});

test("security UI uses fixed labels instead of inferring transport or validation", () => {
  assert.equal(transportLabel("directAuthoritativeUdp"), "Direct authoritative UDP");
  assert.equal(transportLabel("icannDoh"), "Validating ICANN DoH");
  assert.equal(transportLabel("handshakeP2pDnsRelay"), "Handshake P2P DNS Relay");
  assert.equal(transportLabel("localHnsProof"), "Local verified HNS proof");
  assert.equal(transportLabel("futureTransport"), "Unavailable");
  assert.equal(stateLabel("notEvaluated"), "Not Evaluated");
  assert.equal(stateLabel("not_evaluated"), "Not evaluated");
  assert.equal(namespaceOutcomeLabel("bothDivergent"), "Both roots differ");
  assert.equal(namespaceLabel("icann"), "ICANN");
  assert.equal(namespaceReasonLabel("stickyBinding"), "sticky site binding");
});

test("security UI retains a successful proof-contained HNS main frame", () => {
  const proofContained = result({
    host: "shakeshift",
    actualSelectedTransport: "localHnsProof",
    localHnsProofState: "verified",
    localDnssecState: "verified",
    localTlsaState: "verified",
    localDaneState: "verified"
  });

  assert.equal(currentSecurityResult(proofContained, runtime), proofContained);
  assert.equal(transportLabel(proofContained.actualSelectedTransport), "Local verified HNS proof");
});

test("security UI rejects inconsistent namespace selection", () => {
  assert.equal(
    currentSecurityResult(
      result({ namespaceOutcome: "bothDivergent", selectedNamespace: null }),
      runtime
    ),
    null
  );
  assert.equal(
    currentSecurityResult(
      result({ namespaceOutcome: "neither", selectedNamespace: "hns" }),
      runtime
    ),
    null
  );
  assert.equal(
    currentSecurityResult(
      result({ namespaceOutcome: "hnsOnly", selectedNamespace: "icann" }),
      runtime
    ),
    null
  );
  assert.equal(
    currentSecurityResult(
      result({ namespaceOutcome: "icannOnly", selectedNamespace: "hns" }),
      runtime
    ),
    null
  );
  assert.equal(
    currentSecurityResult(
      result({ hnsResolutionState: "futureState" }),
      runtime
    ),
    null
  );
  assert.equal(
    currentSecurityResult(
      result({ namespaceSelectionReason: "icannDefault" }),
      runtime
    ),
    null
  );
});

test("security UI validates coherent five-way and indeterminate results", () => {
  const fixtures = [
    result(),
    result({
      namespaceOutcome: "icannOnly",
      selectedNamespace: "icann",
      namespaceSelectionReason: "onlyAvailableRoot",
      hnsResolutionState: "authenticatedAbsent",
      icannResolutionState: "present"
    }),
    result({
      namespaceOutcome: "bothConvergent",
      selectedNamespace: "icann",
      namespaceSelectionReason: "icannDefault",
      hnsResolutionState: "securePresent",
      icannResolutionState: "present"
    }),
    result({
      namespaceOutcome: "bothDivergent",
      selectedNamespace: "icann",
      namespaceSelectionReason: "icannDefault",
      hnsResolutionState: "securePresent",
      icannResolutionState: "present"
    }),
    result({
      namespaceOutcome: "neither",
      selectedNamespace: null,
      namespaceSelectionReason: "unavailable",
      hnsResolutionState: "authenticatedAbsent",
      icannResolutionState: "absent"
    }),
    result({
      namespaceOutcome: "indeterminate",
      selectedNamespace: null,
      namespaceSelectionReason: "unavailable",
      decisionFingerprint: null,
      hnsResolutionState: "failed",
      icannResolutionState: "absent"
    }),
    result({
      namespaceOutcome: "indeterminate",
      selectedNamespace: null,
      namespaceSelectionReason: "unavailable",
      decisionFingerprint: null,
      hnsResolutionState: "failed",
      icannResolutionState: "failed"
    })
  ];

  for (const fixture of fixtures) {
    assert.equal(currentSecurityResult(fixture, runtime), fixture);
  }
});

test("security UI never accepts a synthesized result for canonical unavailability", () => {
  const unavailable = result({
    canonicalStatus: "unavailable",
    canonicalStatusUnavailableReason: "evidenceUnavailable",
    namespaceOutcome: "indeterminate",
    selectedNamespace: null,
    namespaceSelectionReason: "unavailable",
    decisionFingerprint: null,
    hnsResolutionState: "unknown",
    icannResolutionState: "unknown",
    actualSelectedTransport: "unavailable",
    peerIdentity: null,
    proxyIdentity: null,
    targetIdentity: null,
    transportPolicy: null,
    providerReadiness: null,
    registryProfile: null,
    registryFingerprint: null,
    protocolVersion: null
  });

  assert.equal(currentSecurityResult(unavailable, runtime), null);
  assert.equal(
    currentSecurityResult(
      { ...unavailable, actualSelectedTransport: "handshakeP2pDnsRelay" },
      runtime
    ),
    null
  );
  assert.equal(
    currentSecurityResult(
      { ...unavailable, peerIdentity: "198.51.100.7:12038" },
      runtime
    ),
    null
  );
});

test("WebPKI CONNECT decisions remain decision-only and epoch-bound", () => {
  const decision = connectDecision();
  assert.equal(currentConnectSecurityDecision(decision, runtime), decision);
  assert.equal(
    currentConnectSecurityDecision(
      { ...decision, httpStatusObserved: true },
      runtime
    ),
    null
  );
  assert.equal(
    currentConnectSecurityDecision({ ...decision, statusCode: 200 }, runtime),
    null
  );
  assert.equal(
    currentConnectSecurityDecision({ ...decision, mainFrame: true }, runtime),
    null
  );
  assert.equal(
    currentConnectSecurityDecision(
      { ...decision, maintenanceEpoch: runtime.securityMaintenanceEpoch - 1 },
      runtime
    ),
    null
  );
});

test("WebPKI CONNECT decisions accept only authenticated ICANN fallback", () => {
  assert.equal(
    currentConnectSecurityDecision(
      connectDecision({
        icannTlsAction: "webPkiInsecureDelegation",
        icannDnssecStatus: "insecureDelegation"
      }),
      runtime
    )?.host,
    "developer.chrome.com"
  );
  for (const invalid of [
    connectDecision({ selectedNamespace: "hns" }),
    connectDecision({ icannTlsAction: "enforceDane" }),
    connectDecision({ icannDnssecStatus: "bogus" }),
    connectDecision({ actualSelectedTransport: "directAuthoritativeTcp" }),
    connectDecision({ port: 0 }),
    connectDecision({ host: "Developer.Chrome.Com" }),
    connectDecision({ host: "bad_host.example" }),
    connectDecision({ observedAtUnixMs: Date.now() + 10 * 60 * 1000 })
  ]) {
    assert.equal(currentConnectSecurityDecision(invalid, runtime), null);
  }
});
