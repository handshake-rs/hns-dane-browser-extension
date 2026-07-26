import test from "node:test";
import assert from "node:assert/strict";
import {
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
  policyGeneration: 3
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
  assert.equal(transportLabel("futureTransport"), "Unavailable");
  assert.equal(stateLabel("notEvaluated"), "Not Evaluated");
  assert.equal(stateLabel("not_evaluated"), "Not evaluated");
  assert.equal(namespaceOutcomeLabel("bothDivergent"), "Both roots differ");
  assert.equal(namespaceLabel("icann"), "ICANN");
  assert.equal(namespaceReasonLabel("stickyBinding"), "sticky site binding");
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
      icannResolutionState: "unknown"
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
