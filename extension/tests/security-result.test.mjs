import test from "node:test";
import assert from "node:assert/strict";
import {
  currentSecurityResult,
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
    schemaVersion: 1,
    eventSequence: 11,
    runtimeSession: "session-a",
    runtimeGeneration: 7,
    policyGeneration: 3,
    host: "welcome",
    actualSelectedTransport: "directAuthoritativeTcp",
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
});
