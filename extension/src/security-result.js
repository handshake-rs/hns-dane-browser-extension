const SECURITY_RESULT_SCHEMA_VERSION = 1;

const TRANSPORT_LABELS = Object.freeze({
  directAuthoritativeUdp: "Direct authoritative UDP",
  directAuthoritativeTcp: "Direct authoritative TCP",
  authenticatedAuthoritativeDoh: "Authenticated authoritative DoH",
  handshakeP2pOdoh: "Handshake P2P ODoH",
  handshakeP2pDnsRelay: "Handshake P2P DNS Relay",
  unavailable: "Unavailable"
});

export function currentSecurityResult(candidate, runtime) {
  if (!isRecord(candidate) || !isRecord(runtime)) return null;
  if (
    candidate.schemaVersion !== SECURITY_RESULT_SCHEMA_VERSION ||
    typeof candidate.runtimeSession !== "string" ||
    candidate.runtimeSession !== runtime.runtimeSession ||
    !Number.isSafeInteger(candidate.runtimeGeneration) ||
    candidate.runtimeGeneration !== runtime.runtimeGeneration ||
    !Number.isSafeInteger(candidate.policyGeneration) ||
    candidate.policyGeneration !== runtime.policyGeneration ||
    !Number.isSafeInteger(candidate.eventSequence) ||
    candidate.eventSequence < 1 ||
    typeof candidate.host !== "string" ||
    candidate.host.length < 1 ||
    candidate.host.length > 253 ||
    !Object.hasOwn(TRANSPORT_LABELS, candidate.actualSelectedTransport)
  ) {
    return null;
  }
  return candidate;
}

export function transportLabel(transport) {
  return TRANSPORT_LABELS[transport] ?? TRANSPORT_LABELS.unavailable;
}

export function stateLabel(state) {
  if (typeof state !== "string" || state.length === 0) return "Not evaluated";
  return state
    .replaceAll("_", " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (first) => first.toUpperCase());
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
