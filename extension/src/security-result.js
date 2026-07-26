const SECURITY_RESULT_SCHEMA_VERSION = 2;

const TRANSPORT_LABELS = Object.freeze({
  directAuthoritativeUdp: "Direct authoritative UDP",
  directAuthoritativeTcp: "Direct authoritative TCP",
  authenticatedAuthoritativeDoh: "Authenticated authoritative DoH",
  icannDoh: "Validating ICANN DoH",
  handshakeP2pOdoh: "Handshake P2P ODoH",
  handshakeP2pDnsRelay: "Handshake P2P DNS Relay",
  unavailable: "Unavailable"
});

const NAMESPACE_OUTCOME_LABELS = Object.freeze({
  hnsOnly: "HNS only",
  icannOnly: "ICANN only",
  bothConvergent: "Both roots converge",
  bothDivergent: "Both roots differ",
  neither: "Neither root resolves",
  indeterminate: "Namespace resolution indeterminate"
});

const NAMESPACE_LABELS = Object.freeze({
  hns: "HNS",
  icann: "ICANN"
});

const NAMESPACE_REASON_LABELS = Object.freeze({
  explicitPin: "explicit pin",
  stickyBinding: "sticky site binding",
  icannDefault: "ICANN default",
  onlyAvailableRoot: "only resolving root",
  convergentDefault: "convergent-root default",
  unavailable: "unavailable"
});

const HNS_ROOT_STATES = new Set([
  "securePresent",
  "authenticatedAbsent",
  "failed",
  "unknown"
]);

const ICANN_ROOT_STATES = new Set([
  "securePresent",
  "insecurePresent",
  "authenticatedAbsent",
  "insecureAbsent",
  "failed",
  "unknown"
]);

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
    !Object.hasOwn(NAMESPACE_OUTCOME_LABELS, candidate.namespaceOutcome) ||
    !Object.hasOwn(NAMESPACE_REASON_LABELS, candidate.namespaceSelectionReason) ||
    !HNS_ROOT_STATES.has(candidate.hnsResolutionState) ||
    !ICANN_ROOT_STATES.has(candidate.icannResolutionState) ||
    !validNamespaceDecision(candidate) ||
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

export function namespaceOutcomeLabel(outcome) {
  return NAMESPACE_OUTCOME_LABELS[outcome] ?? NAMESPACE_OUTCOME_LABELS.indeterminate;
}

export function namespaceLabel(namespace) {
  return NAMESPACE_LABELS[namespace] ?? "None";
}

export function namespaceReasonLabel(reason) {
  return NAMESPACE_REASON_LABELS[reason] ?? NAMESPACE_REASON_LABELS.unavailable;
}

function validSelectedNamespace(outcome, namespace) {
  if (outcome === "hnsOnly") return namespace === "hns";
  if (outcome === "icannOnly") return namespace === "icann";
  if (outcome === "bothConvergent" || outcome === "bothDivergent") {
    return Object.hasOwn(NAMESPACE_LABELS, namespace);
  }
  return namespace == null;
}

function validNamespaceDecision(candidate) {
  const {
    namespaceOutcome: outcome,
    selectedNamespace: selected,
    namespaceSelectionReason: reason,
    hnsResolutionState: hns,
    icannResolutionState: icann
  } = candidate;
  if (!validSelectedNamespace(outcome, selected)) return false;

  if (outcome === "hnsOnly") {
    return (
      hns === "securePresent" &&
      ["authenticatedAbsent", "insecureAbsent"].includes(icann) &&
      ["explicitPin", "stickyBinding", "onlyAvailableRoot"].includes(reason)
    );
  }
  if (outcome === "icannOnly") {
    return (
      ["securePresent", "insecurePresent"].includes(icann) &&
      hns === "authenticatedAbsent" &&
      ["explicitPin", "stickyBinding", "onlyAvailableRoot"].includes(reason)
    );
  }
  if (outcome === "bothConvergent") {
    return (
      hns === "securePresent" &&
      ["securePresent", "insecurePresent"].includes(icann) &&
      ["explicitPin", "stickyBinding", "convergentDefault"].includes(reason)
    );
  }
  if (outcome === "bothDivergent") {
    return (
      hns === "securePresent" &&
      ["securePresent", "insecurePresent"].includes(icann) &&
      ["explicitPin", "stickyBinding", "icannDefault"].includes(reason)
    );
  }
  if (outcome === "neither") {
    return (
      hns === "authenticatedAbsent" &&
      ["authenticatedAbsent", "insecureAbsent"].includes(icann) &&
      reason === "unavailable"
    );
  }
  return (
    outcome === "indeterminate" &&
    selected == null &&
    reason === "unavailable" &&
    [hns, icann].some((state) => state === "failed" || state === "unknown")
  );
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
