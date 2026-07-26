import {
  currentSecurityResult,
  namespaceLabel,
  namespaceOutcomeLabel,
  namespaceReasonLabel,
  stateLabel,
  transportLabel
} from "./security-result.js";

document.querySelector("#retry").addEventListener("click", () => void retry());
document.querySelector("#settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
void refresh();

async function retry() {
  await chrome.runtime.sendMessage({ type: "restart" });
  await refresh();
}

async function refresh() {
  const response = await chrome.runtime.sendMessage({ type: "getStatus" });
  const status = response?.ok ? response.result : { state: "degraded", reason: response?.error };
  const active = status.state === "active";
  const security = currentSecurityResult(status.latestMainFrameSecurity, status);
  document.querySelector("#state-title").textContent = active
    ? "Rust security path active"
    : "Handshake browsing blocked";
  document.querySelector("#state-detail").textContent = security
    ? namespaceSummary(security)
    : active
      ? "No browser main-frame security result has been recorded in this proxy generation."
      : `Fail-closed reason: ${status.reason ?? status.state ?? "runtime unavailable"}`;
  document.querySelector("#runtime-generation").textContent =
    status.runtimeGeneration ?? "—";
  document.querySelector("#policy-generation").textContent =
    status.policyGeneration ?? "—";
  document.querySelector("#ca-state").textContent = status.caReady ? "Installed" : "Not ready";
  document.querySelector("#security-origin").textContent = security?.host ?? "—";
  document.querySelector("#security-namespace-outcome").textContent = security
    ? namespaceOutcomeLabel(security.namespaceOutcome)
    : "—";
  document.querySelector("#security-namespace-selected").textContent = security
    ? namespaceLabel(security.selectedNamespace)
    : "—";
  document.querySelector("#security-namespace-reason").textContent = security
    ? namespaceReasonLabel(security.namespaceSelectionReason)
    : "—";
  document.querySelector("#security-hns-resolution").textContent = security
    ? stateLabel(security.hnsResolutionState)
    : "—";
  document.querySelector("#security-icann-resolution").textContent = security
    ? stateLabel(security.icannResolutionState)
    : "—";
  document.querySelector("#security-transport").textContent = security
    ? transportLabel(security.actualSelectedTransport)
    : "—";
  document.querySelector("#security-hns-proof").textContent = security
    ? stateLabel(security.localHnsProofState)
    : "—";
  document.querySelector("#security-dnssec").textContent = security
    ? stateLabel(security.localDnssecState)
    : "—";
  document.querySelector("#security-tlsa").textContent = security
    ? stateLabel(security.localTlsaState)
    : "—";
  document.querySelector("#security-dane").textContent = security
    ? stateLabel(security.localDaneState)
    : "—";
  document.querySelector("#security-event").textContent =
    security?.eventSequence ?? "—";
}

function namespaceSummary(security) {
  const outcome = namespaceOutcomeLabel(security.namespaceOutcome);
  if (security.namespaceOutcome === "bothDivergent") {
    return `${outcome} for ${security.host}; ${namespaceLabel(
      security.selectedNamespace
    )} was selected by ${namespaceReasonLabel(security.namespaceSelectionReason)}.`;
  }
  if (security.selectedNamespace) {
    return `${outcome} for ${security.host}; ${namespaceLabel(
      security.selectedNamespace
    )} is active.`;
  }
  return `${outcome} for ${security.host}; the request failed closed.`;
}
