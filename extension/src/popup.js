import {
  currentSecurityResult,
  namespaceLabel,
  namespaceOutcomeLabel,
  namespaceReasonLabel,
  stateLabel,
  transportLabel
} from "./security-result.js";
import { headerChainView, pageProofAnchor } from "./header-status.js";

document.querySelector("#retry").addEventListener("click", () => void retry());
document
  .querySelector("#sync-headers")
  .addEventListener("click", () => void syncHeadersNow());
document.querySelector("#settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
void refresh();

async function retry() {
  await chrome.runtime.sendMessage({ type: "restart" });
  await refresh();
}

async function refresh() {
  const response = await chrome.runtime.sendMessage({ type: "getStatus" });
  const status = response?.ok ? response.result : { state: "degraded", reason: response?.error };
  renderStatus(status);
}

async function syncHeadersNow() {
  setSyncBusy(true);
  try {
    const response = await chrome.runtime.sendMessage({ type: "syncHeadersNow" });
    if (response?.ok) {
      renderStatus(response.result);
      return;
    }
    await showSyncError(response?.error ?? "Header sync failed");
  } catch (error) {
    await showSyncError(error instanceof Error ? error.message : String(error));
  }
}

async function showSyncError(error) {
  try {
    const statusResponse = await chrome.runtime.sendMessage({ type: "getStatus" });
    if (statusResponse?.ok) renderStatus(statusResponse.result);
  } catch {
    // The explicit error below remains useful if status refresh is unavailable.
  }
  setSyncBusy(false, error);
}

function renderStatus(status) {
  const active = status.state === "active";
  const security = currentSecurityResult(status.latestMainFrameSecurity, status);
  renderHeaderStatus(status);
  document.querySelector("#state-title").textContent = active
    ? "Rust security path active"
    : "Handshake browsing blocked";
  document.querySelector("#state-detail").textContent = security
    ? namespaceSummary(security)
    : active
      ? status.latestMainFrameSecurityUnavailableReason
        ? `Checked main-frame security status unavailable: ${stateLabel(
            status.latestMainFrameSecurityUnavailableReason
          )}.`
        : "No browser main-frame security result has been recorded in this proxy generation."
      : `Fail-closed reason: ${status.reason ?? status.state ?? "runtime unavailable"}`;
  document.querySelector("#runtime-generation").textContent =
    status.runtimeGeneration ?? "—";
  document.querySelector("#policy-generation").textContent =
    status.policyGeneration ?? "—";
  document.querySelector("#ca-state").textContent = status.caReady ? "Installed" : "Not ready";
  document.querySelector("#security-origin").textContent = security?.host ?? "—";
  document.querySelector("#security-proof-anchor").textContent = pageProofAnchor(security);
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

function renderHeaderStatus(status) {
  const view = headerChainView(status.headerSync, {
    syncing: status.headerSyncInProgress,
    error: status.headerSyncError
  });
  document.querySelector("#header-best-height").textContent = view.bestHeight;
  document.querySelector("#header-peer-height").textContent = view.peerHeight;
  document.querySelector("#header-estimated-height").textContent = view.estimatedHeight;
  document.querySelector("#header-target-height").textContent = view.targetHeight;
  document.querySelector("#header-target-groups").textContent = view.targetPeerGroups;
  document.querySelector("#header-lag").textContent = view.lag;
  document.querySelector("#header-threshold").textContent = view.threshold;
  document.querySelector("#header-state").textContent = view.state;
  document.querySelector("#header-detail").textContent = view.detail;
  const button = document.querySelector("#sync-headers");
  button.disabled = status.state !== "active" || status.headerSyncInProgress === true;
  button.textContent =
    status.headerSyncInProgress === true ? "Syncing headers…" : "Sync headers now";
}

function setSyncBusy(syncing, error = null) {
  const button = document.querySelector("#sync-headers");
  button.disabled = syncing;
  button.textContent = syncing ? "Syncing headers…" : "Sync headers now";
  document.querySelector("#header-state").textContent = syncing ? "Syncing" : "Sync failed";
  document.querySelector("#header-detail").textContent = syncing
    ? "Synchronizing validated headers with Handshake peers…"
    : `The header sync request failed: ${String(error).slice(0, 512)}`;
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
