import {
  currentConnectSecurityDecision,
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
document.querySelector("#setup").addEventListener("click", () => {
  void chrome.tabs.create({ url: chrome.runtime.getURL("src/setup.html") });
});
void refresh();

async function retry() {
  await chrome.runtime.sendMessage({ type: "restart" });
  await refresh();
}

async function refresh() {
  const response = await chrome.runtime.sendMessage({
    type: "getStatus",
    tabId: await activeTabId()
  });
  const status = response?.ok ? response.result : { state: "degraded", reason: response?.error };
  renderStatus(status);
}

async function syncHeadersNow() {
  setSyncBusy(true);
  try {
    const response = await chrome.runtime.sendMessage({
      type: "syncHeadersNow",
      tabId: await activeTabId()
    });
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
    const statusResponse = await chrome.runtime.sendMessage({
      type: "getStatus",
      tabId: await activeTabId()
    });
    if (statusResponse?.ok) renderStatus(statusResponse.result);
  } catch {
    // The explicit error below remains useful if status refresh is unavailable.
  }
  setSyncBusy(false, error);
}

function renderStatus(status) {
  const active = status.state === "active" && status.proxyActive === true;
  const security = currentSecurityResult(status.latestMainFrameSecurity, status);
  const connectDecision = connectDecisionForStatus(status);
  const displayedSecurity = security ?? connectDecision;
  renderHeaderStatus(status);
  document.querySelector("#state-title").textContent = active
    ? "Rust security path active"
    : "Handshake browsing blocked";
  document.querySelector("#state-detail").textContent = security
    ? namespaceSummary(security, status.latestMainFrameSecurityReceiptState)
    : connectDecision
      ? connectDecisionSummary(
          connectDecision,
          status.latestMainFrameSecurityReceiptState,
          status.latestMainFrameSecurityReceiptSource
        )
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
  document.querySelector("#security-origin").textContent =
    displayedSecurity?.host ?? "—";
  document.querySelector("#security-proof-anchor").textContent =
    pageProofAnchor(displayedSecurity);
  document.querySelector("#security-namespace-outcome").textContent = displayedSecurity
    ? namespaceOutcomeLabel(displayedSecurity.namespaceOutcome)
    : "—";
  document.querySelector("#security-namespace-selected").textContent = displayedSecurity
    ? namespaceLabel(displayedSecurity.selectedNamespace)
    : "—";
  document.querySelector("#security-namespace-reason").textContent = displayedSecurity
    ? namespaceReasonLabel(displayedSecurity.namespaceSelectionReason)
    : "—";
  document.querySelector("#security-hns-resolution").textContent = displayedSecurity
    ? stateLabel(displayedSecurity.hnsResolutionState)
    : "—";
  document.querySelector("#security-icann-resolution").textContent = displayedSecurity
    ? stateLabel(displayedSecurity.icannResolutionState)
    : "—";
  document.querySelector("#security-transport").textContent = displayedSecurity
    ? transportLabel(displayedSecurity.actualSelectedTransport)
    : "—";
  document.querySelector("#security-receipt-source").textContent = displayedSecurity
    ? receiptSourceLabel(status.latestMainFrameSecurityReceiptSource)
    : "—";
  document.querySelector("#security-hns-proof").textContent = displayedSecurity
    ? stateLabel(displayedSecurity.localHnsProofState)
    : "—";
  document.querySelector("#security-dnssec").textContent = displayedSecurity
    ? stateLabel(displayedSecurity.localDnssecState)
    : "—";
  document.querySelector("#security-tlsa").textContent = displayedSecurity
    ? stateLabel(displayedSecurity.localTlsaState)
    : "—";
  document.querySelector("#security-dane").textContent = displayedSecurity
    ? stateLabel(displayedSecurity.localDaneState)
    : "—";
  document.querySelector("#security-event").textContent =
    displayedSecurity?.eventSequence ?? "—";
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

function connectDecisionForStatus(status) {
  const receipt = status.latestMainFrameConnectDecisionReceipt;
  const decision = receipt?.nativeDecision;
  if (
    receipt?.schemaVersion !== 1 ||
    receipt.receiptKind !== "browserWebPkiDocumentReceipt" ||
    !decision
  ) {
    return null;
  }
  return currentConnectSecurityDecision(decision, {
    ...status,
    securityMaintenanceEpoch: decision.maintenanceEpoch
  });
}

function connectDecisionSummary(decision, receiptState, receiptSource) {
  const namespace = namespaceSummary(decision, receiptState);
  if (receiptSource === "browserWebPkiConnectionReuse") {
    return `${namespace} Chromium owns end-to-end WebPKI for this document over a retained same-host tunnel that Rust authorized in its maintenance epoch.`;
  }
  if (receiptSource === "browserWebPkiCacheReceipt") {
    return `${namespace} Chromium owns end-to-end WebPKI; this exact cached URL retains its correlated Rust ICANN fallback decision.`;
  }
  return `${namespace} Chromium owns end-to-end WebPKI for this document; Rust authenticated the ICANN namespace and WebPKI fallback decision.`;
}

function receiptSourceLabel(source) {
  const labels = {
    rustHttpResponse: "Rust-observed origin response",
    rustHttpResponseCache: "Exact-URL Rust receipt from Chromium cache",
    browserWebPkiPassthrough: "Rust CONNECT decision + Chromium completion",
    browserWebPkiConnectionReuse: "Current-epoch Rust decision for reused tunnel",
    browserWebPkiCacheReceipt: "Exact-URL WebPKI decision from Chromium cache"
  };
  return labels[source] ?? "Unavailable";
}

function namespaceSummary(security, receiptState) {
  const outcome = namespaceOutcomeLabel(security.namespaceOutcome);
  if (security.namespaceOutcome === "bothDivergent") {
    return `${outcome} for ${security.host}; ${namespaceLabel(
      security.selectedNamespace
    )} was selected by ${namespaceReasonLabel(
      security.namespaceSelectionReason
    )}.${receiptQualifier(receiptState)}`;
  }
  if (security.selectedNamespace) {
    const selected = namespaceLabel(security.selectedNamespace);
    if (receiptState === "committedBeforeHeaderMaintenance") {
      return `${outcome} for ${security.host}; ${selected} was selected for this committed document before the latest header sync.`;
    }
    if (receiptState === "browserCacheReceipt") {
      return `${outcome} for ${security.host}; ${selected} was verified when this exact URL entered Chromium's cache.`;
    }
    if (receiptState === "restoredDocument") {
      return `${outcome} for ${security.host}; ${selected} was verified for this restored document.`;
    }
    return `${outcome} for ${security.host}; ${selected} is active.`;
  }
  return `${outcome} for ${security.host}; the request failed closed.${receiptQualifier(
    receiptState
  )}`;
}

function receiptQualifier(receiptState) {
  if (receiptState === "committedBeforeHeaderMaintenance") {
    return " This immutable receipt belongs to the committed document and predates the latest header sync.";
  }
  if (receiptState === "browserCacheReceipt") {
    return " This exact URL was restored from Chromium's cache with its same-generation receipt.";
  }
  if (receiptState === "restoredDocument") {
    return " This is the same checked document restored from browser history.";
  }
  return "";
}

async function activeTabId() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabId = tabs?.[0]?.id;
  return Number.isSafeInteger(tabId) && tabId >= 0 ? tabId : null;
}
