import {
  currentSecurityResult,
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
    ? `Rust recorded the latest HNS main-frame result for ${security.host}.`
    : active
      ? "No HNS main-frame security result has been recorded in this proxy generation."
      : `Fail-closed reason: ${status.reason ?? status.state ?? "runtime unavailable"}`;
  document.querySelector("#runtime-generation").textContent =
    status.runtimeGeneration ?? "—";
  document.querySelector("#policy-generation").textContent =
    status.policyGeneration ?? "—";
  document.querySelector("#ca-state").textContent = status.caReady ? "Installed" : "Not ready";
  document.querySelector("#security-origin").textContent = security?.host ?? "—";
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
