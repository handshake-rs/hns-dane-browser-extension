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
  document.querySelector("#state-title").textContent = active
    ? "Rust security path active"
    : "Handshake browsing blocked";
  document.querySelector("#state-detail").textContent = active
    ? "Only HNS names use the authenticated local proxy. DNSSEC and DANE are verified in Rust."
    : `Fail-closed reason: ${status.reason ?? status.state ?? "runtime unavailable"}`;
  document.querySelector("#runtime-generation").textContent =
    status.runtimeGeneration ?? "—";
  document.querySelector("#policy-generation").textContent =
    status.policyGeneration ?? "—";
  document.querySelector("#ca-state").textContent = status.caReady ? "Installed" : "Not ready";
}
