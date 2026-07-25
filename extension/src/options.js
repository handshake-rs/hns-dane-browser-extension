import { DEFAULT_POLICY, normalizePolicy } from "./policy.js";

const form = document.querySelector("#policy-form");
const statusOutput = document.querySelector("#status");
const diagnosticOutput = document.querySelector("#diagnostic-output");
const fields = {
  p2pDnsRelay: document.querySelector("#p2p-dns-relay"),
  p2pOdoh: document.querySelector("#p2p-odoh"),
  privacyDowngrade: document.querySelector("#privacy-downgrade"),
  hnsr: document.querySelector("#hnsr"),
  experimentalWireProfile: document.querySelector("#wire-profile")
};

form.addEventListener("submit", (event) => {
  event.preventDefault();
  void applyPolicy();
});

document.querySelector("#diagnostics").addEventListener("click", () => {
  void refreshDiagnostics();
});

void initialize();

async function initialize() {
  const stored = await chrome.storage.local.get(["policy"]);
  renderPolicy(normalizePolicy(stored.policy ?? DEFAULT_POLICY));
  await refreshStatus();
}

async function applyPolicy() {
  setFormDisabled(true);
  try {
    const response = await chrome.runtime.sendMessage({
      type: "setPolicy",
      policy: readPolicy()
    });
    if (!response?.ok) throw new Error(response?.error ?? "policy update failed");
    statusOutput.textContent = JSON.stringify(response.result, null, 2);
  } catch (error) {
    statusOutput.textContent = `Fail closed: ${error instanceof Error ? error.message : error}`;
  } finally {
    setFormDisabled(false);
  }
}

async function refreshStatus() {
  const response = await chrome.runtime.sendMessage({ type: "getStatus" });
  statusOutput.textContent = response?.ok
    ? JSON.stringify(response.result, null, 2)
    : `Unavailable: ${response?.error ?? "unknown error"}`;
}

async function refreshDiagnostics() {
  diagnosticOutput.textContent = "Loading…";
  const response = await chrome.runtime.sendMessage({ type: "diagnostics" });
  diagnosticOutput.textContent = response?.ok
    ? JSON.stringify(response.result, null, 2)
    : `Unavailable: ${response?.error ?? "unknown error"}`;
}

function readPolicy() {
  return normalizePolicy({
    p2pDnsRelay: fields.p2pDnsRelay.checked,
    p2pOdoh: fields.p2pOdoh.value,
    privacyDowngrade: fields.privacyDowngrade.value,
    hnsr: fields.hnsr.value,
    experimentalWireProfile: fields.experimentalWireProfile.value
  });
}

function renderPolicy(policy) {
  fields.p2pDnsRelay.checked = policy.p2pDnsRelay;
  fields.p2pOdoh.value = policy.p2pOdoh;
  fields.privacyDowngrade.value = policy.privacyDowngrade;
  fields.hnsr.value = policy.hnsr;
  fields.experimentalWireProfile.value = policy.experimentalWireProfile;
}

function setFormDisabled(disabled) {
  for (const element of form.elements) element.disabled = disabled;
}
