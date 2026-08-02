const params = new URLSearchParams(location.search);
const approvalId = params.get("id");
const title = document.querySelector("#title");
const origin = document.querySelector("#origin");
const status = document.querySelector("#status");
const summary = document.querySelector("#summary");
const approve = document.querySelector("#approve");
const reject = document.querySelector("#reject");
let prompt = null;

approve.addEventListener("click", () => void decide("approve"));
reject.addEventListener("click", () => void decide("reject"));
void load();

async function load() {
  setEnabled(false);
  const response = await send({ type: "walletApprovalGet", approvalId });
  if (response?.ok !== true || !response.result) {
    status.textContent = response?.error ?? "This request is unavailable or expired.";
    return;
  }
  prompt = response.result;
  title.textContent = label(prompt.kind);
  origin.textContent = `Requested by ${prompt.origin}`;
  status.textContent = `${prompt.method} · expires ${new Date(
    prompt.expiresAtUnixMs
  ).toLocaleTimeString()}`;
  summary.replaceChildren(
    ...Object.entries(prompt.summary).flatMap(([field, value]) => {
      const term = document.createElement("dt");
      term.textContent = field.replace(/([A-Z])/g, " $1").toLowerCase();
      const detail = document.createElement("dd");
      detail.textContent = Array.isArray(value) ? value.join(", ") : String(value);
      return [term, detail];
    })
  );
  setEnabled(true);
}

async function decide(decision) {
  if (!prompt) return;
  setEnabled(false);
  status.textContent = decision === "approve" ? "Approving…" : "Rejecting…";
  const response = await send({
    type: "walletApprovalDecision",
    approvalId: prompt.approvalId,
    decision
  });
  if (response?.ok === true) {
    status.textContent = decision === "approve" ? "Approved." : "Rejected.";
    setTimeout(() => window.close(), 350);
  } else {
    status.textContent = response?.error ?? "The native wallet rejected the decision.";
    setEnabled(true);
  }
}

function send(message) {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}

function setEnabled(enabled) {
  approve.disabled = !enabled;
  reject.disabled = !enabled;
}

function label(kind) {
  return {
    permissions: "Approve wallet permissions",
    valueMovement: "Approve value movement",
    typedMessage: "Approve typed message",
    marketplaceMatch: "Approve marketplace match"
  }[kind] ?? "Review wallet request";
}
