import { validNavigationGateTarget } from "./navigation-gate.js";

const POLL_INTERVAL_MS = 500;
const RESUME_KEY = "hnsNavigationGateResume";
const message = document.querySelector("#message");
const targetLabel = document.querySelector("#target");
const retry = document.querySelector("#retry");
let target = validNavigationGateTarget(location.hash.slice(1));

if (window.top !== window) {
  message.textContent = "This waiting-page address is invalid.";
  retry.hidden = true;
} else {
  targetLabel.textContent = target;
  retry.addEventListener("click", () => {
    sessionStorage.removeItem(RESUME_KEY);
    retry.hidden = true;
    message.textContent = "Waiting for current proxy and name-tree authority…";
    void poll();
  });
  void initialize();
}

async function initialize() {
  await adoptBootstrapTarget();
  if (target == null) {
    message.textContent =
      "The secure proxy is starting. When it is ready, retry the address from your browser history.";
    targetLabel.textContent = "Your original address was not exposed to the network.";
    retry.hidden = true;
  } else {
    targetLabel.textContent = target;
  }
  await poll();
}

async function poll() {
  while (true) {
    await adoptBootstrapTarget();
    const status = await sendGateStatus().catch(() => null);
    if (status?.ready === true && typeof status.openRevision === "string") {
      if (target == null) {
        message.textContent =
          "The secure proxy is ready. Retry the address from your browser history.";
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        continue;
      }
      const resumed = readResumeMarker();
      if (
        resumed?.target === target
      ) {
        message.textContent =
          "The proxy is ready, but this navigation already resumed once. Retry manually to avoid a proxy-restart loop.";
        retry.hidden = false;
        return;
      }
      sessionStorage.setItem(
        RESUME_KEY,
        JSON.stringify({ openRevision: status.openRevision, target })
      );
      location.replace(target);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
}

async function adoptBootstrapTarget() {
  if (target != null) return;
  const bootstrap = await sendGateMessage("navigationGateBootstrap").catch(
    () => null
  );
  target = validNavigationGateTarget(bootstrap?.target);
  if (target != null) targetLabel.textContent = target;
}

function readResumeMarker() {
  try {
    const marker = JSON.parse(sessionStorage.getItem(RESUME_KEY));
    return marker && typeof marker === "object" ? marker : null;
  } catch {
    return null;
  }
}

function sendGateStatus() {
  return sendGateMessage("navigationGateStatus");
}

function sendGateMessage(type) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { type },
      (response) => {
        const error = chrome.runtime.lastError;
        if (error) {
          reject(new Error(error.message));
          return;
        }
        if (!response?.ok) {
          reject(new Error(response?.error ?? "navigation gate status unavailable"));
          return;
        }
        resolve(response.result);
      }
    );
  });
}
