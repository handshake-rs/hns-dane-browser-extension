(() => {
  "use strict";
  const SCHEMA_VERSION = 1;
  const CHANNEL = "hns-wallet-provider";
  const MAX_PENDING = 32;
  const MAX_MESSAGE_BYTES = 64 * 1024;
  const MAX_INITIALIZE_RETRIES = 4;
  const INITIALIZE_RETRY_DELAYS_MS = [150, 350, 750, 1500];
  let binding = null;
  let lastSequence = 0;
  let initialization = null;
  let initializeRetryCount = 0;
  let initializeRetryTimer = null;
  let initializedDocumentUrl = location.href;
  const pending = new Set();

  window.addEventListener("message", (event) => {
    if (
      event.source !== window ||
      event.origin !== location.origin ||
      !isPageRequest(event.data)
    ) {
      return;
    }
    void forwardPageRequest(event.data);
  });

  chrome.runtime.onMessage.addListener((message) => {
    if (
      isRecord(message) &&
      message.schemaVersion === SCHEMA_VERSION &&
      message.type === "walletProviderBootstrapReady"
    ) {
      scheduleInitialize(0);
      return false;
    }
    if (
      isRecord(message) &&
      message.schemaVersion === SCHEMA_VERSION &&
      message.type === "walletProviderInvalidate"
    ) {
      binding = null;
      initializeRetryCount = 0;
      clearInitializeRetry();
      postToPage({ kind: "event", event: "disconnect", payload: null });
      return false;
    }
    if (
      !binding ||
      !isRecord(message) ||
      message.type !== "walletProviderEvent" ||
      message.schemaVersion !== SCHEMA_VERSION ||
      !sameBinding(message.binding, binding) ||
      typeof message.event !== "string"
    ) {
      return false;
    }
    postToPage({
      kind: "event",
      event: message.event,
      payload: message.payload ?? null
    });
    return false;
  });

  void initialize();

  async function initialize() {
    if (initialization) return initialization;
    initialization = sendRuntimeMessage({
      type: "walletProviderInitialize",
      schemaVersion: SCHEMA_VERSION,
      origin: location.origin
    })
      .then((response) => {
        if (response?.ok === true && response.result?.available === true) {
          binding = response.result.binding;
          initializedDocumentUrl = location.href;
          initializeRetryCount = 0;
          clearInitializeRetry();
          return true;
        }
        binding = null;
        if (response?.error?.code === "browserAuthorityDenied") {
          scheduleInitializeRetry();
        }
        return false;
      })
      .catch(() => {
        binding = null;
        return false;
      })
      .finally(() => {
        initialization = null;
      });
    return initialization;
  }

  function scheduleInitializeRetry() {
    if (initializeRetryCount >= MAX_INITIALIZE_RETRIES) return;
    const delay = INITIALIZE_RETRY_DELAYS_MS[initializeRetryCount];
    initializeRetryCount += 1;
    scheduleInitialize(delay);
  }

  function scheduleInitialize(delay) {
    clearInitializeRetry();
    initializeRetryTimer = setTimeout(() => {
      initializeRetryTimer = null;
      void initialize();
    }, delay);
  }

  function clearInitializeRetry() {
    if (initializeRetryTimer != null) clearTimeout(initializeRetryTimer);
    initializeRetryTimer = null;
  }

  async function forwardPageRequest(request) {
    if (
      request.sequence <= lastSequence ||
      pending.has(request.requestId) ||
      pending.size >= MAX_PENDING
    ) {
      postError(request, "replay", "provider request was replayed or capacity is exhausted");
      return;
    }
    lastSequence = request.sequence;
    pending.add(request.requestId);
    try {
      if (initializedDocumentUrl !== location.href) binding = null;
      if (!binding) await initialize();
      if (!binding) {
        postError(request, "walletUnavailable", "wallet provider is unavailable");
        return;
      }
      let response = await sendRuntimeMessage({
        type: "walletProviderRequest",
        schemaVersion: SCHEMA_VERSION,
        origin: location.origin,
        binding,
        request
      });
      if (
        response?.ok === false &&
        [
          "staleContext",
          "permissionGenerationChanged",
          "walletSessionChanged"
        ].includes(response.error?.code)
      ) {
        binding = null;
      }
      postToPage({
        kind: "response",
        requestId: request.requestId,
        sequence: request.sequence,
        ok: response?.ok === true,
        ...(response?.ok === true
          ? { result: response.result }
          : {
              error: isRecord(response?.error)
                ? response.error
                : { code: "internalError", message: "wallet request failed" }
            })
      });
    } catch {
      postError(request, "extensionUnavailable", "wallet extension is unavailable");
    } finally {
      pending.delete(request.requestId);
    }
  }

  function postError(request, code, message) {
    postToPage({
      kind: "response",
      requestId: request.requestId,
      sequence: request.sequence,
      ok: false,
      error: { code, message }
    });
  }

  function postToPage(fields) {
    window.postMessage(
      {
        channel: CHANNEL,
        schemaVersion: SCHEMA_VERSION,
        direction: "extensionToPage",
        ...fields
      },
      location.origin
    );
  }

  function sendRuntimeMessage(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        const error = chrome.runtime.lastError;
        if (error) reject(new Error(error.message));
        else resolve(response);
      });
    });
  }

  function isPageRequest(value) {
    return (
      isRecord(value) &&
      value.channel === CHANNEL &&
      value.schemaVersion === SCHEMA_VERSION &&
      value.direction === "pageToExtension" &&
      value.kind === "request" &&
      typeof value.requestId === "string" &&
      value.requestId.length <= 96 &&
      /^[A-Za-z0-9._:-]+$/.test(value.requestId) &&
      Number.isSafeInteger(value.sequence) &&
      value.sequence >= 1 &&
      boundedJson(value)
    );
  }

  function boundedJson(value) {
    try {
      const seen = new Set();
      const visit = (candidate, depth) => {
        if (depth > 12) throw new Error("depth");
        if (candidate == null || typeof candidate === "boolean") return;
        if (typeof candidate === "string") {
          if (candidate.length > 16 * 1024) throw new Error("string");
          return;
        }
        if (typeof candidate === "number") {
          if (!Number.isSafeInteger(candidate)) throw new Error("number");
          return;
        }
        if (typeof candidate !== "object" || seen.has(candidate)) {
          throw new Error("object");
        }
        const entries = Array.isArray(candidate)
          ? [...candidate.entries()]
          : Object.entries(candidate);
        if (entries.length > 128) throw new Error("entries");
        seen.add(candidate);
        for (const [key, child] of entries) {
          if (["__proto__", "prototype", "constructor"].includes(String(key))) {
            throw new Error("key");
          }
          visit(child, depth + 1);
        }
        seen.delete(candidate);
      };
      visit(value, 0);
      return new TextEncoder().encode(JSON.stringify(value)).length <= MAX_MESSAGE_BYTES;
    } catch {
      return false;
    }
  }

  function sameBinding(left, right) {
    const fields = [
      "origin",
      "namespace",
      "browserAuthoritySession",
      "runtimeGeneration",
      "policyGeneration",
      "navigationGeneration",
      "walletSession",
      "permissionGeneration",
      "documentId"
    ];
    return isRecord(left) && fields.every((field) => left[field] === right[field]);
  }

  function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }
})();
