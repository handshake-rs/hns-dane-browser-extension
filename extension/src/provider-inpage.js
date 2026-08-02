(() => {
  "use strict";
  const INSTALL_MARKER = "__hnsWalletProviderV1__";
  if (Object.prototype.hasOwnProperty.call(window, INSTALL_MARKER)) return;
  Object.defineProperty(window, INSTALL_MARKER, {
    value: true,
    writable: false,
    enumerable: false,
    configurable: false
  });

  const SCHEMA_VERSION = 1;
  const CHANNEL = "hns-wallet-provider";
  const REQUEST_TIMEOUT_MS = 2 * 60 * 1000;
  const MAX_PENDING = 32;
  const EVENT_NAMES = new Set([
    "connect",
    "disconnect",
    "permissionsChanged",
    "modulesChanged",
    "accountsChanged",
    "balancesChanged",
    "transactionsChanged",
    "namesChanged",
    "nameMarketChanged",
    "priceRoundChanged",
    "marketIntentChanged",
    "swapSessionChanged",
    "walletLocked"
  ]);
  const listeners = new Map();
  const pending = new Map();
  let sequence = 0;

  class HandshakeProviderError extends Error {
    constructor(code, message) {
      super(message);
      this.name = "HandshakeProviderError";
      this.code = code;
    }
  }

  const provider = Object.freeze({
    request(args) {
      if (
        !isRecord(args) ||
        typeof args.method !== "string" ||
        args.method.length < 1 ||
        args.method.length > 128
      ) {
        return Promise.reject(
          new HandshakeProviderError("invalidRequest", "request requires a method")
        );
      }
      if (pending.size >= MAX_PENDING) {
        return Promise.reject(
          new HandshakeProviderError("rateLimited", "too many requests are pending")
        );
      }
      if (!boundedRequest(args)) {
        return Promise.reject(
          new HandshakeProviderError(
            "requestTooLarge",
            "wallet request is not bounded JSON"
          )
        );
      }
      const requestSequence = ++sequence;
      const requestId = `page-${Date.now().toString(36)}-${requestSequence.toString(36)}`;
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          pending.delete(requestId);
          reject(new HandshakeProviderError("timeout", "wallet request timed out"));
        }, REQUEST_TIMEOUT_MS);
        pending.set(requestId, { resolve, reject, timeout, sequence: requestSequence });
        window.postMessage(
          {
            channel: CHANNEL,
            schemaVersion: SCHEMA_VERSION,
            direction: "pageToExtension",
            kind: "request",
            requestId,
            sequence: requestSequence,
            method: args.method,
            params: args.params ?? null
          },
          location.origin
        );
      });
    },

    on(event, listener) {
      if (!EVENT_NAMES.has(event) || typeof listener !== "function") {
        throw new TypeError("unsupported Handshake provider event or listener");
      }
      const eventListeners = listeners.get(event) ?? new Set();
      eventListeners.add(listener);
      listeners.set(event, eventListeners);
      return provider;
    },

    removeListener(event, listener) {
      listeners.get(event)?.delete(listener);
      return provider;
    }
  });

  const providerInfo = Object.freeze({
    id: "org.handshake-rs.wallet",
    name: "HNS DANE Browser Wallet",
    providerApiVersion: "1"
  });

  function announceProvider() {
    window.dispatchEvent(
      new CustomEvent("hns:announceProvider", {
        detail: Object.freeze({ info: providerInfo, provider })
      })
    );
  }

  window.addEventListener("hns:requestProvider", announceProvider);
  window.addEventListener("message", (event) => {
    if (
      event.source !== window ||
      event.origin !== location.origin ||
      !isRecord(event.data) ||
      event.data.channel !== CHANNEL ||
      event.data.schemaVersion !== SCHEMA_VERSION ||
      event.data.direction !== "extensionToPage"
    ) {
      return;
    }
    if (event.data.kind === "response") {
      const request = pending.get(event.data.requestId);
      if (!request || request.sequence !== event.data.sequence) return;
      clearTimeout(request.timeout);
      pending.delete(event.data.requestId);
      if (event.data.ok === true) {
        request.resolve(event.data.result);
      } else {
        request.reject(
          new HandshakeProviderError(
            typeof event.data.error?.code === "string"
              ? event.data.error.code
              : "internalError",
            typeof event.data.error?.message === "string"
              ? event.data.error.message
              : "wallet request failed"
          )
        );
      }
      return;
    }
    if (event.data.kind === "event" && EVENT_NAMES.has(event.data.event)) {
      if (event.data.event === "disconnect") {
        for (const request of pending.values()) {
          clearTimeout(request.timeout);
          request.reject(
            new HandshakeProviderError("staleContext", "wallet context was invalidated")
          );
        }
        pending.clear();
      }
      for (const listener of listeners.get(event.data.event) ?? []) {
        try {
          listener(event.data.payload);
        } catch {
          // One application listener cannot interfere with other listeners.
        }
      }
    }
  });

  announceProvider();

  function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function boundedRequest(value) {
    try {
      const encoded = JSON.stringify(value);
      return (
        typeof encoded === "string" &&
        new TextEncoder().encode(encoded).length <= 64 * 1024
      );
    } catch {
      return false;
    }
  }
})();
