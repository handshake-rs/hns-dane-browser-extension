const SCHEMA_VERSION = 1;
const MAX_PENDING_REQUESTS = 32;
export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
// A full bounded header catch-up can span many peer batches. Keep one native
// request outstanding instead of timing it out while the Rust operation is
// still safely progressing in the background.
export const MAX_REQUEST_TIMEOUT_MS = 15 * 60 * 1000;

export class NativeClient {
  constructor(chromeApi, hostName) {
    this.chrome = chromeApi;
    this.hostName = hostName;
    this.port = null;
    this.pending = new Map();
    this.sequence = 0;
    this.runtimeSession = null;
    this.lastEventSequence = 0;
    this.disconnectHandlers = new Set();
    this.eventHandlers = new Set();
    this.lifecycleEpoch = 0;
  }

  connect() {
    if (this.port) return;
    const port = this.chrome.runtime.connectNative(this.hostName);
    this.port = port;
    this.lifecycleEpoch += 1;
    port.onMessage.addListener((message) => this.handleMessage(port, message));
    port.onDisconnect.addListener(() => this.handleDisconnect(port));
  }

  onDisconnect(handler) {
    this.disconnectHandlers.add(handler);
    return () => this.disconnectHandlers.delete(handler);
  }

  onEvent(handler) {
    this.eventHandlers.add(handler);
    return () => this.eventHandlers.delete(handler);
  }

  currentConnectionEpoch() {
    return this.port == null ? null : this.lifecycleEpoch;
  }

  connectionIsCurrent(epoch) {
    return (
      Number.isSafeInteger(epoch) &&
      epoch > 0 &&
      this.port != null &&
      this.lifecycleEpoch === epoch
    );
  }

  request(command, fields = {}, options = {}) {
    this.connect();
    if (this.pending.size >= MAX_PENDING_REQUESTS) {
      return Promise.reject(new Error("native request capacity is exhausted"));
    }
    const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > MAX_REQUEST_TIMEOUT_MS
    ) {
      return Promise.reject(new Error("native request timeout is out of bounds"));
    }
    const requestId = `request-${Date.now().toString(36)}-${++this.sequence}`;
    const message = {
      command,
      schemaVersion: SCHEMA_VERSION,
      requestId,
      ...fields
    };
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(requestId);
        reject(new Error(`native request timed out: ${command}`));
      }, timeoutMs);
      this.pending.set(requestId, { resolve, reject, timeout });
      try {
        this.port.postMessage(message);
      } catch (error) {
        clearTimeout(timeout);
        this.pending.delete(requestId);
        reject(error);
      }
    });
  }

  disconnect() {
    const port = this.port;
    if (port) {
      this.disconnectPort(port);
      return;
    }
    this.rejectPending(new Error("native host disconnected"));
  }

  disconnectIfCurrent(epoch) {
    if (!this.connectionIsCurrent(epoch)) return false;
    this.disconnectPort(this.port);
    return true;
  }

  handleMessage(port, message) {
    if (port !== this.port) return;
    if (
      !isRecord(message) ||
      message.schemaVersion !== SCHEMA_VERSION ||
      typeof message.runtimeSession !== "string" ||
      !Number.isSafeInteger(message.eventSequence) ||
      message.eventSequence < 1
    ) {
      this.disconnectPort(port, true);
      return;
    }
    if (this.runtimeSession === message.runtimeSession) {
      if (message.eventSequence <= this.lastEventSequence) {
        this.disconnectPort(port, true);
        return;
      }
    } else {
      this.runtimeSession = message.runtimeSession;
    }
    this.lastEventSequence = message.eventSequence;

    if (message.type === "walletProviderEvent") {
      this.notifyEvent(message);
      return;
    }
    if (typeof message.requestId !== "string") {
      this.disconnectPort(port, true);
      return;
    }

    const pending = this.pending.get(message.requestId);
    if (!pending) return;
    clearTimeout(pending.timeout);
    this.pending.delete(message.requestId);
    if (message.ok === true) {
      pending.resolve(message.result);
      return;
    }
    const code = isRecord(message.error) ? message.error.code : "nativeError";
    const detail = isRecord(message.error) ? message.error.message : "native request failed";
    const error = new Error(`${code}: ${detail}`);
    error.code = code;
    pending.reject(error);
  }

  handleDisconnect(port) {
    if (port !== this.port) return;
    const disconnectedEpoch = this.lifecycleEpoch;
    this.port = null;
    this.lifecycleEpoch += 1;
    this.rejectPending(new Error("native host disconnected"));
    this.notifyDisconnect(disconnectedEpoch);
  }

  notifyDisconnect(disconnectedEpoch) {
    for (const handler of this.disconnectHandlers) {
      try {
        handler(disconnectedEpoch);
      } catch {
        // Disconnect observers are isolated from the protocol lifecycle.
      }
    }
  }

  notifyEvent(event) {
    for (const handler of this.eventHandlers) {
      try {
        handler(event);
      } catch {
        // Native event observers are isolated from the request lifecycle.
      }
    }
  }

  disconnectPort(port, notify = false) {
    if (port !== this.port) return;
    const disconnectedEpoch = this.lifecycleEpoch;
    this.port = null;
    this.lifecycleEpoch += 1;
    try {
      port.disconnect();
    } finally {
      this.rejectPending(new Error("native host disconnected"));
      if (notify) this.notifyDisconnect(disconnectedEpoch);
    }
  }

  rejectPending(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.pending.clear();
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
