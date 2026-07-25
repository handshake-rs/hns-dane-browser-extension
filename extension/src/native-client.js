const SCHEMA_VERSION = 1;
const MAX_PENDING_REQUESTS = 32;
const REQUEST_TIMEOUT_MS = 15_000;

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
  }

  connect() {
    if (this.port) return;
    const port = this.chrome.runtime.connectNative(this.hostName);
    this.port = port;
    port.onMessage.addListener((message) => this.handleMessage(message));
    port.onDisconnect.addListener(() => this.handleDisconnect());
  }

  onDisconnect(handler) {
    this.disconnectHandlers.add(handler);
    return () => this.disconnectHandlers.delete(handler);
  }

  request(command, fields = {}) {
    this.connect();
    if (this.pending.size >= MAX_PENDING_REQUESTS) {
      return Promise.reject(new Error("native request capacity is exhausted"));
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
      }, REQUEST_TIMEOUT_MS);
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
    if (this.port) {
      this.port.disconnect();
      this.port = null;
    }
    this.rejectPending(new Error("native host disconnected"));
  }

  handleMessage(message) {
    if (
      !isRecord(message) ||
      message.schemaVersion !== SCHEMA_VERSION ||
      typeof message.requestId !== "string" ||
      typeof message.runtimeSession !== "string" ||
      !Number.isSafeInteger(message.eventSequence) ||
      message.eventSequence < 1
    ) {
      this.disconnect();
      return;
    }
    if (this.runtimeSession === message.runtimeSession) {
      if (message.eventSequence <= this.lastEventSequence) {
        this.disconnect();
        return;
      }
    } else {
      this.runtimeSession = message.runtimeSession;
    }
    this.lastEventSequence = message.eventSequence;

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

  handleDisconnect() {
    this.port = null;
    this.rejectPending(new Error("native host disconnected"));
    for (const handler of this.disconnectHandlers) {
      try {
        handler();
      } catch {
        // Disconnect observers are isolated from the protocol lifecycle.
      }
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
