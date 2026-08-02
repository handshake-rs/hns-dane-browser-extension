import {
  WALLET_NATIVE_ABI_VERSION,
  WALLET_PROVIDER_SCHEMA_VERSION,
  protocolError,
  validateNativeCapabilities,
  validateNativeResult,
  validatePageRequest,
  validateProviderEvent
} from "./wallet-provider-protocol.js";

const MAX_ACTIVE_DOCUMENTS = 64;
const MAX_PENDING_PER_DOCUMENT = 16;
const MAX_SEEN_REQUEST_IDS = 512;
const INITIALIZE_RATE_PER_MINUTE = 12;
const READ_RATE_PER_MINUTE = 120;
const MUTATION_RATE_PER_MINUTE = 20;
const RATE_WINDOW_MS = 60 * 1000;
const MUTATING_PREFIXES = [
  "wallet_enable",
  "wallet_disable",
  "wallet_request",
  "wallet_revoke",
  "wallet_lock",
  "hns_request",
  "hns_send",
  "hns_import",
  "hns_transfer",
  "hns_finalize",
  "hns_sign",
  "asset_send",
  "nameMarket_create",
  "nameMarket_cancel",
  "nameMarket_accept",
  "nameMarket_finalize",
  "nameMarket_recover",
  "swap_publish",
  "swap_cancel",
  "swap_request",
  "swap_accept",
  "swap_redeem",
  "swap_refund"
];

export class WalletProviderRouter {
  constructor({ nativeRequest, authorityForSender, deliverEvent, now = Date.now }) {
    this.nativeRequest = nativeRequest;
    this.authorityForSender = authorityForSender;
    this.deliverEvent = deliverEvent;
    this.now = now;
    this.documents = new Map();
    this.initializeWindows = new Map();
  }

  async initialize(message, sender) {
    const origin = exactMessageOrigin(message?.origin, sender);
    const key = documentKey(sender);
    enforceStandaloneRate(this.initializeWindows, key, this.now());
    const authority = await this.authorityForSender(sender, origin);
    const rawCapabilities = await this.nativeRequest(
      "walletProviderCapabilities",
      {
        providerAbiVersion: WALLET_NATIVE_ABI_VERSION,
        authority
      }
    );
    const capabilities = validateNativeCapabilities(rawCapabilities);
    const binding = Object.freeze({
      schemaVersion: WALLET_PROVIDER_SCHEMA_VERSION,
      origin,
      namespace: authority.namespace,
      browserAuthoritySession: authority.browserAuthoritySession,
      runtimeGeneration: authority.runtimeGeneration,
      policyGeneration: authority.policyGeneration,
      navigationGeneration: authority.navigationGeneration,
      walletSession: capabilities.walletSession,
      permissionGeneration: capabilities.permissionGeneration,
      documentId: authority.documentId
    });
    this.documents.delete(key);
    this.documents.set(key, {
      binding,
      sender: publicSender(sender),
      methods: new Set(capabilities.methods),
      lastSequence: 0,
      pending: new Set(),
      seenRequestIds: new Set(),
      readWindow: [],
      mutationWindow: [],
      methodWindows: new Map()
    });
    this.pruneDocuments();
    return Object.freeze({
      available: true,
      binding,
      methods: capabilities.methods
    });
  }

  async request(message, sender) {
    const pageRequest = validatePageRequest(message?.request);
    const origin = exactMessageOrigin(message?.origin, sender);
    const key = documentKey(sender);
    const document = this.documents.get(key);
    if (!document) {
      throw protocolError("staleContext", "provider document is not initialized");
    }
    requireExpectedBinding(message?.binding, document.binding);
    if (!document.methods.has(pageRequest.method)) {
      throw protocolError(
        "unsupportedMethod",
        "the native wallet did not negotiate this provider method"
      );
    }
    if (pageRequest.sequence <= document.lastSequence) {
      throw protocolError("replay", "provider request sequence was already observed");
    }
    document.lastSequence = pageRequest.sequence;
    if (document.seenRequestIds.has(pageRequest.requestId)) {
      throw protocolError("replay", "provider request identifier was already observed");
    }
    if (document.seenRequestIds.size >= MAX_SEEN_REQUEST_IDS) {
      throw protocolError(
        "rateLimited",
        "provider replay window is exhausted for this document"
      );
    }
    if (document.pending.size >= MAX_PENDING_PER_DOCUMENT) {
      throw protocolError("rateLimited", "too many provider requests are pending");
    }
    enforceRate(document, pageRequest.method, this.now());
    document.seenRequestIds.add(pageRequest.requestId);
    document.pending.add(pageRequest.requestId);
    try {
      const authority = await this.authorityForSender(sender, origin);
      requireAuthorityBinding(document.binding, authority);
      const response = validateNativeResult(
        await this.nativeRequest("walletProviderRequest", {
          providerAbiVersion: WALLET_NATIVE_ABI_VERSION,
          authority: {
            ...authority,
            walletSession: document.binding.walletSession,
            permissionGeneration: document.binding.permissionGeneration
          },
          request: pageRequest
        })
      );
      return await this.extractEvents(response, sender, document.binding);
    } finally {
      document.pending.delete(pageRequest.requestId);
    }
  }

  forgetTab(tabId) {
    for (const key of this.documents.keys()) {
      if (key.startsWith(`${tabId}:`)) this.documents.delete(key);
    }
    for (const key of this.initializeWindows.keys()) {
      if (key.startsWith(`${tabId}:`)) this.initializeWindows.delete(key);
    }
  }

  forgetDocument(tabId, documentId) {
    const key = `${tabId}:${documentId}`;
    this.documents.delete(key);
    this.initializeWindows.delete(key);
  }

  forgetAll() {
    this.documents.clear();
    this.initializeWindows.clear();
  }

  async revalidateApproval(context) {
    if (!isRecord(context) || !isRecord(context.sender) || !isRecord(context.binding)) {
      throw protocolError("staleContext", "approval context is unavailable");
    }
    const origin = exactMessageOrigin(context.binding.origin, context.sender);
    const document = this.documents.get(documentKey(context.sender));
    if (!document) {
      throw protocolError("staleContext", "approval document is no longer active");
    }
    requireExpectedBinding(context.binding, document.binding);
    const authority = await this.authorityForSender(context.sender, origin);
    requireAuthorityBinding(document.binding, authority);
    const capabilities = validateNativeCapabilities(
      await this.nativeRequest("walletProviderCapabilities", {
        providerAbiVersion: WALLET_NATIVE_ABI_VERSION,
        authority
      })
    );
    if (
      capabilities.walletSession !== document.binding.walletSession ||
      capabilities.permissionGeneration !== document.binding.permissionGeneration ||
      !capabilities.methods.includes(context.request?.method)
    ) {
      throw protocolError("staleContext", "wallet approval authority changed");
    }
    return Object.freeze({
      ...authority,
      walletSession: capabilities.walletSession,
      permissionGeneration: capabilities.permissionGeneration
    });
  }

  async deliverNativeEvent(candidate) {
    if (
      !isRecord(candidate) ||
      candidate.providerAbiVersion !== WALLET_NATIVE_ABI_VERSION ||
      !isRecord(candidate.binding)
    ) {
      throw protocolError("invalidEvent", "native wallet event envelope is invalid");
    }
    const event = validateProviderEvent(candidate);
    for (const document of this.documents.values()) {
      try {
        requireExpectedBinding(candidate.binding, document.binding);
        const authority = await this.authorityForSender(
          document.sender,
          document.binding.origin
        );
        requireAuthorityBinding(document.binding, authority);
        await this.deliverEvent(document.sender, document.binding, event);
      } catch {
        // Stale and unrelated documents cannot receive this native event.
      }
    }
  }

  async extractEvents(response, sender, binding) {
    if (!isRecord(response) || !Array.isArray(response.events)) return response;
    if (response.events.length > 32) {
      throw protocolError("invalidEvent", "native wallet returned too many events");
    }
    const events = response.events.map(validateProviderEvent);
    for (const event of events) {
      await this.deliverEvent(sender, binding, event);
    }
    const { events: _events, ...result } = response;
    return result;
  }

  pruneDocuments() {
    while (this.documents.size > MAX_ACTIVE_DOCUMENTS) {
      this.documents.delete(this.documents.keys().next().value);
    }
    while (this.initializeWindows.size > MAX_ACTIVE_DOCUMENTS) {
      this.initializeWindows.delete(this.initializeWindows.keys().next().value);
    }
  }
}

function exactMessageOrigin(value, sender) {
  if (typeof value !== "string" || value.length > 512) {
    throw protocolError("invalidOrigin", "provider origin is invalid");
  }
  let parsed;
  let senderUrl;
  try {
    parsed = new URL(value);
    senderUrl = new URL(sender?.url);
  } catch {
    throw protocolError("invalidOrigin", "provider origin is invalid");
  }
  if (parsed.href !== `${parsed.origin}/` || parsed.origin !== senderUrl.origin) {
    throw protocolError("originMismatch", "provider origin does not match its document");
  }
  if (typeof sender?.origin === "string" && sender.origin !== parsed.origin) {
    throw protocolError("originMismatch", "browser sender origin does not match");
  }
  if (!secureProviderOrigin(parsed)) {
    throw protocolError("insecureOrigin", "provider requires HTTPS or loopback HTTP");
  }
  if (
    sender?.frameId !== 0 ||
    !Number.isSafeInteger(sender?.tab?.id) ||
    typeof sender?.documentId !== "string" ||
    sender.documentId.length < 1 ||
    sender.documentId.length > 160
  ) {
    throw protocolError("invalidDocument", "provider requires an exact main-frame document");
  }
  return parsed.origin;
}

function secureProviderOrigin(parsed) {
  if (parsed.protocol === "https:") return true;
  return (
    parsed.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
  );
}

function documentKey(sender) {
  return `${sender.tab.id}:${sender.documentId}`;
}

function requireExpectedBinding(candidate, expected) {
  if (!isRecord(candidate)) {
    throw protocolError("staleContext", "provider authority binding is absent");
  }
  const fields = [
    "schemaVersion",
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
  if (fields.some((field) => candidate[field] !== expected[field])) {
    throw protocolError("staleContext", "provider authority binding is stale");
  }
}

function requireAuthorityBinding(expected, authority) {
  const authorityFields = [
    ["origin", "origin"],
    ["namespace", "namespace"],
    ["browserAuthoritySession", "browserAuthoritySession"],
    ["runtimeGeneration", "runtimeGeneration"],
    ["policyGeneration", "policyGeneration"],
    ["navigationGeneration", "navigationGeneration"],
    ["documentId", "documentId"]
  ];
  if (authorityFields.some(([bindingField, authorityField]) =>
    expected[bindingField] !== authority[authorityField]
  )) {
    throw protocolError("staleContext", "browser navigation authority changed");
  }
}

function enforceRate(document, method, now) {
  const mutation = MUTATING_PREFIXES.some((prefix) => method.startsWith(prefix));
  const globalWindow = mutation ? document.mutationWindow : document.readWindow;
  const limit = mutation ? MUTATION_RATE_PER_MINUTE : READ_RATE_PER_MINUTE;
  pruneWindow(globalWindow, now);
  if (globalWindow.length >= limit) {
    throw protocolError("rateLimited", "provider method rate limit exceeded");
  }
  const methodWindow = document.methodWindows.get(method) ?? [];
  pruneWindow(methodWindow, now);
  const methodLimit = mutation ? Math.min(limit, 10) : limit;
  if (methodWindow.length >= methodLimit) {
    throw protocolError("rateLimited", "provider method rate limit exceeded");
  }
  globalWindow.push(now);
  methodWindow.push(now);
  document.methodWindows.set(method, methodWindow);
}

function enforceStandaloneRate(windows, key, now) {
  const window = windows.get(key) ?? [];
  pruneWindow(window, now);
  if (window.length >= INITIALIZE_RATE_PER_MINUTE) {
    throw protocolError("rateLimited", "provider initialization rate limit exceeded");
  }
  window.push(now);
  windows.set(key, window);
}

function pruneWindow(window, now) {
  while (window.length > 0 && window[0] <= now - RATE_WINDOW_MS) window.shift();
}

function publicSender(sender) {
  return Object.freeze({
    id: sender.id,
    origin: sender.origin,
    url: sender.url,
    frameId: sender.frameId,
    documentId: sender.documentId,
    tab: Object.freeze({ id: sender.tab.id })
  });
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
