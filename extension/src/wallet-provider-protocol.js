export const WALLET_PROVIDER_SCHEMA_VERSION = 1;
export const WALLET_NATIVE_ABI_VERSION = 2;

export const WALLET_PROVIDER_METHODS = Object.freeze([
  "wallet_getCapabilities",
  "wallet_getEnabledModules",
  "wallet_enableModule",
  "wallet_disableModule",
  "wallet_requestPermissions",
  "wallet_getPermissions",
  "wallet_revokePermissions",
  "wallet_lock",
  "wallet_getStatus",
  "hns_requestAccounts",
  "hns_accounts",
  "hns_getBalance",
  "hns_getTransactions",
  "hns_getReceiveAddress",
  "hns_send",
  "hns_getNames",
  "hns_getName",
  "hns_importKnownName",
  "hns_transferName",
  "hns_finalizeName",
  "hns_signTypedMessage",
  "asset_getAccount",
  "asset_getBalance",
  "asset_getTransactions",
  "asset_getReceiveTarget",
  "asset_send",
  "nameMarket_listOffers",
  "nameMarket_createFixedPriceOffer",
  "nameMarket_cancelOffer",
  "nameMarket_acceptOffer",
  "nameMarket_getSession",
  "nameMarket_finalizePurchase",
  "nameMarket_recoverName",
  "swap_getSupportedPairs",
  "swap_getPriceRound",
  "swap_listMarketIntents",
  "swap_publishMarketIntent",
  "swap_cancelMarketIntent",
  "swap_requestMatch",
  "swap_acceptFill",
  "swap_getSession",
  "swap_redeem",
  "swap_refund"
]);

export const WALLET_PROVIDER_EVENTS = Object.freeze([
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

export const FORBIDDEN_WALLET_METHODS = Object.freeze([
  "eth_sendTransaction",
  "eth_call",
  "eth_estimateGas",
  "eth_sign",
  "personal_sign",
  "wallet_addEthereumChain",
  "wallet_switchEthereumChain",
  "bitcoin_signPsbt",
  "signRawTransaction"
]);

const METHOD_SET = new Set(WALLET_PROVIDER_METHODS);
const EVENT_SET = new Set(WALLET_PROVIDER_EVENTS);
const FORBIDDEN_SET = new Set(FORBIDDEN_WALLET_METHODS);
const ASSET_METHODS = new Set([
  "asset_getAccount",
  "asset_getBalance",
  "asset_getTransactions",
  "asset_getReceiveTarget",
  "asset_send"
]);
const NO_PARAMETER_METHODS = new Set([
  "wallet_getCapabilities",
  "wallet_getEnabledModules",
  "wallet_getPermissions",
  "wallet_lock",
  "wallet_getStatus",
  "hns_requestAccounts",
  "hns_accounts",
  "hns_getBalance",
  "hns_getReceiveAddress",
  "hns_getNames",
  "swap_getSupportedPairs",
  "swap_listMarketIntents"
]);

const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_RESULT_BYTES = 256 * 1024;
const MAX_REQUEST_ID_LENGTH = 96;
const MAX_STRING_LENGTH = 16 * 1024;
const MAX_CONTAINER_ENTRIES = 128;
const MAX_NESTING_DEPTH = 12;
const SENSITIVE_RESULT_FIELDS = new Set([
  "authorityhandle",
  "authorityrevision",
  "recoveryphrase",
  "mnemonic",
  "seed",
  "seedbytes",
  "privatekey",
  "passphrase",
  "databaseencryptionkey",
  "encryptionkey",
  "htlcpreimage",
  "preimage",
  "providercapabilitysecret",
  "sessionauthorizationtoken"
]);

export class WalletProviderProtocolError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "WalletProviderProtocolError";
    this.code = code;
  }
}

export function validatePageRequest(candidate) {
  requireRecord(candidate, "invalidRequest", "provider request must be an object");
  if (candidate.schemaVersion !== WALLET_PROVIDER_SCHEMA_VERSION) {
    throw protocolError("unsupportedVersion", "unsupported provider schema version");
  }
  if (candidate.kind !== "request") {
    throw protocolError("invalidRequest", "invalid provider message kind");
  }
  if (
    typeof candidate.requestId !== "string" ||
    candidate.requestId.length < 1 ||
    candidate.requestId.length > MAX_REQUEST_ID_LENGTH ||
    !/^[A-Za-z0-9._:-]+$/.test(candidate.requestId)
  ) {
    throw protocolError("invalidRequest", "invalid provider request identifier");
  }
  if (!Number.isSafeInteger(candidate.sequence) || candidate.sequence < 1) {
    throw protocolError("invalidRequest", "invalid provider request sequence");
  }
  if (typeof candidate.method !== "string") {
    throw protocolError("invalidRequest", "provider method must be a string");
  }
  if (FORBIDDEN_SET.has(candidate.method)) {
    throw protocolError(
      "forbiddenMethod",
      `${candidate.method} is intentionally unavailable through the Handshake provider`
    );
  }
  if (!METHOD_SET.has(candidate.method)) {
    throw protocolError("unsupportedMethod", "unsupported Handshake provider method");
  }
  validateBoundedJson(candidate, MAX_MESSAGE_BYTES);
  validateMethodParameters(candidate.method, candidate.params);
  return Object.freeze({
    requestId: candidate.requestId,
    sequence: candidate.sequence,
    method: candidate.method,
    params: candidate.params ?? null
  });
}

export function validateNativeResult(candidate) {
  validateBoundedJson(candidate, MAX_RESULT_BYTES, true);
  return candidate;
}

export function validateNativeCapabilities(candidate) {
  requireRecord(
    candidate,
    "walletUnavailable",
    "wallet native capability response is invalid"
  );
  if (
    candidate.abiVersion !== WALLET_NATIVE_ABI_VERSION ||
    candidate.available !== true ||
    typeof candidate.walletSession !== "string" ||
    candidate.walletSession.length < 1 ||
    candidate.walletSession.length > 160 ||
    !Number.isSafeInteger(candidate.permissionGeneration) ||
    candidate.permissionGeneration < 1 ||
    !Array.isArray(candidate.methods) ||
    candidate.methods.length > WALLET_PROVIDER_METHODS.length ||
    Object.keys(candidate).some(
      (field) =>
        ![
          "abiVersion",
          "available",
          "walletSession",
          "permissionGeneration",
          "methods"
        ].includes(field)
    )
  ) {
    throw protocolError(
      "walletUnavailable",
      "the native host does not provide the required wallet ABI"
    );
  }
  if (
    candidate.methods.some(
      (method) => typeof method !== "string" || !METHOD_SET.has(method)
    ) ||
    new Set(candidate.methods).size !== candidate.methods.length
  ) {
    throw protocolError(
      "walletUnavailable",
      "the native host advertised an invalid wallet method set"
    );
  }
  return Object.freeze({
    abiVersion: WALLET_NATIVE_ABI_VERSION,
    walletSession: candidate.walletSession,
    permissionGeneration: candidate.permissionGeneration,
    methods: Object.freeze([...candidate.methods])
  });
}

export function validateProviderEvent(candidate) {
  requireRecord(candidate, "invalidEvent", "provider event must be an object");
  if (!EVENT_SET.has(candidate.event)) {
    throw protocolError("invalidEvent", "unsupported provider event");
  }
  validateBoundedJson(candidate, MAX_MESSAGE_BYTES, true);
  return Object.freeze({ event: candidate.event, payload: candidate.payload ?? null });
}

export function isProviderBridgeMessage(candidate) {
  return (
    isRecord(candidate) &&
    candidate.schemaVersion === WALLET_PROVIDER_SCHEMA_VERSION &&
    ["walletProviderInitialize", "walletProviderRequest"].includes(candidate.type)
  );
}

export function providerErrorPayload(error) {
  const code =
    error instanceof WalletProviderProtocolError && typeof error.code === "string"
      ? error.code
      : "internalError";
  const message =
    error instanceof Error ? error.message.slice(0, 512) : "wallet provider failed";
  return Object.freeze({ code, message });
}

export function protocolError(code, message) {
  return new WalletProviderProtocolError(code, message);
}

function validateMethodParameters(method, params) {
  if (NO_PARAMETER_METHODS.has(method)) {
    if (params != null && (!isRecord(params) || Object.keys(params).length !== 0)) {
      throw protocolError("invalidParams", `${method} does not accept parameters`);
    }
    return;
  }
  requireRecord(params, "invalidParams", `${method} requires an object parameter`);
  if (ASSET_METHODS.has(method) && !["bitcoin", "ethereum"].includes(params.module)) {
    throw protocolError(
      "invalidParams",
      `${method} requires module to be bitcoin or ethereum`
    );
  }
}

function validateBoundedJson(value, maximumBytes, rejectSensitiveFields = false) {
  walkBoundedJson(value, 0, new Set(), rejectSensitiveFields);
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw protocolError("invalidRequest", "provider payload is not serializable");
  }
  if (typeof encoded !== "string" || new TextEncoder().encode(encoded).length > maximumBytes) {
    throw protocolError("requestTooLarge", "provider payload exceeds its byte limit");
  }
}

function walkBoundedJson(value, depth, ancestors, rejectSensitiveFields) {
  if (depth > MAX_NESTING_DEPTH) {
    throw protocolError("requestTooLarge", "provider payload is nested too deeply");
  }
  if (value == null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      throw protocolError("requestTooLarge", "provider string exceeds its length limit");
    }
    return;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw protocolError(
        "invalidRequest",
        "provider numbers must be safe integers; encode base units as decimal strings"
      );
    }
    return;
  }
  if (typeof value !== "object" || value instanceof Date) {
    throw protocolError("invalidRequest", "provider payload contains a non-JSON value");
  }
  if (ancestors.has(value)) {
    throw protocolError("invalidRequest", "provider payload contains a cycle");
  }
  const entries = Array.isArray(value) ? value.entries() : Object.entries(value);
  if (Object.keys(value).length > MAX_CONTAINER_ENTRIES) {
    throw protocolError("requestTooLarge", "provider object has too many entries");
  }
  ancestors.add(value);
  for (const [key, child] of entries) {
    if (["__proto__", "prototype", "constructor"].includes(String(key))) {
      throw protocolError("invalidRequest", "provider payload contains a forbidden key");
    }
    if (
      rejectSensitiveFields &&
      SENSITIVE_RESULT_FIELDS.has(String(key).toLowerCase().replace(/[^a-z0-9]/g, ""))
    ) {
      throw protocolError("invalidResult", "native wallet result contains a secret field");
    }
    walkBoundedJson(child, depth + 1, ancestors, rejectSensitiveFields);
  }
  ancestors.delete(value);
}

function requireRecord(value, code, message) {
  if (!isRecord(value)) throw protocolError(code, message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
