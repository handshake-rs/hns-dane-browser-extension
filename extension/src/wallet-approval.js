import {
  WALLET_PROVIDER_METHODS,
  protocolError,
  validateNativeResult
} from "./wallet-provider-protocol.js";

const METHOD_SET = new Set(WALLET_PROVIDER_METHODS);
const APPROVAL_KINDS = new Set([
  "permissions",
  "valueMovement",
  "typedMessage",
  "marketplaceMatch"
]);
const MAX_APPROVAL_LIFETIME_MS = 90 * 1000;
const MAX_SUMMARY_FIELDS = 24;
const PUBLIC_SUMMARY_FIELDS = new Set([
  "asset",
  "amountBaseUnits",
  "recipient",
  "feeBaseUnits",
  "chain",
  "confirmationPolicy",
  "priceRound",
  "refundTimeout",
  "name",
  "listingId",
  "marketIntentId",
  "swapSessionId",
  "module",
  "scopes",
  "messageType",
  "warning"
]);
const DECIMAL_FIELDS = new Set(["amountBaseUnits", "feeBaseUnits"]);
const STRING_FIELDS = new Set([
  "asset",
  "recipient",
  "chain",
  "confirmationPolicy",
  "priceRound",
  "refundTimeout",
  "name",
  "listingId",
  "marketIntentId",
  "swapSessionId",
  "module",
  "messageType"
]);
const WARNING_CODES = new Set([
  "feeEstimateMayChange",
  "nameTransferIsIrreversible",
  "refundRequiresManualAction",
  "settlementCanBeDelayed"
]);
const REQUIRED_FIELDS = Object.freeze({
  permissions: ["scopes"],
  valueMovement: [
    "asset",
    "amountBaseUnits",
    "recipient",
    "feeBaseUnits",
    "chain",
    "confirmationPolicy"
  ],
  typedMessage: ["messageType"],
  marketplaceMatch: [
    "asset",
    "amountBaseUnits",
    "recipient",
    "feeBaseUnits",
    "chain",
    "confirmationPolicy",
    "priceRound",
    "refundTimeout"
  ]
});

export function validateApprovalPrompt(
  candidate,
  binding,
  expectedRequest,
  now = Date.now()
) {
  try {
    validateNativeResult(candidate);
  } catch {
    throw protocolError("invalidApproval", "native wallet approval prompt is invalid");
  }
  if (
    !isRecord(candidate) ||
    candidate.schemaVersion !== 1 ||
    typeof candidate.approvalId !== "string" ||
    !/^[A-Za-z0-9_-]{16,96}$/.test(candidate.approvalId) ||
    !APPROVAL_KINDS.has(candidate.kind) ||
    !METHOD_SET.has(candidate.method) ||
    candidate.method !== expectedRequest?.method ||
    candidate.origin !== binding?.origin ||
    !Number.isSafeInteger(candidate.expiresAtUnixMs) ||
    candidate.expiresAtUnixMs <= now ||
    candidate.expiresAtUnixMs > now + MAX_APPROVAL_LIFETIME_MS ||
    !isRecord(candidate.summary)
  ) {
    throw protocolError("invalidApproval", "native wallet approval prompt is invalid");
  }
  const summary = Object.create(null);
  const entries = Object.entries(candidate.summary);
  if (entries.length > MAX_SUMMARY_FIELDS) {
    throw protocolError("invalidApproval", "wallet approval summary has too many fields");
  }
  for (const [field, value] of entries) {
    if (!PUBLIC_SUMMARY_FIELDS.has(field) || !publicSummaryValue(field, value)) {
      throw protocolError("invalidApproval", "wallet approval contains a non-public field");
    }
    summary[field] = value;
  }
  if (REQUIRED_FIELDS[candidate.kind].some((field) => !Object.hasOwn(summary, field))) {
    throw protocolError("invalidApproval", "wallet approval omits required review fields");
  }
  return Object.freeze({
    schemaVersion: 1,
    approvalId: candidate.approvalId,
    kind: candidate.kind,
    method: candidate.method,
    origin: candidate.origin,
    expiresAtUnixMs: candidate.expiresAtUnixMs,
    summary: Object.freeze(summary)
  });
}

export function validateApprovalId(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{16,96}$/.test(value)) {
    throw protocolError("invalidApproval", "wallet approval identifier is invalid");
  }
  return value;
}

export function validateApprovalDecision(value) {
  if (!["approve", "reject"].includes(value)) {
    throw protocolError("invalidApproval", "wallet approval decision is invalid");
  }
  return value;
}

export function approvalStorageKey(approvalId) {
  return `walletApproval:${validateApprovalId(approvalId)}`;
}

function publicSummaryValue(field, value) {
  if (DECIMAL_FIELDS.has(field)) {
    return typeof value === "string" && /^(0|[1-9][0-9]{0,77})$/.test(value);
  }
  if (field === "scopes") {
    return (
      Array.isArray(value) &&
      value.length > 0 &&
      value.length <= 32 &&
      value.every(
        (entry) =>
          typeof entry === "string" &&
          entry.length > 0 &&
          entry.length <= 128 &&
          /^[A-Za-z0-9:._-]+$/.test(entry)
      )
    );
  }
  if (field === "warning") return WARNING_CODES.has(value);
  return (
    STRING_FIELDS.has(field) &&
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512
  );
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
