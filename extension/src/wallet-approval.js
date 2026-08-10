import {
  WALLET_PROVIDER_METHODS,
  protocolError,
  validateNativeResult
} from "./wallet-provider-protocol.js";
import { hnsNameHash } from "./hns-name-hash.js";

export const WALLET_APPROVAL_SCHEMA_VERSION = 3;

const METHOD_SET = new Set(WALLET_PROVIDER_METHODS);
const MAX_APPROVAL_LIFETIME_MS = 90 * 1000;
const MAX_PUBLIC_STRING_BYTES = 4096;
const MAX_HNS_NAME_DISCLOSURES = 64;
const MAX_U128 = 340282366920938463463374607431768211455n;
const PROVIDER_APPROVAL_ID = /^[A-Za-z0-9_-]{21}[AQgw]$/;
const HNS_NAME = /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/;
const HNS_NAME_HASH = /^[0-9a-f]{64}$/;
const ASSETS = new Set(["HNS", "BTC", "ETH"]);
const MODULE_ASSET = Object.freeze({ handshake: "HNS", bitcoin: "BTC", ethereum: "ETH" });
const FINALITY_BY_MODULE = Object.freeze({
  handshake: "proof_of_work_confirmations",
  bitcoin: "proof_of_work_confirmations",
  ethereum: "ethereum_finalized_checkpoint"
});
const FINALITY_BY_ASSET = Object.freeze({
  HNS: "proof_of_work_confirmations",
  BTC: "proof_of_work_confirmations",
  ETH: "ethereum_finalized_checkpoint"
});
const PERMISSION_CAPABILITIES = Object.freeze([
  "accounts",
  "balance",
  "transactions",
  "receive_target",
  "send",
  "names",
  "name_transfer",
  "name_finalize",
  "typed_identity_signature",
  "name_market",
  "cross_chain_market",
  "swap_settlement"
]);
const PERMISSION_CAPABILITY_SET = new Set(PERMISSION_CAPABILITIES);
const WARNING_CODES = Object.freeze([
  "feeEstimateMayChange",
  "nameTransferIsIrreversible",
  "refundRequiresManualAction",
  "settlementCanBeDelayed"
]);
const WARNING_CODE_SET = new Set(WARNING_CODES);
const APPROVAL_METHODS = Object.freeze({
  permissions: new Set(["wallet_requestPermissions", "hns_requestAccounts"]),
  moduleEnablement: new Set(["wallet_enableModule", "wallet_disableModule"]),
  send: new Set(["hns_send", "asset_send"]),
  nameTransfer: new Set(["hns_transferName"]),
  nameFinalize: new Set(["hns_finalizeName"]),
  typedSignature: new Set(["hns_signTypedMessage"]),
  nameMarketOffer: new Set([
    "nameMarket_createFixedPriceOffer",
    "nameMarket_cancelOffer",
    "nameMarket_recoverName"
  ]),
  nameMarketPurchase: new Set([
    "nameMarket_acceptOffer",
    "nameMarket_finalizePurchase"
  ]),
  marketIntent: new Set(["swap_publishMarketIntent", "swap_cancelMarketIntent"]),
  fillAcceptance: new Set(["swap_requestMatch", "swap_acceptFill"]),
  swapRedeem: new Set(["swap_redeem"]),
  swapRefund: new Set(["swap_refund"])
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
    throw invalidApproval();
  }
  requireExactFields(candidate, [
    "schemaVersion",
    "approvalId",
    "method",
    "origin",
    "expiresAtUnixMs",
    "summary"
  ]);
  if (
    candidate.schemaVersion !== WALLET_APPROVAL_SCHEMA_VERSION ||
    typeof candidate.approvalId !== "string" ||
    !isCanonicalApprovalId(candidate.approvalId) ||
    !METHOD_SET.has(candidate.method) ||
    candidate.method !== expectedRequest?.method ||
    candidate.origin !== binding?.origin ||
    !Number.isSafeInteger(candidate.expiresAtUnixMs) ||
    candidate.expiresAtUnixMs <= now ||
    candidate.expiresAtUnixMs > now + MAX_APPROVAL_LIFETIME_MS
  ) {
    throw invalidApproval();
  }
  const summary = validateApprovalSummary(
    candidate.summary,
    candidate.method,
    expectedRequest
  );
  return Object.freeze({
    schemaVersion: WALLET_APPROVAL_SCHEMA_VERSION,
    approvalId: candidate.approvalId,
    kind: summary.kind,
    method: candidate.method,
    origin: candidate.origin,
    expiresAtUnixMs: candidate.expiresAtUnixMs,
    summary
  });
}

export function approvalPromptDisplay(prompt) {
  const summary = prompt?.summary;
  if (!isRecord(summary)) throw invalidApproval();
  const rows = [];
  const add = (label, value) => rows.push(Object.freeze([label, String(value)]));
  const addAmount = (label, amount) => add(label, `${amount.baseUnits} ${amount.asset}`);
  const addWarnings = () => {
    if (summary.warnings?.length > 0) add("Warnings", summary.warnings.join(", "));
  };
  let title;
  switch (summary.kind) {
    case "permissions":
      title = "Approve wallet permissions";
      add("Capabilities", summary.capabilities.join(", "));
      if (summary.hnsNames.length === 0 && summary.capabilities.includes("names")) {
        add("HNS names", "No names are currently disclosed");
      }
      for (const [index, disclosure] of summary.hnsNames.entries()) {
        add(`HNS name ${index + 1}`, disclosure.name);
        add(`HNS name hash ${index + 1}`, disclosure.nameHash);
      }
      break;
    case "moduleEnablement":
      title = summary.action === "enable" ? "Enable wallet module" : "Disable wallet module";
      add("Module", summary.module);
      add("Action", summary.action);
      break;
    case "send":
      title = "Approve asset send";
      addAmount("Amount", summary.amount);
      add("Recipient", summary.recipient);
      addAmount("Maximum fee", summary.maximumFee);
      add("Chain", summary.chain);
      add("Finality", summary.finality);
      addWarnings();
      break;
    case "nameTransfer":
    case "nameFinalize":
      title = summary.kind === "nameTransfer" ? "Approve name transfer" : "Approve name finalization";
      add("Name", summary.name);
      add("Recipient", summary.recipient);
      addAmount("Maximum fee", summary.maximumFee);
      addWarnings();
      break;
    case "typedSignature":
      title = "Approve typed signature";
      add("Message type", summary.messageType);
      add("Message digest", summary.messageDigest);
      break;
    case "nameMarketOffer":
      title = "Approve name offer action";
      add("Action", summary.action);
      add("Name", summary.name);
      if (summary.listingId != null) add("Listing ID", summary.listingId);
      addAmount("Price", summary.price);
      addAmount("Maximum fee", summary.maximumFee);
      addWarnings();
      break;
    case "nameMarketPurchase":
      title = "Approve name purchase";
      add("Name", summary.name);
      add("Listing ID", summary.listingId);
      addAmount("Payment", summary.payment);
      add("Recipient", summary.recipient);
      addAmount("Maximum fee", summary.maximumFee);
      addWarnings();
      break;
    case "marketIntent":
      title = "Approve market intent";
      add("Action", summary.action);
      if (summary.marketIntentId != null) add("Market intent ID", summary.marketIntentId);
      addAmount("Offered", summary.offered);
      add("Requested asset", summary.requestedAsset);
      add("Price round", summary.priceRound);
      addAmount("Maximum fee", summary.maximumFee);
      addWarnings();
      break;
    case "fillAcceptance":
      title = "Approve marketplace fill";
      add("Market intent ID", summary.marketIntentId);
      add("Fill ID", summary.fillId);
      addAmount("Offered", summary.offered);
      addAmount("Expected", summary.expected);
      add("Price round", summary.priceRound);
      add("Refund timeout", summary.refundTimeoutUnixMs);
      addAmount("Maximum fee", summary.maximumFee);
      addWarnings();
      break;
    case "swapRedeem":
      title = "Approve swap redemption";
      add("Swap session ID", summary.swapSessionId);
      addAmount("Amount", summary.amount);
      add("Recipient", summary.recipient);
      addAmount("Maximum fee", summary.maximumFee);
      add("Finality", summary.finality);
      addWarnings();
      break;
    case "swapRefund":
      title = "Approve swap refund";
      add("Swap session ID", summary.swapSessionId);
      addAmount("Amount", summary.amount);
      add("Recipient", summary.recipient);
      addAmount("Maximum fee", summary.maximumFee);
      add("Refund available at", summary.refundAvailableAtUnixMs);
      addWarnings();
      break;
    default:
      throw invalidApproval();
  }
  return Object.freeze({ title, rows: Object.freeze(rows) });
}

export function validateApprovalId(value) {
  if (!isCanonicalApprovalId(value)) {
    throw invalidApproval();
  }
  return value;
}

function isCanonicalApprovalId(value) {
  return (
    typeof value === "string" &&
    PROVIDER_APPROVAL_ID.test(value) &&
    value !== "AAAAAAAAAAAAAAAAAAAAAA"
  );
}

export function validateApprovalDecision(value) {
  if (!["approve", "reject"].includes(value)) throw invalidApproval();
  return value;
}

export function approvalStorageKey(approvalId) {
  return `walletApproval:${validateApprovalId(approvalId)}`;
}

function validateApprovalSummary(candidate, method, expectedRequest) {
  if (!isRecord(candidate) || typeof candidate.kind !== "string") {
    throw invalidApproval();
  }
  if (!APPROVAL_METHODS[candidate.kind]?.has(method)) throw invalidApproval();
  switch (candidate.kind) {
    case "permissions": {
      requireExactFields(candidate, ["kind", "capabilities", "hnsNames"]);
      const capabilities = validateCanonicalEnumList(
        candidate.capabilities,
        PERMISSION_CAPABILITIES,
        false
      );
      requireRequestedCapabilities(capabilities, method, expectedRequest);
      const hnsNames = validateHnsNameDisclosures(candidate.hnsNames, capabilities, method);
      return frozenRecord({
        kind: candidate.kind,
        capabilities,
        hnsNames
      });
    }
    case "moduleEnablement": {
      requireExactFields(candidate, ["kind", "module", "action"]);
      const module = validateModule(candidate.module);
      const action = validateEnum(candidate.action, new Set(["enable", "disable"]));
      if (
        (action === "enable") !== (method === "wallet_enableModule") ||
        expectedRequest?.params?.module !== module
      ) {
        throw invalidApproval();
      }
      return frozenRecord({ kind: candidate.kind, module, action });
    }
    case "send": {
      requireExactFields(candidate, [
        "kind", "amount", "recipient", "maximumFee", "chain", "finality", "warnings"
      ]);
      const chain = validateModule(candidate.chain);
      const expectedChain = method === "hns_send" ? "handshake" : expectedRequest?.params?.module;
      const amount = validateAmount(candidate.amount, false);
      const maximumFee = validateAmount(candidate.maximumFee, true);
      if (
        chain !== expectedChain ||
        amount.asset !== MODULE_ASSET[chain] ||
        maximumFee.asset !== amount.asset ||
        candidate.finality !== FINALITY_BY_MODULE[chain]
      ) {
        throw invalidApproval();
      }
      return frozenRecord({
        kind: candidate.kind,
        amount,
        recipient: validatePublicString(candidate.recipient),
        maximumFee,
        chain,
        finality: candidate.finality,
        warnings: validateWarnings(candidate.warnings)
      });
    }
    case "nameTransfer":
    case "nameFinalize": {
      requireExactFields(candidate, ["kind", "name", "recipient", "maximumFee", "warnings"]);
      const maximumFee = validateAmount(candidate.maximumFee, true);
      if (maximumFee.asset !== "HNS") throw invalidApproval();
      return frozenRecord({
        kind: candidate.kind,
        name: validatePublicString(candidate.name),
        recipient: validatePublicString(candidate.recipient),
        maximumFee,
        warnings: validateWarnings(candidate.warnings)
      });
    }
    case "typedSignature":
      requireExactFields(candidate, ["kind", "messageType", "messageDigest"]);
      return frozenRecord({
        kind: candidate.kind,
        messageType: validatePublicString(candidate.messageType),
        messageDigest: validatePublicString(candidate.messageDigest)
      });
    case "nameMarketOffer": {
      requireExactFields(candidate, [
        "kind", "action", "name", "listingId", "price", "maximumFee", "warnings"
      ]);
      const action = validateEnum(candidate.action, new Set(["create", "cancel", "recover"]));
      const expectedAction = {
        nameMarket_createFixedPriceOffer: "create",
        nameMarket_cancelOffer: "cancel",
        nameMarket_recoverName: "recover"
      }[method];
      const price = validateAmount(candidate.price, false);
      const maximumFee = validateAmount(candidate.maximumFee, true);
      if (action !== expectedAction || price.asset !== "HNS" || maximumFee.asset !== "HNS") {
        throw invalidApproval();
      }
      return frozenRecord({
        kind: candidate.kind,
        action,
        name: validatePublicString(candidate.name),
        listingId: validateOptionalPublicString(candidate.listingId),
        price,
        maximumFee,
        warnings: validateWarnings(candidate.warnings)
      });
    }
    case "nameMarketPurchase": {
      requireExactFields(candidate, [
        "kind", "name", "listingId", "payment", "recipient", "maximumFee", "warnings"
      ]);
      const payment = validateAmount(candidate.payment, false);
      const maximumFee = validateAmount(candidate.maximumFee, true);
      if (payment.asset !== "HNS" || maximumFee.asset !== "HNS") throw invalidApproval();
      return frozenRecord({
        kind: candidate.kind,
        name: validatePublicString(candidate.name),
        listingId: validatePublicString(candidate.listingId),
        payment,
        recipient: validatePublicString(candidate.recipient),
        maximumFee,
        warnings: validateWarnings(candidate.warnings)
      });
    }
    case "marketIntent": {
      requireExactFields(candidate, [
        "kind", "action", "marketIntentId", "offered", "requestedAsset", "priceRound",
        "maximumFee", "warnings"
      ]);
      const action = validateEnum(candidate.action, new Set(["publish", "cancel"]));
      const expectedAction = method === "swap_publishMarketIntent" ? "publish" : "cancel";
      const offered = validateAmount(candidate.offered, false);
      const requestedAsset = validateAsset(candidate.requestedAsset);
      const maximumFee = validateAmount(candidate.maximumFee, true);
      if (
        action !== expectedAction ||
        offered.asset === requestedAsset ||
        maximumFee.asset !== offered.asset
      ) {
        throw invalidApproval();
      }
      return frozenRecord({
        kind: candidate.kind,
        action,
        marketIntentId: validateOptionalPublicString(candidate.marketIntentId),
        offered,
        requestedAsset,
        priceRound: validatePublicString(candidate.priceRound),
        maximumFee,
        warnings: validateWarnings(candidate.warnings)
      });
    }
    case "fillAcceptance": {
      requireExactFields(candidate, [
        "kind", "marketIntentId", "fillId", "offered", "expected", "priceRound",
        "refundTimeoutUnixMs", "maximumFee", "warnings"
      ]);
      const offered = validateAmount(candidate.offered, false);
      const expected = validateAmount(candidate.expected, false);
      const maximumFee = validateAmount(candidate.maximumFee, true);
      if (offered.asset === expected.asset || maximumFee.asset !== offered.asset) {
        throw invalidApproval();
      }
      return frozenRecord({
        kind: candidate.kind,
        marketIntentId: validatePublicString(candidate.marketIntentId),
        fillId: validatePublicString(candidate.fillId),
        offered,
        expected,
        priceRound: validatePublicString(candidate.priceRound),
        refundTimeoutUnixMs: validatePositiveTime(candidate.refundTimeoutUnixMs),
        maximumFee,
        warnings: validateWarnings(candidate.warnings)
      });
    }
    case "swapRedeem":
    case "swapRefund": {
      const refund = candidate.kind === "swapRefund";
      requireExactFields(candidate, refund
        ? [
            "kind", "swapSessionId", "amount", "recipient", "maximumFee",
            "refundAvailableAtUnixMs", "warnings"
          ]
        : [
            "kind", "swapSessionId", "amount", "recipient", "maximumFee",
            "finality", "warnings"
          ]);
      const amount = validateAmount(candidate.amount, false);
      const maximumFee = validateAmount(candidate.maximumFee, true);
      if (maximumFee.asset !== amount.asset) throw invalidApproval();
      const value = {
        kind: candidate.kind,
        swapSessionId: validatePublicString(candidate.swapSessionId),
        amount,
        recipient: validatePublicString(candidate.recipient),
        maximumFee,
        warnings: validateWarnings(candidate.warnings)
      };
      if (refund) {
        value.refundAvailableAtUnixMs = validatePositiveTime(candidate.refundAvailableAtUnixMs);
      } else {
        const finality = validateEnum(
          candidate.finality,
          new Set(["proof_of_work_confirmations", "ethereum_finalized_checkpoint"])
        );
        if (finality !== FINALITY_BY_ASSET[amount.asset]) throw invalidApproval();
        value.finality = finality;
      }
      return frozenRecord(value);
    }
    default:
      throw invalidApproval();
  }
}

function validateAmount(candidate, allowZero) {
  requireExactFields(candidate, ["asset", "baseUnits"]);
  const asset = validateAsset(candidate.asset);
  if (typeof candidate.baseUnits !== "string" || !/^(0|[1-9][0-9]{0,38})$/.test(candidate.baseUnits)) {
    throw invalidApproval();
  }
  const value = BigInt(candidate.baseUnits);
  if (value > MAX_U128 || (!allowZero && value === 0n)) throw invalidApproval();
  return frozenRecord({ asset, baseUnits: candidate.baseUnits });
}

function validateWarnings(candidate) {
  return validateCanonicalEnumList(candidate, WARNING_CODES, true);
}

function validateCanonicalEnumList(candidate, ordered, allowEmpty) {
  const allowed = ordered === PERMISSION_CAPABILITIES
    ? PERMISSION_CAPABILITY_SET
    : WARNING_CODE_SET;
  if (
    !Array.isArray(candidate) ||
    (!allowEmpty && candidate.length === 0) ||
    candidate.length > allowed.size ||
    candidate.some((value) => typeof value !== "string" || !allowed.has(value)) ||
    new Set(candidate).size !== candidate.length
  ) {
    throw invalidApproval();
  }
  const canonical = ordered.filter((value) => candidate.includes(value));
  if (candidate.some((value, index) => value !== canonical[index])) throw invalidApproval();
  return Object.freeze([...candidate]);
}

function requireRequestedCapabilities(capabilities, method, expectedRequest) {
  if (method === "hns_requestAccounts") {
    if (capabilities.length !== 1 || capabilities[0] !== "accounts") {
      throw invalidApproval();
    }
    return;
  }
  if (capabilities.includes("accounts")) throw invalidApproval();
  const params = expectedRequest?.params;
  if (!isRecord(params)) throw invalidApproval();
  const hasCapabilities = Object.hasOwn(params, "capabilities");
  const hasScopes = Object.hasOwn(params, "scopes");
  if (hasCapabilities === hasScopes) throw invalidApproval();
  const requested = params[hasCapabilities ? "capabilities" : "scopes"];
  if (
    !Array.isArray(requested) ||
    requested.length === 0 ||
    requested.length > PERMISSION_CAPABILITIES.length ||
    requested.some((value) => typeof value !== "string" || !PERMISSION_CAPABILITY_SET.has(value)) ||
    new Set(requested).size !== requested.length
  ) {
    throw invalidApproval();
  }
  const canonical = PERMISSION_CAPABILITIES.filter((value) => requested.includes(value));
  if (
    canonical.length !== capabilities.length ||
    canonical.some((value, index) => value !== capabilities[index])
  ) {
    throw invalidApproval();
  }
}

function validateHnsNameDisclosures(candidate, capabilities, method) {
  if (!Array.isArray(candidate) || candidate.length > MAX_HNS_NAME_DISCLOSURES) {
    throw invalidApproval();
  }
  if (
    candidate.length > 0 &&
    (method === "hns_requestAccounts" || !capabilities.includes("names"))
  ) {
    throw invalidApproval();
  }

  const validated = [];
  let previous = null;
  for (const disclosure of candidate) {
    requireExactFields(disclosure, ["name", "nameHash"]);
    const { name, nameHash } = disclosure;
    if (
      typeof name !== "string" ||
      !HNS_NAME.test(name) ||
      typeof nameHash !== "string" ||
      !HNS_NAME_HASH.test(nameHash) ||
      hnsNameHash(name) !== nameHash ||
      (previous !== null &&
        (previous.name > name ||
          (previous.name === name && previous.nameHash >= nameHash)))
    ) {
      throw invalidApproval();
    }
    previous = { name, nameHash };
    validated.push(frozenRecord(previous));
  }
  return Object.freeze(validated);
}

function validateEnum(candidate, allowed) {
  if (typeof candidate !== "string" || !allowed.has(candidate)) throw invalidApproval();
  return candidate;
}

function validateAsset(candidate) {
  return validateEnum(candidate, ASSETS);
}

function validateModule(candidate) {
  return validateEnum(candidate, new Set(Object.keys(MODULE_ASSET)));
}

function validatePublicString(candidate) {
  if (
    typeof candidate !== "string" ||
    candidate.length === 0 ||
    new TextEncoder().encode(candidate).length > MAX_PUBLIC_STRING_BYTES ||
    !/^[\x20-\x7e]+$/.test(candidate)
  ) {
    throw invalidApproval();
  }
  return candidate;
}

function validateOptionalPublicString(candidate) {
  return candidate == null ? null : validatePublicString(candidate);
}

function validatePositiveTime(candidate) {
  if (!Number.isSafeInteger(candidate) || candidate <= 0) throw invalidApproval();
  return candidate;
}

function requireExactFields(candidate, required) {
  if (!isRecord(candidate)) throw invalidApproval();
  const fields = Object.keys(candidate);
  if (
    fields.length !== required.length ||
    required.some((field) => !Object.hasOwn(candidate, field))
  ) {
    throw invalidApproval();
  }
}

function frozenRecord(value) {
  return Object.freeze(value);
}

function invalidApproval() {
  return protocolError("invalidApproval", "native wallet approval prompt is invalid");
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
