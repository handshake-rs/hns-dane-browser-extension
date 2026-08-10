import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  WALLET_APPROVAL_SCHEMA_VERSION,
  approvalPromptDisplay,
  approvalStorageKey,
  validateApprovalDecision,
  validateApprovalPrompt
} from "../src/wallet-approval.js";

const NOW = 1_800_000_000_000;
const binding = Object.freeze({ origin: "https://welcome" });
const APPROVAL_ID = "AQIDBAUGBwgJCgsMDQ4PEA";

const APPROVAL_CASES = Object.freeze([
  {
    method: "wallet_requestPermissions",
    params: { capabilities: ["balance", "send"] },
    summary: { kind: "permissions", capabilities: ["balance", "send"], hnsNames: [] }
  },
  {
    method: "wallet_enableModule",
    params: { module: "bitcoin" },
    summary: { kind: "moduleEnablement", module: "bitcoin", action: "enable" }
  },
  {
    method: "asset_send",
    params: { module: "bitcoin" },
    summary: {
      kind: "send",
      amount: amount("BTC", "12000"),
      recipient: "tb1qexample",
      maximumFee: amount("BTC", "420"),
      chain: "bitcoin",
      finality: "proof_of_work_confirmations",
      warnings: ["feeEstimateMayChange"]
    }
  },
  {
    method: "hns_transferName",
    summary: {
      kind: "nameTransfer",
      name: "example",
      recipient: "hs1qrecipient",
      maximumFee: amount("HNS", "10"),
      warnings: ["nameTransferIsIrreversible"]
    }
  },
  {
    method: "hns_finalizeName",
    summary: {
      kind: "nameFinalize",
      name: "example",
      recipient: "hs1qrecipient",
      maximumFee: amount("HNS", "10"),
      warnings: []
    }
  },
  {
    method: "hns_signTypedMessage",
    summary: {
      kind: "typedSignature",
      messageType: "hns-login-v1",
      messageDigest: "ab".repeat(32)
    }
  },
  {
    method: "nameMarket_createFixedPriceOffer",
    summary: {
      kind: "nameMarketOffer",
      action: "create",
      name: "example",
      listingId: null,
      price: amount("HNS", "5000"),
      maximumFee: amount("HNS", "50"),
      warnings: ["feeEstimateMayChange"]
    }
  },
  {
    method: "nameMarket_acceptOffer",
    summary: {
      kind: "nameMarketPurchase",
      name: "example",
      listingId: "listing-1",
      payment: amount("HNS", "5000"),
      recipient: "hs1qseller",
      maximumFee: amount("HNS", "50"),
      warnings: []
    }
  },
  {
    method: "swap_publishMarketIntent",
    summary: {
      kind: "marketIntent",
      action: "publish",
      marketIntentId: null,
      offered: amount("HNS", "1000"),
      requestedAsset: "BTC",
      priceRound: "price-round-1",
      maximumFee: amount("HNS", "25"),
      warnings: ["settlementCanBeDelayed"]
    }
  },
  {
    method: "swap_acceptFill",
    summary: {
      kind: "fillAcceptance",
      marketIntentId: "intent-1",
      fillId: "fill-1",
      offered: amount("HNS", "1000"),
      expected: amount("ETH", "2000"),
      priceRound: "price-round-1",
      refundTimeoutUnixMs: NOW + 600_000,
      maximumFee: amount("HNS", "25"),
      warnings: ["refundRequiresManualAction", "settlementCanBeDelayed"]
    }
  },
  {
    method: "swap_redeem",
    summary: {
      kind: "swapRedeem",
      swapSessionId: "swap-1",
      amount: amount("ETH", "2000"),
      recipient: "0x1111111111111111111111111111111111111111",
      maximumFee: amount("ETH", "25"),
      finality: "ethereum_finalized_checkpoint",
      warnings: []
    }
  },
  {
    method: "swap_refund",
    summary: {
      kind: "swapRefund",
      swapSessionId: "swap-1",
      amount: amount("BTC", "2000"),
      recipient: "tb1qrefund",
      maximumFee: amount("BTC", "25"),
      refundAvailableAtUnixMs: NOW + 600_000,
      warnings: ["refundRequiresManualAction"]
    }
  }
]);

test("all twelve ABI-v2 approval variants use approval schema v3 trusted rows", () => {
  assert.equal(APPROVAL_CASES.length, 12);
  assert.equal(WALLET_APPROVAL_SCHEMA_VERSION, 3);
  for (const scenario of APPROVAL_CASES) {
    const prompt = approve(scenario.method, scenario.params, scenario.summary);
    const display = approvalPromptDisplay(prompt);
    assert.equal(prompt.schemaVersion, WALLET_APPROVAL_SCHEMA_VERSION);
    assert.equal(prompt.kind, scenario.summary.kind);
    assert.equal(Object.isFrozen(prompt), true);
    assert.equal(Object.isFrozen(prompt.summary), true);
    assert.equal(Object.isFrozen(display), true);
    assert.equal(Object.isFrozen(display.rows), true);
    assert.ok(display.title.length > 0);
    assert.ok(display.rows.length > 0);
    assert.ok(display.rows.every((row) => Object.isFrozen(row) && row.length === 2));
  }
  assert.equal(approvalStorageKey(APPROVAL_ID), `walletApproval:${APPROVAL_ID}`);
  assert.equal(validateApprovalDecision("reject"), "reject");
});

test("approval envelopes reject origin, method, version, expiry, and unknown-field substitution", () => {
  const scenario = APPROVAL_CASES[2];
  const base = approvalCandidate(scenario.method, scenario.summary);
  rejects({ ...base, origin: "https://attacker.example" }, scenario.method, scenario.params);
  rejects({ ...base, method: "hns_send" }, scenario.method, scenario.params);
  rejects({ ...base, schemaVersion: 1 }, scenario.method, scenario.params);
  rejects({ ...base, schemaVersion: 2 }, scenario.method, scenario.params);
  rejects({ ...base, expiresAtUnixMs: NOW + 90_001 }, scenario.method, scenario.params);
  rejects({ ...base, approvalId: "approval_1234567890" }, scenario.method, scenario.params);
  rejects(
    { ...base, approvalId: "AAAAAAAAAAAAAAAAAAAAAA" },
    scenario.method,
    scenario.params
  );
  rejects({ ...base, privateKey: "secret" }, scenario.method, scenario.params);
  rejects(
    { ...base, summary: { ...base.summary, futureField: true } },
    scenario.method,
    scenario.params
  );
});

test("amounts, assets, send chains, finality, and public strings fail closed", () => {
  const scenario = APPROVAL_CASES[2];
  const base = approvalCandidate(scenario.method, scenario.summary);
  rejects(
    { ...base, summary: { ...base.summary, amount: { asset: "BTC", baseUnits: 12000 } } },
    scenario.method,
    scenario.params
  );
  rejects(
    { ...base, summary: { ...base.summary, amount: amount("BTC", "01") } },
    scenario.method,
    scenario.params
  );
  rejects(
    {
      ...base,
      summary: {
        ...base.summary,
        amount: amount("BTC", "340282366920938463463374607431768211456")
      }
    },
    scenario.method,
    scenario.params
  );
  rejects(
    { ...base, summary: { ...base.summary, amount: amount("HNS", "12000") } },
    scenario.method,
    scenario.params
  );
  rejects(
    { ...base, summary: { ...base.summary, chain: "ethereum" } },
    scenario.method,
    scenario.params
  );
  rejects(
    { ...base, summary: { ...base.summary, finality: "ethereum_finalized_checkpoint" } },
    scenario.method,
    scenario.params
  );
  rejects(
    { ...base, summary: { ...base.summary, recipient: "line\nbreak" } },
    scenario.method,
    scenario.params
  );
});

test("permission summaries exactly bind canonical requested capabilities and scopes", () => {
  approve(
    "wallet_requestPermissions",
    { scopes: ["send", "balance"] },
    { kind: "permissions", capabilities: ["balance", "send"], hnsNames: [] }
  );
  const summary = { kind: "permissions", capabilities: ["balance", "send"], hnsNames: [] };
  rejects(
    approvalCandidate("wallet_requestPermissions", summary),
    "wallet_requestPermissions",
    { capabilities: ["balance"] }
  );
  rejects(
    approvalCandidate("wallet_requestPermissions", summary),
    "wallet_requestPermissions",
    { capabilities: ["balance", "balance"] }
  );
  rejects(
    approvalCandidate("wallet_requestPermissions", {
      kind: "permissions",
      capabilities: ["send", "balance"],
      hnsNames: []
    }),
    "wallet_requestPermissions",
    { capabilities: ["send", "balance"] }
  );
  rejects(
    approvalCandidate("wallet_requestPermissions", summary),
    "wallet_requestPermissions",
    { capabilities: ["balance", "send"], scopes: ["balance", "send"] }
  );
  approve(
    "hns_requestAccounts",
    null,
    { kind: "permissions", capabilities: ["accounts"], hnsNames: [] }
  );
  rejects(
    approvalCandidate("hns_requestAccounts", {
      kind: "permissions",
      capabilities: ["send"],
      hnsNames: []
    }),
    "hns_requestAccounts",
    null
  );
  rejects(
    approvalCandidate("wallet_requestPermissions", {
      kind: "permissions",
      capabilities: ["accounts"],
      hnsNames: []
    }),
    "wallet_requestPermissions",
    { capabilities: ["accounts"] }
  );
});

test("approval schema v3 validates and renders exact HNS name disclosures", () => {
  const alpha = hnsDisclosure("alpha");
  const beta = hnsDisclosure("beta");
  assert.equal(
    alpha.nameHash,
    "271878f8a927b4566ac951fc815b18dfad8d0302d61d11d80cbe15b7a3a056af"
  );
  assert.equal(
    beta.nameHash,
    "f0277d92062bd9a41dd26cddbaf2c41d576cf7b0173cbe96c23d5f5a4f92cc8f"
  );

  const prompt = approve(
    "wallet_requestPermissions",
    { capabilities: ["names"] },
    { kind: "permissions", capabilities: ["names"], hnsNames: [alpha, beta] }
  );
  assert.equal(Object.isFrozen(prompt.summary.hnsNames), true);
  assert.ok(prompt.summary.hnsNames.every((disclosure) => Object.isFrozen(disclosure)));
  assert.deepEqual(approvalPromptDisplay(prompt).rows, [
    ["Capabilities", "names"],
    ["HNS name 1", "alpha"],
    ["HNS name hash 1", alpha.nameHash],
    ["HNS name 2", "beta"],
    ["HNS name hash 2", beta.nameHash]
  ]);

  const empty = approve(
    "wallet_requestPermissions",
    { capabilities: ["names"] },
    { kind: "permissions", capabilities: ["names"], hnsNames: [] }
  );
  assert.deepEqual(approvalPromptDisplay(empty).rows, [
    ["Capabilities", "names"],
    ["HNS names", "No names are currently disclosed"]
  ]);

  approve(
    "wallet_requestPermissions",
    { capabilities: ["names"] },
    {
      kind: "permissions",
      capabilities: ["names"],
      hnsNames: [hnsDisclosure("a-1_name")]
    }
  );
  approve(
    "wallet_requestPermissions",
    { capabilities: ["names"] },
    {
      kind: "permissions",
      capabilities: ["names"],
      hnsNames: [hnsDisclosure("a".repeat(63))]
    }
  );
});

test("approval schema v3 HNS disclosure constraints fail closed", () => {
  const alpha = hnsDisclosure("alpha");
  const beta = hnsDisclosure("beta");
  const candidate = (hnsNames, capabilities = ["names"], method = "wallet_requestPermissions") =>
    approvalCandidate(method, { kind: "permissions", capabilities, hnsNames });
  const params = { capabilities: ["names"] };

  rejects(
    approvalCandidate("wallet_requestPermissions", {
      kind: "permissions",
      capabilities: ["names"]
    }),
    "wallet_requestPermissions",
    params
  );
  rejects(candidate([beta, alpha]), "wallet_requestPermissions", params);
  rejects(candidate([alpha, alpha]), "wallet_requestPermissions", params);
  rejects(
    candidate([{ ...alpha, nameHash: beta.nameHash }]),
    "wallet_requestPermissions",
    params
  );
  rejects(
    candidate([{ ...alpha, nameHash: alpha.nameHash.toUpperCase() }]),
    "wallet_requestPermissions",
    params
  );
  rejects(
    candidate([{ ...alpha, privateField: true }]),
    "wallet_requestPermissions",
    params
  );
  for (const name of [
    "",
    "Alpha",
    "-alpha",
    "alpha-",
    "_alpha",
    "alpha_",
    "alpha.name",
    "example",
    "a".repeat(64)
  ]) {
    rejects(candidate([hnsDisclosure(name)]), "wallet_requestPermissions", params);
  }

  rejects(
    candidate([alpha], ["balance"]),
    "wallet_requestPermissions",
    { capabilities: ["balance"] }
  );
  rejects(
    candidate([alpha], ["accounts"], "hns_requestAccounts"),
    "hns_requestAccounts",
    null
  );

  const maximum = Array.from(
    { length: 64 },
    (_, index) => hnsDisclosure(`name${String(index).padStart(2, "0")}`)
  );
  approve(
    "wallet_requestPermissions",
    { capabilities: ["names"] },
    { kind: "permissions", capabilities: ["names"], hnsNames: maximum }
  );
  rejects(
    candidate([...maximum, hnsDisclosure("name64")]),
    "wallet_requestPermissions",
    params
  );
});

test("actions, typed digests, warnings, and swap finality remain structurally bound", () => {
  const moduleCase = APPROVAL_CASES[1];
  rejects(
    approvalCandidate(moduleCase.method, { ...moduleCase.summary, action: "disable" }),
    moduleCase.method,
    moduleCase.params
  );
  const typed = APPROVAL_CASES[5];
  const { messageDigest: _digest, ...missingDigest } = typed.summary;
  rejects(approvalCandidate(typed.method, missingDigest), typed.method, typed.params);

  const fill = APPROVAL_CASES[9];
  rejects(
    approvalCandidate(fill.method, {
      ...fill.summary,
      warnings: ["settlementCanBeDelayed", "refundRequiresManualAction"]
    }),
    fill.method,
    fill.params
  );
  rejects(
    approvalCandidate(fill.method, {
      ...fill.summary,
      warnings: ["refundRequiresManualAction", "refundRequiresManualAction"]
    }),
    fill.method,
    fill.params
  );

  const redeem = APPROVAL_CASES[10];
  rejects(
    approvalCandidate(redeem.method, {
      ...redeem.summary,
      finality: "proof_of_work_confirmations"
    }),
    redeem.method,
    redeem.params
  );
  rejects(
    approvalCandidate(redeem.method, {
      ...redeem.summary,
      amount: amount("HNS", "2000"),
      maximumFee: amount("HNS", "25"),
      finality: "ethereum_finalized_checkpoint"
    }),
    redeem.method,
    redeem.params
  );
});

function amount(asset, baseUnits) {
  return { asset, baseUnits };
}

function hnsDisclosure(name) {
  return {
    name,
    nameHash: createHash("sha3-256").update(name, "ascii").digest("hex")
  };
}

function approvalCandidate(method, summary, overrides = {}) {
  return {
    schemaVersion: WALLET_APPROVAL_SCHEMA_VERSION,
    approvalId: APPROVAL_ID,
    method,
    origin: binding.origin,
    expiresAtUnixMs: NOW + 60_000,
    summary,
    ...overrides
  };
}

function approve(method, params, summary) {
  return validateApprovalPrompt(
    approvalCandidate(method, summary),
    binding,
    { method, params },
    NOW
  );
}

function rejects(candidate, method, params) {
  assert.throws(
    () => validateApprovalPrompt(candidate, binding, { method, params }, NOW),
    (error) => error.code === "invalidApproval"
  );
}
