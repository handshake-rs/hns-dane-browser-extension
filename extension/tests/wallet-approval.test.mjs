import test from "node:test";
import assert from "node:assert/strict";
import {
  approvalStorageKey,
  validateApprovalDecision,
  validateApprovalPrompt
} from "../src/wallet-approval.js";

const binding = Object.freeze({ origin: "https://welcome" });
const request = Object.freeze({ method: "asset_send" });

test("approval prompts contain only bounded public review fields", () => {
  const now = 1_800_000_000_000;
  const prompt = validateApprovalPrompt(
    {
      schemaVersion: 1,
      approvalId: "approval_1234567890",
      kind: "valueMovement",
      method: "asset_send",
      origin: "https://welcome",
      expiresAtUnixMs: now + 60_000,
      summary: {
        asset: "BTC",
        amountBaseUnits: "12000",
        recipient: "tb1qexample",
        feeBaseUnits: "420",
        chain: "bitcoin-regtest",
        confirmationPolicy: "2 confirmations"
      }
    },
    binding,
    request,
    now
  );
  assert.equal(prompt.summary.amountBaseUnits, "12000");
  assert.equal(approvalStorageKey(prompt.approvalId), "walletApproval:approval_1234567890");
  assert.equal(validateApprovalDecision("reject"), "reject");
});

test("approval prompts reject origin substitution, secrets, and long lifetimes", () => {
  const now = 1_800_000_000_000;
  const candidate = {
    schemaVersion: 1,
    approvalId: "approval_1234567890",
    kind: "valueMovement",
    method: "hns_send",
    origin: "https://attacker.example",
    expiresAtUnixMs: now + 60_000,
    summary: { asset: "HNS" }
  };
  assert.throws(
    () => validateApprovalPrompt(candidate, binding, { method: "hns_send" }, now),
    (error) => error.code === "invalidApproval"
  );
  assert.throws(
    () =>
      validateApprovalPrompt(
        {
          ...candidate,
          origin: binding.origin,
          summary: { privateKey: "secret" }
        },
        binding,
        { method: "hns_send" },
        now
      ),
    (error) => error.code === "invalidApproval"
  );
  assert.throws(
    () =>
      validateApprovalPrompt(
        {
          ...candidate,
          origin: binding.origin,
          expiresAtUnixMs: now + 11 * 60 * 1000
        },
        binding,
        { method: "hns_send" },
        now
      ),
    (error) => error.code === "invalidApproval"
  );
});

test("value movement prompts require canonical complete review fields", () => {
  const now = 1_800_000_000_000;
  const base = {
    schemaVersion: 1,
    approvalId: "approval_1234567890",
    kind: "valueMovement",
    method: "asset_send",
    origin: binding.origin,
    expiresAtUnixMs: now + 60_000,
    summary: {
      asset: "BTC",
      amountBaseUnits: "12000",
      recipient: "tb1qexample",
      feeBaseUnits: "420",
      chain: "bitcoin-regtest",
      confirmationPolicy: "2 confirmations"
    }
  };
  assert.throws(
    () => validateApprovalPrompt(
      { ...base, summary: { ...base.summary, amountBaseUnits: 12000 } },
      binding,
      request,
      now
    ),
    (error) => error.code === "invalidApproval"
  );
  const { feeBaseUnits: _fee, ...missingFee } = base.summary;
  assert.throws(
    () => validateApprovalPrompt(
      { ...base, summary: missingFee },
      binding,
      request,
      now
    ),
    (error) => error.code === "invalidApproval"
  );
  assert.throws(
    () => validateApprovalPrompt(
      { ...base, method: "hns_send" },
      binding,
      request,
      now
    ),
    (error) => error.code === "invalidApproval"
  );
});
