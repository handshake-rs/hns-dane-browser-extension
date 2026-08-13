import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  MAX_NAVIGATION_GATE_TARGET_BYTES,
  NAVIGATION_GATE_ALLOW_RULE_ID,
  NAVIGATION_GATE_BOOTSTRAP_RULE_ID,
  NAVIGATION_GATE_REDIRECT_RULE_ID,
  NavigationGateController,
  navigationGateAllowRule,
  navigationGateRedirectRule,
  validNavigationGateTarget
} from "../src/navigation-gate.js";

test("navigation rules synchronously hold only top-level GET requests", () => {
  const waitPage = "chrome-extension://abcdefghijklmnop/src/proxy-wait.html";
  const redirect = navigationGateRedirectRule(waitPage);
  const allow = navigationGateAllowRule();

  assert.equal(redirect.id, NAVIGATION_GATE_REDIRECT_RULE_ID);
  assert.equal(redirect.priority, 2);
  assert.equal(
    redirect.action.redirect.regexSubstitution,
    `${waitPage}#\\1`
  );
  assert.deepEqual(redirect.condition.resourceTypes, ["main_frame"]);
  assert.deepEqual(redirect.condition.requestMethods, ["get"]);
  assert.equal(allow.id, NAVIGATION_GATE_ALLOW_RULE_ID);
  assert.equal(allow.priority, 3);
  assert.equal(allow.action.type, "allow");
  assert.deepEqual(allow.condition, redirect.condition);

  const bootstrap = JSON.parse(
    readFileSync("extension/rules/navigation-gate.json", "utf8")
  );
  assert.deepEqual(bootstrap, [
    {
      id: NAVIGATION_GATE_BOOTSTRAP_RULE_ID,
      priority: 1,
      action: {
        type: "redirect",
        redirect: { extensionPath: "/src/proxy-wait.html" }
      },
      condition: redirect.condition
    }
  ]);
});

test("waiting-page targets are bounded, HTTP-only, and credential-free", () => {
  assert.equal(
    validNavigationGateTarget("https://news.google.com/topstories?hl=en"),
    "https://news.google.com/topstories?hl=en"
  );
  assert.equal(validNavigationGateTarget("http://example.com"), "http://example.com/");
  for (const rejected of [
    "",
    "chrome://settings/",
    "file:///tmp/private",
    "javascript:alert(1)",
    "https://user:secret@example.com/",
    "not a URL",
    `https://example.com/${"x".repeat(MAX_NAVIGATION_GATE_TARGET_BYTES)}`
  ]) {
    assert.equal(validNavigationGateTarget(rejected), null, rejected);
  }
});

test("the gate closes before blocker work and opens only for the current generation", async () => {
  const mutations = [];
  let currentEpoch = 7;
  let now = 100;
  const gate = new NavigationGateController({
    updateDynamicRules: async (update) => mutations.push(["dynamic", update]),
    updateSessionRules: async (update) => mutations.push(["session", update]),
    waitPageUrl: "chrome-extension://abcdefghijklmnop/src/proxy-wait.html",
    isCurrent: (epoch) => epoch === currentEpoch,
    now: () => now
  });

  assert.deepEqual(gate.status(null), {
    schemaVersion: 1,
    ready: false,
    openRevision: null
  });
  await gate.close(7);
  assert.deepEqual(mutations.map(([kind]) => kind), ["session", "dynamic"]);
  assert.deepEqual(mutations[0][1], {
    removeRuleIds: [NAVIGATION_GATE_ALLOW_RULE_ID]
  });

  const revision = await gate.open(7);
  assert.equal(revision, "100-1");
  assert.equal(
    gate.logicallyOpen({
      state: "active",
      proxyActive: true,
      headerSync: {
        treeRootReady: true,
        blocksUntilAuthoritativeTreeRoot: 0,
        targetEvidenceExpired: false,
        targetEvidenceValidUntilUnix: 10
      }
    }),
    true
  );
  assert.deepEqual(mutations.slice(2).map(([kind]) => kind), ["dynamic", "session"]);
  assert.equal(
    gate.status({
      state: "active",
      proxyActive: true,
      headerSync: {
        treeRootReady: true,
        blocksUntilAuthoritativeTreeRoot: 0,
        targetEvidenceExpired: false,
        targetEvidenceValidUntilUnix: 10
      }
    }).ready,
    true
  );
  now = 10_000;
  assert.equal(
    gate.status({
      state: "active",
      proxyActive: true,
      headerSync: {
        treeRootReady: true,
        blocksUntilAuthoritativeTreeRoot: 0,
        targetEvidenceExpired: false,
        targetEvidenceValidUntilUnix: 10
      }
    }).ready,
    false
  );
  now = 100;
  assert.equal(
    gate.status({
      state: "active",
      proxyActive: true,
      headerSync: {
        treeRootReady: false,
        blocksUntilAuthoritativeTreeRoot: 1,
        targetEvidenceExpired: false,
        targetEvidenceValidUntilUnix: 10
      }
    }).ready,
    false
  );

  currentEpoch = 8;
  now = 101;
  await assert.rejects(gate.close(7), /superseded/);
  assert.equal(
    gate.status({
      state: "active",
      proxyActive: true,
      headerSync: {
        treeRootReady: true,
        blocksUntilAuthoritativeTreeRoot: 0,
        targetEvidenceExpired: false,
        targetEvidenceValidUntilUnix: 10
      }
    }).openRevision,
    revision
  );
});

test("a queued close cannot leave a removed allow rule reported open", async () => {
  const mutations = [];
  let releaseFirstDynamic;
  const firstDynamic = new Promise((resolve) => {
    releaseFirstDynamic = resolve;
  });
  let dynamicCalls = 0;
  const gate = new NavigationGateController({
    updateDynamicRules: async (update) => {
      mutations.push(["dynamic", update]);
      dynamicCalls += 1;
      if (dynamicCalls === 1) await firstDynamic;
    },
    updateSessionRules: async (update) => mutations.push(["session", update]),
    waitPageUrl: "chrome-extension://abcdefghijklmnop/src/proxy-wait.html",
    isCurrent: (epoch) => epoch === 9,
    now: () => 200
  });
  const open = gate.open(9);
  const close = gate.close(9);
  releaseFirstDynamic();
  await open;
  await close;

  assert.deepEqual(mutations.map(([kind]) => kind), [
    "dynamic",
    "session",
    "session",
    "dynamic"
  ]);
  assert.deepEqual(gate.status(null), {
    schemaVersion: 1,
    ready: false,
    openRevision: null
  });
});

test("a failed allow-rule removal aborts close before redirect repair", async () => {
  const mutations = [];
  let sessionCalls = 0;
  const gate = new NavigationGateController({
    updateDynamicRules: async (update) => mutations.push(["dynamic", update]),
    updateSessionRules: async (update) => {
      mutations.push(["session", update]);
      sessionCalls += 1;
      if (sessionCalls === 2) throw new Error("session rules unavailable");
    },
    waitPageUrl: "chrome-extension://abcdefghijklmnop/src/proxy-wait.html",
    isCurrent: (epoch) => epoch === 10,
    now: () => 300
  });

  await gate.open(10);
  await assert.rejects(gate.close(10), /session rules unavailable/);
  assert.deepEqual(mutations.map(([kind]) => kind), [
    "dynamic",
    "session",
    "session"
  ]);
  assert.deepEqual(gate.status(null), {
    schemaVersion: 1,
    ready: false,
    openRevision: null
  });
});
