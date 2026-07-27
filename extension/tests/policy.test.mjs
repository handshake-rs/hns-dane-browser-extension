import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_POLICY,
  migrateStoredSettings,
  normalizePolicy
} from "../src/policy.js";

test("legacy public HNS DoH settings are removed without inheriting relay consent", () => {
  const migration = migrateStoredSettings({
    legacyHnsDohCompatibility: true,
    hnsDohResolver: "https://legacy.example/dns-query",
    policy: {
      hnsDohResolver: "https://nested-legacy.example/dns-query"
    }
  });
  assert.deepEqual(migration.policy, DEFAULT_POLICY);
  assert.deepEqual(migration.removedLegacyKeys, [
    "hnsDohResolver",
    "legacyHnsDohCompatibility"
  ]);
  assert.equal(migration.migration.publicRecursiveHnsDohRemoved, true);
  assert.equal(migration.migration.p2pRelayConsentInherited, false);
});

test("policy normalization is bounded to known native-host values", () => {
  assert.deepEqual(
    normalizePolicy({
      p2pDnsRelay: true,
      p2pOdoh: "future",
      privacyDowngrade: "allowDirect",
      hnsr: "client",
      experimentalWireProfile: "future"
    }),
    {
      recursiveHnsDohUrl: "",
      p2pDnsRelay: true,
      p2pOdoh: "off",
      privacyDowngrade: "allowDirect",
      experimentalWireProfile: "stable"
    }
  );
});

test("new recursive HNS DoH consent is explicit, blank by default, and bounded", () => {
  assert.equal(normalizePolicy({}).recursiveHnsDohUrl, "");
  assert.equal(
    normalizePolicy({
      recursiveHnsDohUrl: "  https://hnsdoh.com/dns-query  "
    }).recursiveHnsDohUrl,
    "https://hnsdoh.com/dns-query"
  );
  assert.equal(
    normalizePolicy({ recursiveHnsDohUrl: "x".repeat(10_000) })
      .recursiveHnsDohUrl.length,
    2_049
  );
});

test("migration preserves only the new resolver key and never revives legacy values", () => {
  const migrated = migrateStoredSettings({
    hnsDohResolver: "https://legacy.example/dns-query",
    policy: {
      hnsDohResolver: "https://nested-legacy.example/dns-query",
      recursiveHnsDohUrl: "https://hnsdoh.com/dns-query"
    }
  });

  assert.equal(
    migrated.policy.recursiveHnsDohUrl,
    "https://hnsdoh.com/dns-query"
  );
  assert.deepEqual(migrated.removedLegacyKeys, ["hnsDohResolver"]);
  assert.equal(migrated.migration.version, 2);
});
