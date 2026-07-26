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
    hnsDohResolver: "https://resolver.invalid/dns-query"
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
      p2pDnsRelay: true,
      p2pOdoh: "off",
      privacyDowngrade: "allowDirect",
      experimentalWireProfile: "stable"
    }
  );
});
