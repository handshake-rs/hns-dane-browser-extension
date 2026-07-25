export const DEFAULT_POLICY = Object.freeze({
  p2pDnsRelay: false,
  p2pOdoh: "off",
  privacyDowngrade: "failClosed",
  hnsr: "off",
  experimentalWireProfile: "stable"
});

export const LEGACY_HNS_DOH_KEYS = Object.freeze([
  "hnsDohResolver",
  "legacyHnsDohCompatibility",
  "thirdPartyHnsDoh",
  "compatibilityDohResolver"
]);

const P2P_ODOH_MODES = new Set(["off", "preferred", "required", "directAllowed"]);
const PRIVACY_DOWNGRADES = new Set(["failClosed", "allowDirect"]);
const HNSR_MODES = new Set(["off", "client", "endpoint"]);
const WIRE_PROFILES = new Set(["stable", "hipDrafts", "denuoExtension"]);

export function normalizePolicy(value) {
  const candidate = isRecord(value) ? value : {};
  return {
    p2pDnsRelay: candidate.p2pDnsRelay === true,
    p2pOdoh: memberOrDefault(candidate.p2pOdoh, P2P_ODOH_MODES, "off"),
    privacyDowngrade: memberOrDefault(
      candidate.privacyDowngrade,
      PRIVACY_DOWNGRADES,
      "failClosed"
    ),
    hnsr: memberOrDefault(candidate.hnsr, HNSR_MODES, "off"),
    experimentalWireProfile: memberOrDefault(
      candidate.experimentalWireProfile,
      WIRE_PROFILES,
      "stable"
    )
  };
}

export function migrateStoredSettings(values) {
  const source = isRecord(values) ? values : {};
  const removedLegacyKeys = LEGACY_HNS_DOH_KEYS.filter((key) =>
    Object.prototype.hasOwnProperty.call(source, key)
  );
  return {
    policy: normalizePolicy(source.policy),
    removedLegacyKeys,
    migration: {
      version: 1,
      publicRecursiveHnsDohRemoved: removedLegacyKeys.length > 0,
      p2pRelayConsentInherited: false
    }
  };
}

function memberOrDefault(value, allowed, fallback) {
  return typeof value === "string" && allowed.has(value) ? value : fallback;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
