export const DEFAULT_POLICY = Object.freeze({
  recursiveHnsDohUrl: "",
  p2pDnsRelay: false,
  p2pOdoh: "off",
  privacyDowngrade: "failClosed",
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
const WIRE_PROFILES = new Set(["stable", "hipDrafts", "denuoExtension"]);
const MAX_RECURSIVE_HNS_DOH_URL_BYTES = 2_048;

export function normalizePolicy(value) {
  const candidate = isRecord(value) ? value : {};
  return {
    recursiveHnsDohUrl: normalizeResolverUrl(candidate.recursiveHnsDohUrl),
    p2pDnsRelay: candidate.p2pDnsRelay === true,
    p2pOdoh: memberOrDefault(candidate.p2pOdoh, P2P_ODOH_MODES, "off"),
    privacyDowngrade: memberOrDefault(
      candidate.privacyDowngrade,
      PRIVACY_DOWNGRADES,
      "failClosed"
    ),
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
      version: 2,
      publicRecursiveHnsDohRemoved: removedLegacyKeys.length > 0,
      p2pRelayConsentInherited: false
    }
  };
}

function normalizeResolverUrl(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  // Preserve one byte past the native limit so Rust returns an explicit
  // validation error without allowing unbounded extension storage input to
  // enter a native-messaging request.
  return trimmed.slice(0, MAX_RECURSIVE_HNS_DOH_URL_BYTES + 1);
}

function memberOrDefault(value, allowed, fallback) {
  return typeof value === "string" && allowed.has(value) ? value : fallback;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
