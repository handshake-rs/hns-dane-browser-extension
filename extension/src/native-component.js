const VERSION_PATTERN = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?$/;
const EMBEDDED_INSTALLER_PATH_PATTERN = /^installers\/[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$/;

export const INSTALLER_INDEX_SCHEMA_VERSION = 1;

export function inspectNativeComponent(hello, extensionVersion) {
  if (!validVersion(extensionVersion)) {
    throw new Error("the extension manifest has an invalid version");
  }
  const nativeHostVersion =
    isRecord(hello) && validVersion(hello.nativeHost)
      ? hello.nativeHost
      : null;
  if (nativeHostVersion == null) {
    return Object.freeze({
      state: "incompatible",
      extensionVersion,
      nativeHostVersion: null
    });
  }
  return Object.freeze({
    state:
      nativeHostVersion === extensionVersion ? "ready" : "versionMismatch",
    extensionVersion,
    nativeHostVersion
  });
}

export function nativeSetupPromptRequired(storedVersion, requiredVersion) {
  if (!validVersion(requiredVersion)) return false;
  return storedVersion !== requiredVersion;
}

export function normalizeChromiumPlatform(platformInfo) {
  if (!isRecord(platformInfo)) return null;
  const platform = {
    linux: "linux",
    mac: "macos",
    win: "windows"
  }[platformInfo.os];
  const architecture = {
    "x86-64": "x64",
    x64: "x64",
    arm64: "arm64"
  }[platformInfo.arch];
  if (!platform || !architecture) return null;
  return Object.freeze({ platform, architecture });
}

export function selectEmbeddedInstaller(index, platformInfo, extensionVersion) {
  if (!isRecord(index) || index.schemaVersion !== INSTALLER_INDEX_SCHEMA_VERSION) {
    throw new Error("the embedded Setup index has an unsupported schema");
  }
  if (!validVersion(extensionVersion) || index.version !== extensionVersion) {
    throw new Error("the embedded Setup index does not match this extension version");
  }
  if (!Array.isArray(index.installers) || index.installers.length < 1) {
    throw new Error("the embedded Setup index contains no installers");
  }
  const normalizedPlatform = normalizeChromiumPlatform(platformInfo);
  if (!normalizedPlatform) return null;
  const matches = index.installers.filter((candidate) => {
    if (!isRecord(candidate)) return false;
    return (
      candidate.platform === normalizedPlatform.platform &&
      normalizedArchitecture(candidate.architecture ?? candidate.arch) ===
        normalizedPlatform.architecture
    );
  });
  if (matches.length !== 1) {
    if (matches.length === 0) return null;
    throw new Error("the embedded Setup index has duplicate platform entries");
  }
  const candidate = matches[0];
  const fileName =
    typeof candidate.path === "string"
      ? candidate.path.slice("installers/".length)
      : null;
  if (
    (candidate.version ?? index.version) !== extensionVersion ||
    typeof candidate.path !== "string" ||
    !EMBEDDED_INSTALLER_PATH_PATTERN.test(candidate.path) ||
    (candidate.fileName != null && candidate.fileName !== fileName)
  ) {
    throw new Error("the embedded Setup entry is invalid");
  }
  if (
    candidate.size != null &&
    (!Number.isSafeInteger(candidate.size) || candidate.size < 1)
  ) {
    throw new Error("the embedded Setup entry has an invalid size");
  }
  if (
    candidate.sha256 != null &&
    (typeof candidate.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(candidate.sha256))
  ) {
    throw new Error("the embedded Setup entry has an invalid SHA-256 digest");
  }
  return Object.freeze({
    platform: normalizedPlatform.platform,
    architecture: normalizedPlatform.architecture,
    version: candidate.version ?? index.version,
    path: candidate.path,
    fileName,
    size: candidate.size ?? null,
    sha256: candidate.sha256 ?? null,
    signingStatus:
      typeof candidate.signingStatus === "string"
        ? candidate.signingStatus.slice(0, 64)
        : null,
    snapshot: normalizedSnapshot(index.snapshot)
  });
}

export function formatInstallerSize(size) {
  if (!Number.isSafeInteger(size) || size < 1) return "";
  const mebibytes = size / (1024 * 1024);
  return `${mebibytes >= 10 ? mebibytes.toFixed(0) : mebibytes.toFixed(1)} MiB`;
}

export function platformLabel(selection) {
  if (!selection) return "this system";
  const system = {
    linux: "Linux",
    macos: "macOS",
    windows: "Windows"
  }[selection.platform];
  const architecture = {
    x64: "Intel/AMD 64-bit",
    arm64: "ARM 64-bit"
  }[selection.architecture];
  return system && architecture ? `${system}, ${architecture}` : "this system";
}

function normalizedArchitecture(architecture) {
  return {
    x86_64: "x64",
    "x86-64": "x64",
    x64: "x64",
    amd64: "x64",
    aarch64: "arm64",
    arm64: "arm64"
  }[architecture] ?? null;
}

function normalizedSnapshot(snapshot) {
  if (!isRecord(snapshot)) return null;
  const height = snapshot.targetHeight ?? snapshot.height;
  if (!Number.isSafeInteger(height) || height < 0) return null;
  const sha256 = snapshot.compressedSha256 ?? snapshot.sha256;
  return Object.freeze({
    height,
    sha256:
      typeof sha256 === "string" && /^[a-f0-9]{64}$/.test(sha256)
        ? sha256
        : null
  });
}

function validVersion(value) {
  return (
    typeof value === "string" &&
    value.length <= 32 &&
    VERSION_PATTERN.test(value)
  );
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
