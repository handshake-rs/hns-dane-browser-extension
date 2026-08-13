import {
  formatInstallerSize,
  platformLabel,
  selectEmbeddedInstaller
} from "./native-component.js";

const extensionId = globalThis.chrome?.runtime?.id;
const extensionManifest = globalThis.chrome?.runtime?.getManifest?.();
const extensionVersion = extensionManifest?.version;

if (globalThis.document) initializeSetupPage();

function initializeSetupPage() {
  if (typeof extensionId === "string" && /^[a-p]{32}$/.test(extensionId)) {
    document.querySelector("#extension-id").textContent = extensionId;
  }
  if (
    typeof extensionVersion === "string" &&
    /^\d+(?:\.\d+){2,3}$/.test(extensionVersion)
  ) {
    document.querySelector("#extension-version").textContent = extensionVersion;
  }

  document.querySelector("#copy-extension-id").addEventListener("click", async () => {
    const status = document.querySelector("#copy-status");
    if (typeof extensionId !== "string" || !/^[a-p]{32}$/.test(extensionId)) {
      status.textContent = "The exact extension ID is unavailable.";
      return;
    }
    try {
      await navigator.clipboard.writeText(extensionId);
      status.textContent = "Exact extension ID copied.";
    } catch {
      status.textContent = "Select the ID above and copy it manually.";
    }
  });

  renderUpdateReason();
  void initializeEmbeddedSetup();
}

async function initializeEmbeddedSetup() {
  const status = document.querySelector("#installer-status");
  const uninstallStatus = document.querySelector("#uninstall-installer-status");
  try {
    if (typeof extensionVersion !== "string") {
      throw new Error("the extension version is unavailable");
    }
    const [platformInfo, response] = await Promise.all([
      chrome.runtime.getPlatformInfo(),
      fetch(chrome.runtime.getURL("installers/index.json"))
    ]);
    if (!response.ok) {
      throw new Error(`embedded Setup index could not be read (${response.status})`);
    }
    const index = await response.json();
    const selection = selectEmbeddedInstaller(
      index,
      platformInfo,
      extensionVersion
    );
    if (!selection) {
      status.textContent =
        "No embedded Setup is available for this operating system and CPU.";
      uninstallStatus.textContent = status.textContent;
      return;
    }
    const windowsTrust = validateWindowsInstallerTrust(index, selection);
    const label = platformLabel(selection);
    const setupUrl = chrome.runtime.getURL(selection.path);
    document.querySelector("#detected-platform").textContent = label;
    configureDownload("#download-setup", setupUrl, selection.fileName);
    configureDownload(
      "#download-uninstall-setup",
      setupUrl,
      selection.fileName
    );
    document.querySelector("#installer-file").textContent = selection.fileName;
    document.querySelector("#installer-size").textContent =
      formatInstallerSize(selection.size) || "Included in this extension";
    document.querySelector("#installer-signing").textContent =
      windowsTrust
        ? "Project self-signed Authenticode; RFC 3161 SHA-256 timestamp"
        : selection.signingStatus ?? "See package metadata";
    document.querySelector("#installer-sha256").textContent =
      selection.sha256 ?? "See package metadata";
    renderWindowsSigningDisclosure(windowsTrust);
    const snapshotDetail = selection.snapshot
      ? ` It contains validated Handshake headers through block ${selection.snapshot.height.toLocaleString("en-US")}.`
      : "";
    status.textContent = `Selected ${label}.${snapshotDetail}`;
    uninstallStatus.textContent = `The ${label} package above also provides Complete Uninstall.`;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    status.textContent = `Embedded Setup is unavailable: ${detail}`;
    uninstallStatus.textContent =
      "Complete Uninstall requires the matching Setup package. Contact support if this store package omitted it.";
  }
}

export function validateWindowsInstallerTrust(index, selection) {
  if (selection?.platform !== "windows") return null;
  if (!selection.sha256 || !/^[a-f0-9]{64}$/.test(selection.sha256)) {
    throw new Error("Windows Setup is missing its archive SHA-256");
  }
  if (!index || typeof index !== "object" || !Array.isArray(index.installers)) {
    throw new Error("Windows Setup trust metadata is missing");
  }
  const matching = index.installers.filter(
    (candidate) =>
      candidate &&
      typeof candidate === "object" &&
      candidate.platform === "windows" &&
      candidate.path === selection.path
  );
  if (matching.length !== 1) {
    throw new Error("Windows Setup trust metadata is missing or ambiguous");
  }
  const metadata = matching[0];
  if (metadata.signingStatus !== "selfSignedAuthenticodeAndTimestamped") {
    throw new Error("Windows Setup lacks the required self-signed Authenticode status");
  }
  if (metadata.certificateTrust !== "notPubliclyTrusted") {
    throw new Error("Windows Setup certificate trust metadata is invalid");
  }
  if (
    typeof metadata.signerCertificateSha256 !== "string" ||
    !/^[a-fA-F0-9]{64}$/.test(metadata.signerCertificateSha256)
  ) {
    throw new Error("Windows Setup signer certificate SHA-256 is missing or invalid");
  }
  return Object.freeze({
    certificateTrust: metadata.certificateTrust,
    signerCertificateSha256: metadata.signerCertificateSha256.toLowerCase()
  });
}

function renderWindowsSigningDisclosure(windowsTrust) {
  if (!windowsTrust) return;
  document.querySelector("#windows-archive-sha256").textContent =
    formatFingerprint(document.querySelector("#installer-sha256").textContent);
  document.querySelector("#windows-certificate-sha256").textContent =
    formatFingerprint(windowsTrust.signerCertificateSha256);
  document.querySelector("#windows-signing-warning").hidden = false;
}

function formatFingerprint(value) {
  return String(value)
    .toUpperCase()
    .match(/.{1,2}/g)
    ?.join(":") ?? "—";
}

function configureDownload(selector, url, fileName) {
  const link = document.querySelector(selector);
  link.href = url;
  link.download = fileName;
  link.hidden = false;
}

function renderUpdateReason() {
  const parameters = new URLSearchParams(globalThis.location?.search ?? "");
  if (parameters.get("reason") !== "native-component-update") return;
  const installed = parameters.get("installed");
  const warning = document.querySelector("#native-update-warning");
  warning.hidden = false;
  warning.textContent = installed
    ? `Extension ${extensionVersion} detected native component ${installed}. Download and run the newly embedded Setup below; browsing remains blocked until their versions match.`
    : `Extension ${extensionVersion} detected an incompatible native component. Download and run the newly embedded Setup below; browsing remains blocked until their versions match.`;
}
