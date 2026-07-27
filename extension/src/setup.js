const extensionId = globalThis.chrome?.runtime?.id;
if (typeof extensionId === "string" && /^[a-p]{32}$/.test(extensionId)) {
  document.querySelector("#extension-id").textContent = extensionId;
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

const extensionManifest = globalThis.chrome?.runtime?.getManifest?.();
const extensionVersion = extensionManifest?.version;
if (
  typeof extensionVersion === "string" &&
  /^\d+(?:\.\d+){1,3}$/.test(extensionVersion)
) {
  document.querySelector("#extension-version").textContent = extensionVersion;
  const versionRelease =
    `https://github.com/handshake-rs/hns-dane-browser-extension/releases/tag/v${extensionVersion}`;
  document.querySelector("#version-downloads").href = versionRelease;
  document.querySelector("#manual-downloads").href = versionRelease;
}
