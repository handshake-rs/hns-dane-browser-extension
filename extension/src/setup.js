const extensionId = globalThis.chrome?.runtime?.id;
if (typeof extensionId === "string" && /^[a-p]{32}$/.test(extensionId)) {
  document.querySelector("#extension-id").textContent = extensionId;
}

const extensionManifest = globalThis.chrome?.runtime?.getManifest?.();
const extensionVersion = extensionManifest?.version;
if (
  typeof extensionVersion === "string" &&
  /^\d+(?:\.\d+){1,3}$/.test(extensionVersion)
) {
  document.querySelector("#extension-version").textContent = extensionVersion;
  document.querySelector("#version-downloads").href =
    `https://github.com/handshake-rs/hns-dane-browser-extension/releases/tag/v${extensionVersion}`;
}
