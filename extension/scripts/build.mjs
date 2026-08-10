import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const output = resolve("dist/chromium-extension");
const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
if (manifest.manifest_version !== 3) throw new Error("Manifest V3 is required");
if (manifest.background?.service_worker !== "src/service-worker.js") {
  throw new Error("the Rust-native lifecycle service worker is required");
}
for (const permission of [
  "nativeMessaging",
  "proxy",
  "storage",
  "webNavigation",
  "webRequest",
  "webRequestAuthProvider"
]) {
  if (!manifest.permissions.includes(permission)) {
    throw new Error(`missing extension permission: ${permission}`);
  }
}

rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
cpSync("extension/manifest.json", `${output}/manifest.json`);
cpSync("extension/src", `${output}/src`, { recursive: true });
cpSync("extension/assets", `${output}/assets`, { recursive: true });
cpSync("LICENSE", `${output}/LICENSE`);
cpSync("docs/privacy-policy.md", `${output}/PRIVACY.md`);
cpSync(
  "extension/THIRD_PARTY_NOTICES.txt",
  `${output}/THIRD_PARTY_NOTICES.txt`
);
writeFileSync(
  `${output}/BUILD-METADATA.json`,
  `${JSON.stringify(
    {
      schemaVersion: 1,
      package: "hns-dane-browser-extension",
      version: manifest.version,
      sourceRepository:
        "https://github.com/handshake-rs/hns-dane-browser-extension",
      license: "PolyForm-Noncommercial-1.0.0",
      licenseFile: "LICENSE",
      privacyPolicy:
        "https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/docs/privacy-policy.md",
      support:
        "https://github.com/handshake-rs/hns-dane-browser-extension/issues",
      donations: "https://github.com/sponsors/denuoweb",
      nativeHost: "com.denuoweb.hns_dane_browser",
      pacAuthority: "hns-browser-runtime",
      localCaRequired: true,
      supportedBrowsers: [
        "chrome",
        "chromium",
        "edge",
        "brave",
        "vivaldi",
        "opera"
      ],
      supportedDesktopPlatforms: ["linux", "macos", "windows"]
    },
    null,
    2
  )}\n`
);
console.log(output);
