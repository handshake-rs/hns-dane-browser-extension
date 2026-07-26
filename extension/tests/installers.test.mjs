import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const nativeHost = resolve("rust/target/debug/hns-chromium-native-host");
const installScript = resolve("extension/install/install.sh");
const uninstallScript = resolve("extension/install/uninstall.sh");
const extensionId = "abcdefghijklmnopabcdefghijklmnop";

test("Linux installer and complete uninstaller are isolated and symmetric", () => {
  const root = mkdtempSync(join(tmpdir(), "hns-chromium-installer-"));
  try {
    const home = join(root, "home");
    const configHome = join(root, "config");
    const dataHome = join(root, "data");
    const nssDatabase = join(root, "nssdb");
    const fakeBin = join(root, "bin");
    const certutilLog = join(root, "certutil.log");
    const installRoot = join(root, "custom-install");
    run("mkdir", ["-p", home, configHome, dataHome, nssDatabase, fakeBin]);
    const fakeCertutil = join(fakeBin, "certutil");
    writeFileSync(
      fakeCertutil,
      `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >>"$HNS_CERTUTIL_LOG"\nexit 0\n`
    );
    chmodSync(fakeCertutil, 0o700);
    const environment = {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: configHome,
      XDG_DATA_HOME: dataHome,
      HNS_CHROMIUM_INSTALL_ROOT: installRoot,
      HNS_CHROMIUM_NSS_DB_DIR: nssDatabase,
      HNS_CERTUTIL_LOG: certutilLog,
      PATH: `${fakeBin}:${process.env.PATH ?? ""}`
    };
    delete environment.HNS_CHROMIUM_DATA_DIR;

    run(
      "bash",
      [
        installScript,
        "--extension-id",
        extensionId,
        "--browser",
        "all",
        "--native-host",
        nativeHost
      ],
      environment
    );

    const expectedManifestDirectories = [
      "google-chrome",
      "chromium",
      "microsoft-edge",
      "BraveSoftware/Brave-Browser",
      "vivaldi",
      "opera"
    ];
    for (const directory of expectedManifestDirectories) {
      const manifestPath = join(
        configHome,
        directory,
        "NativeMessagingHosts/com.denuoweb.hns_dane_browser.json"
      );
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
      assert.deepEqual(manifest.allowed_origins, [
        `chrome-extension://${extensionId}/`
      ]);
      assert.equal(manifest.path, join(installRoot, "bin/hns-chromium-native-host"));
    }
    assert.ok(
      existsSync(join(installRoot, "data/chromium-ca/ca-installed.json"))
    );
    assert.equal(
      statSync(join(installRoot, "data/chromium-ca/ca-bundle.json")).mode & 0o077,
      0
    );
    assert.match(
      readFileSync(
        join(installRoot, "licenses/THIRD_PARTY_NOTICES.txt"),
        "utf8"
      ),
      /^HNS DANE BROWSER CHROMIUM THIRD-PARTY SOFTWARE NOTICES\n/
    );
    assert.match(readFileSync(certutilLog, "utf8"), / -A /);

    const installedHost = join(installRoot, "bin/hns-chromium-native-host");
    const defaultCaStatus = JSON.parse(
      run(installedHost, ["--ca-info"], environment).stdout
    );
    assert.equal(defaultCaStatus.state, "installed");
    assert.equal(
      defaultCaStatus.certificatePath,
      join(
        installRoot,
        "data/chromium-ca/hns-dane-browser-local-ca.pem"
      )
    );
    assert.equal(existsSync(join(installRoot, "chromium-ca")), false);
    assert.equal(
      existsSync(join(dataHome, "hns-dane-browser/chromium")),
      false
    );

    run("bash", [uninstallScript, "--browser", "all"], environment);
    assert.equal(existsSync(installRoot), false);
    for (const directory of expectedManifestDirectories) {
      assert.equal(
        existsSync(
          join(
            configHome,
            directory,
            "NativeMessagingHosts/com.denuoweb.hns_dane_browser.json"
          )
        ),
        false
      );
    }
    assert.match(readFileSync(certutilLog, "utf8"), / -D /);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Windows scripts cover all browser registries, CA trust, and removal", () => {
  const install = readFileSync("extension/install/install.ps1", "utf8");
  const uninstall = readFileSync("extension/install/uninstall.ps1", "utf8");
  for (const browser of [
    "Google\\Chrome",
    "Chromium",
    "Microsoft\\Edge",
    "BraveSoftware\\Brave-Browser",
    "Vivaldi"
  ]) {
    assert.ok(install.includes(browser), browser);
    assert.ok(uninstall.includes(browser), browser);
  }
  assert.match(install, /certutil\.exe -user -addstore Root/);
  assert.match(install, /THIRD_PARTY_NOTICES\.txt/);
  assert.match(uninstall, /certutil\.exe -user -delstore Root/);
  assert.match(uninstall, /Remove-Item .* -Recurse -Force/);
});

function run(command, arguments_, environment = process.env) {
  const result = spawnSync(command, arguments_, {
    env: environment,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024
  });
  assert.equal(result.status, 0, `${command}: ${result.stderr || result.stdout}`);
  return result;
}
