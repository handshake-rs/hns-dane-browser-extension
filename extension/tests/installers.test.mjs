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
    const legacyNssDatabase = join(home, ".pki/nssdb");
    const nssDatabase = join(dataHome, "pki/nssdb");
    const fakeBin = join(root, "bin");
    const certutilLog = join(root, "certutil.log");
    const certutilState = join(root, "certutil-state");
    const installRoot = join(dataHome, "hns-dane-browser/chromium");
    run("mkdir", ["-p", home, configHome, dataHome, fakeBin, certutilState]);
    const fakeCertutil = join(fakeBin, "certutil");
    writeFakeCertutil(fakeCertutil);
    const environment = {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: configHome,
      XDG_DATA_HOME: dataHome,
      HNS_CERTUTIL_LOG: certutilLog,
      HNS_CERTUTIL_STATE_DIR: certutilState,
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
    assert.equal(
      statSync(join(installRoot, ".manual-install-root")).mode & 0o077,
      0
    );
    assert.match(
      readFileSync(
        join(installRoot, "licenses/THIRD_PARTY_NOTICES.txt"),
        "utf8"
      ),
      /^HNS DANE BROWSER CHROMIUM THIRD-PARTY SOFTWARE NOTICES\n/
    );
    assert.match(
      readFileSync(join(installRoot, "licenses/LICENSE"), "utf8"),
      /^Required Notice: Copyright 2026 Denuo Web, LLC\.\n/
    );
    const installCertutilLog = readFileSync(certutilLog, "utf8");
    assert.match(installCertutilLog, / -A /);
    assert.ok(
      installCertutilLog.includes(`-d sql:${nssDatabase}`),
      installCertutilLog
    );

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
    const foreignDirectory = "vivaldi";
    const foreignManifest = join(
      configHome,
      foreignDirectory,
      "NativeMessagingHosts/com.denuoweb.hns_dane_browser.json"
    );
    writeFileSync(foreignManifest, '{"path":"/foreign/native-host"}\n');
    // Creating the legacy database after installation must not make uninstall
    // forget the exact certificate installed in the XDG database.
    run("mkdir", ["-p", legacyNssDatabase]);
    run("bash", [uninstallScript, "--browser", "all"], environment);
    assert.equal(existsSync(installRoot), false);
    for (const directory of expectedManifestDirectories) {
      const registeredManifest = join(
        configHome,
        directory,
        "NativeMessagingHosts/com.denuoweb.hns_dane_browser.json"
      );
      assert.equal(
        existsSync(registeredManifest),
        directory === foreignDirectory,
        registeredManifest
      );
    }
    assert.equal(
      readFileSync(foreignManifest, "utf8"),
      '{"path":"/foreign/native-host"}\n'
    );
    const finalCertutilLog = readFileSync(certutilLog, "utf8");
    assert.ok(
      finalCertutilLog.includes(`-d sql:${legacyNssDatabase}`),
      finalCertutilLog
    );
    assert.ok(
      finalCertutilLog.includes(`-d sql:${nssDatabase} -D `),
      finalCertutilLog
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Linux installer prefers an existing legacy Chromium NSS database", () => {
  const root = mkdtempSync(join(tmpdir(), "hns-chromium-legacy-nss-"));
  try {
    const home = join(root, "home");
    const configHome = join(root, "config");
    const dataHome = join(root, "data");
    const legacyNssDatabase = join(home, ".pki/nssdb");
    const xdgNssDatabase = join(dataHome, "pki/nssdb");
    const fakeBin = join(root, "bin");
    const certutilLog = join(root, "certutil.log");
    const certutilState = join(root, "certutil-state");
    run("mkdir", [
      "-p",
      home,
      configHome,
      dataHome,
      legacyNssDatabase,
      fakeBin,
      certutilState
    ]);
    const fakeCertutil = join(fakeBin, "certutil");
    writeFakeCertutil(fakeCertutil);
    const environment = {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: configHome,
      XDG_DATA_HOME: dataHome,
      HNS_CERTUTIL_LOG: certutilLog,
      HNS_CERTUTIL_STATE_DIR: certutilState,
      PATH: `${fakeBin}:${process.env.PATH ?? ""}`
    };

    run(
      "bash",
      [
        installScript,
        "--extension-id",
        extensionId,
        "--browser",
        "chromium",
        "--native-host",
        nativeHost
      ],
      environment
    );

    const log = readFileSync(certutilLog, "utf8");
    assert.ok(log.includes(`-d sql:${legacyNssDatabase}`), log);
    assert.equal(log.includes(`-d sql:${xdgNssDatabase}`), false, log);

    run("bash", [uninstallScript, "--browser", "all"], environment);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Unix uninstaller refuses an unowned fixed root", () => {
  const root = mkdtempSync(join(tmpdir(), "hns-chromium-unowned-root-"));
  try {
    const home = join(root, "home");
    const configHome = join(root, "config");
    const dataHome = join(root, "data");
    const installRoot = join(dataHome, "hns-dane-browser/chromium");
    const sentinel = join(installRoot, "keep.txt");
    run("mkdir", ["-p", home, configHome, installRoot]);
    writeFileSync(sentinel, "not owned\n");
    const result = runFailure(
      "bash",
      [uninstallScript, "--browser", "all"],
      {
        ...process.env,
        HOME: home,
        XDG_CONFIG_HOME: configHome,
        XDG_DATA_HOME: dataHome
      }
    );
    assert.match(result.stderr, /ownership marker/);
    assert.equal(readFileSync(sentinel, "utf8"), "not owned\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Unix installer refuses to replace a foreign registration", () => {
  const root = mkdtempSync(join(tmpdir(), "hns-chromium-foreign-registration-"));
  try {
    const home = join(root, "home");
    const configHome = join(root, "config");
    const dataHome = join(root, "data");
    const registration = join(
      configHome,
      "chromium/NativeMessagingHosts/com.denuoweb.hns_dane_browser.json"
    );
    run("mkdir", [
      "-p",
      home,
      dataHome,
      join(configHome, "chromium/NativeMessagingHosts")
    ]);
    writeFileSync(registration, '{"path":"/foreign/native-host"}\n');

    const result = runFailure(
      "bash",
      [
        installScript,
        "--extension-id",
        extensionId,
        "--browser",
        "chromium",
        "--native-host",
        nativeHost
      ],
      {
        ...process.env,
        HOME: home,
        XDG_CONFIG_HOME: configHome,
        XDG_DATA_HOME: dataHome
      }
    );
    assert.match(result.stderr, /foreign native-messaging registration/);
    assert.equal(
      readFileSync(registration, "utf8"),
      '{"path":"/foreign/native-host"}\n'
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Unix scripts use fixed roots and current platform trust-store semantics", () => {
  const install = readFileSync("extension/install/install.sh", "utf8");
  const uninstall = readFileSync("extension/install/uninstall.sh", "utf8");
  for (const script of [install, uninstall]) {
    assert.doesNotMatch(script, /HNS_CHROMIUM_INSTALL_ROOT/);
    assert.doesNotMatch(script, /HNS_CHROMIUM_NSS_DB_DIR/);
    assert.match(script, /legacy_nss_database=.*\.pki\/nssdb/);
    assert.match(script, /xdg_nss_database=.*pki\/nssdb/);
    assert.match(script, /security login-keychain/);
    assert.match(script, /delete-certificate -t -Z/);
    assert.doesNotMatch(script, /Library\/Keychains\/login\.keychain-db/);
  }
  assert.match(uninstall, /exact manual-install ownership marker/);
  assert.doesNotMatch(
    uninstall,
    /find-certificate -c "\$ca_common_name"/
  );
});

test("Windows scripts cover both registry views, exact CA trust, and fixed-root removal", () => {
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
  assert.match(install, /ProductLicenseSource/);
  assert.match(install, /LicenseDirectory 'LICENSE'/);
  assert.match(uninstall, /certutil\.exe -user -delstore Root/);
  assert.match(uninstall, /Remove-Item .* -Recurse -Force/);
  for (const script of [install, uninstall]) {
    assert.match(script, /RegistryView\]::Registry32/);
    assert.match(script, /RegistryView\]::Registry64/);
    assert.match(script, /OpenBaseKey/);
    assert.match(script, /\.manual-install-root/);
    assert.doesNotMatch(script, /\[string\] \$InstallRoot/);
  }
  assert.match(uninstall, /exact manual-install ownership marker/);
  assert.doesNotMatch(
    uninstall,
    /delstore Root 'HNS DANE Browser Local CA'/
  );
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

function runFailure(command, arguments_, environment = process.env) {
  const result = spawnSync(command, arguments_, {
    env: environment,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024
  });
  assert.notEqual(result.status, 0, `${command} unexpectedly succeeded`);
  return result;
}

function writeFakeCertutil(path) {
  writeFileSync(
    path,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >>"$HNS_CERTUTIL_LOG"
action=list
database=
input=
export_pem=false
has_nickname=false
while (($# > 0)); do
  case "$1" in
    -A) action=add; shift ;;
    -D) action=delete; shift ;;
    -L) action=list; shift ;;
    -a) export_pem=true; shift ;;
    -d) database="$2"; shift 2 ;;
    -i) input="$2"; shift 2 ;;
    -n) has_nickname=true; shift 2 ;;
    -t) shift 2 ;;
    *) shift ;;
  esac
done
database="\${database#sql:}"
database_key="$(printf '%s' "$database" | sha256sum | awk '{print $1}')"
state="$HNS_CERTUTIL_STATE_DIR/$database_key.pem"
case "$action" in
  add)
    cp -- "$input" "$state"
    ;;
  delete)
    rm -f -- "$state"
    ;;
  list)
    if [[ "$has_nickname" == true ]]; then
      [[ -f "$state" ]] || exit 255
      if [[ "$export_pem" == true ]]; then
        cat -- "$state"
      else
        printf 'Certificate present\\n'
      fi
    fi
    ;;
esac
`
  );
  chmodSync(path, 0o700);
}
