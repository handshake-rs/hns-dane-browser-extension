import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("extension/manifest.json", "utf8"));
const worker = readFileSync("extension/src/service-worker.js", "utf8");
const buildScript = readFileSync("extension/scripts/build.mjs", "utf8");
const options = readFileSync("extension/src/options.html", "utf8");
const optionsScript = readFileSync("extension/src/options.js", "utf8");
const popup = readFileSync("extension/src/popup.html", "utf8");
const popupScript = readFileSync("extension/src/popup.js", "utf8");
const setup = readFileSync("extension/src/setup.html", "utf8");
const setupScript = readFileSync("extension/src/setup.js", "utf8");
const waitPage = readFileSync("extension/src/proxy-wait.html", "utf8");
const waitPageScript = readFileSync("extension/src/proxy-wait.js", "utf8");
const navigationGateRules = JSON.parse(
  readFileSync("extension/rules/navigation-gate.json", "utf8")
);

test("manifest is MV3 with native messaging, mandatory proxy, and auth permissions", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "src/service-worker.js");
  assert.equal(manifest.background.type, "module");
  for (const permission of [
    "declarativeNetRequestWithHostAccess",
    "nativeMessaging",
    "proxy",
    "storage",
    "webNavigation",
    "webRequest",
    "webRequestAuthProvider"
  ]) {
    assert.ok(manifest.permissions.includes(permission), permission);
  }
  assert.equal(manifest.incognito, "not_allowed");
  assert.deepEqual(manifest.declarative_net_request, {
    rule_resources: [
      {
        id: "navigation_gate",
        enabled: true,
        path: "rules/navigation-gate.json"
      }
    ]
  });
  assert.equal(navigationGateRules[0].action.redirect.extensionPath, "/src/proxy-wait.html");
  assert.deepEqual(manifest.web_accessible_resources, [
    {
      resources: ["src/proxy-wait.html"],
      matches: ["http://*/*", "https://*/*"]
    }
  ]);
  for (const size of ["16", "32", "48", "128"]) {
    assert.equal(manifest.icons[size], `assets/icons/icon-${size}.png`);
    assert.equal(
      manifest.action.default_icon[size],
      `assets/icons/icon-${size}.png`
    );
    assert.ok(existsSync(`extension/assets/icons/icon-${size}.png`), size);
  }
});

test("main-frame navigation waits synchronously across proxy and root transitions", () => {
  assert.match(worker, /new NavigationGateController\(/);
  assert.match(
    worker,
    /await closeNavigationGateAndTransfer\(startControlEpoch\)[\s\S]*?await installBlockingPac\(startControlEpoch\)/
  );
  assert.match(
    worker,
    /await navigationGate\.open\(startControlEpoch\)[\s\S]*?state: "active"/
  );
  assert.match(worker, /case "navigationGateStatus"/);
  assert.match(
    worker,
    /headerSyncReadyForNavigationGate\(publicStatus\.headerSync\)[\s\S]*?await navigationGate\.open\(syncControlEpoch\)/
  );
  assert.match(
    worker,
    /nativeSyncAttempted = true;[\s\S]*?refreshNativeStatus\(true\)[\s\S]*?headerSyncReadyForNavigationGate\(publicStatus\.headerSync\) &&[\s\S]*?!nativeSyncAttempted/
  );
  assert.match(waitPage, /Waiting for the secure proxy/);
  assert.match(waitPageScript, /sessionStorage\.setItem/);
  assert.match(waitPageScript, /resumed\?\.target === target/);
  assert.match(waitPageScript, /location\.replace\(target\)/);
  assert.match(waitPageScript, /navigationGateBootstrap/);
  assert.doesNotMatch(waitPageScript, /tabs\.(?:reload|update)/);

  const refresh = worker.match(
    /async function refreshNativeStatus[\s\S]*?\n\}\n\nfunction maintainHeaderFreshness/
  )?.[0];
  assert.ok(refresh, "refreshNativeStatus implementation");
  const validatedFailure = refresh.indexOf("if (validatedNativeStatus)");
  const timeoutFallback = refresh.indexOf(
    "// A status timeout is not proof that the proxy listener died."
  );
  assert.ok(validatedFailure >= 0, "validated native status failure branch");
  assert.ok(timeoutFallback > validatedFailure, "timeout fallback ordering");
  assert.match(
    refresh.slice(validatedFailure, timeoutFallback),
    /deactivateProxyForHeaderReadiness/
  );
  assert.doesNotMatch(
    refresh.slice(validatedFailure, timeoutFallback),
    /navigationGate\.open/
  );
  assert.match(
    worker,
    /async function deactivateProxyForHeaderReadiness[\s\S]*?closeNavigationGateAndTransfer\(degradedControlEpoch\)[\s\S]*?closeNavigationGateAndTransfer\(degradedControlEpoch\)[\s\S]*?reason:[\s\S]*?"navigationGateCloseFailed"/
  );
  assert.match(worker, /HEADER_EVIDENCE_GATE_LEAD_MS = 30 \* 1000/);
  assert.match(
    worker,
    /expiresAt - HEADER_EVIDENCE_GATE_LEAD_MS/
  );
  assert.match(
    worker,
    /closeNavigationGateAndTransfer\(syncControlEpoch\)[\s\S]*?client\.request\(\s*"syncOnce"/
  );
  assert.match(worker, /RECOVERABLE_PROXY_NAVIGATION_ERRORS/);
  assert.match(
    worker,
    /const failedCandidate =\s*admitted \?\?[\s\S]*?const failureControlEpoch = controlEpoch;[\s\S]*?recoverProxyNavigationFailure\(\s*failedCandidate,\s*failureControlEpoch,\s*failureRuntimeControl\s*\)/
  );
  assert.match(
    worker,
    /async function recoverProxyNavigationFailure[\s\S]*?transferMainFrameNavigation\(candidate\)[\s\S]*?failureControlEpoch !== controlEpoch[\s\S]*?return refreshNativeStatus\(\)/
  );
  assert.doesNotMatch(
    worker.match(
      /async function recoverProxyNavigationFailure[\s\S]*?\n\}/
    )?.[0] ?? "",
    /startRuntime|deactivateProxyForHeaderReadiness|navigationGate\.close/
  );
  assert.match(
    worker,
    /async function closeNavigationGateAndTransfer[\s\S]*?catch \(error\)[\s\S]*?transferAdmittedMainFrameNavigations\(\)/
  );
  assert.match(worker, /navigationGate\.logicallyOpen\(publicStatus\)/);
});

test("service worker activates the authenticated proxy before initial header catch-up", () => {
  assert.match(worker, /mandatory:\s*true/);
  assert.match(worker, /result\.ca\.state !== "installed"/);
  assert.match(worker, /installBlockingPac\(startControlEpoch\)/);
  assert.match(
    worker,
    /installLivePac\(result\.pacScript, startControlEpoch\)/
  );
  assert.match(
    worker,
    /client\.disconnectIfCurrent\(replacedConnectionEpoch\)/
  );
  const startup = worker.match(
    /async function startRuntime\(policyOverride\) \{[\s\S]*?\n\}\n\nasync function establishStartupHeaderReadiness/
  )?.[0];
  assert.ok(startup, "startRuntime implementation");
  const earlyLivePac = startup.indexOf(
    "installLivePac(result.pacScript, startControlEpoch)"
  );
  const initialHeaderCatchUp = startup.indexOf(
    "activationStatus = await establishStartupHeaderReadiness"
  );
  assert.ok(earlyLivePac >= 0, "live PAC activation");
  assert.ok(
    earlyLivePac < initialHeaderCatchUp,
    "the native listener must replace the fixed blocker before initial sync"
  );
  assert.match(
    startup,
    /livePacConfirmed[\s\S]*?reason: "headerReadinessUnavailable"[\s\S]*?proxyActive: true[\s\S]*?return publicStatus/
  );
  assert.doesNotMatch(worker, /proxy\.settings\.clear/);
  assert.doesNotMatch(worker, /client\.request\("stop"\)/);
  assert.doesNotMatch(worker, /dnsResolve\s*\(/);
  assert.doesNotMatch(worker, /sha(?:1|256|512)/i);
  assert.doesNotMatch(worker, /route.*record/i);
});

test("service worker blocks an outdated native component before start and prompts once", () => {
  const startup = worker.match(
    /async function startRuntime\(policyOverride\) \{[\s\S]*?\n\}\n\nasync function establishStartupHeaderReadiness/
  )?.[0];
  assert.ok(startup, "startRuntime implementation");
  const blocker = startup.indexOf("await installBlockingPac(startControlEpoch)");
  const hello = startup.indexOf('client.request("hello")');
  const versionInspection = startup.indexOf("inspectNativeComponent(hello, EXTENSION_VERSION)");
  const nativeStart = startup.indexOf('client.request("start", { policy })');
  assert.ok(blocker >= 0 && blocker < hello, "the mandatory blocker precedes hello");
  assert.ok(hello < versionInspection, "hello is inspected");
  assert.ok(
    versionInspection < nativeStart,
    "exact native version acceptance precedes native startup"
  );
  assert.match(startup, /nativeComponentUpdateRequired/);
  assert.match(startup, /nativeComponentIncompatible/);
  assert.match(worker, /state: "blocked",[\s\S]*?nativeComponentState/);
  assert.match(worker, /NATIVE_SETUP_PROMPTED_VERSION_KEY/);
  assert.match(worker, /chrome\.storage\.session\.get/);
  assert.match(worker, /chrome\.storage\.session\.set/);
  assert.match(worker, /reason", "native-component-update"/);
  assert.match(worker, /setupUrl\.hash = "install"/);
});

test("health checks preserve a live generation and reconnect only after failure", () => {
  assert.match(
    worker,
    /alarm\.name === HEALTH_ALARM\)[\s\S]*?maintainHeaderFreshness\(true\)[\s\S]*?alarm\.name === RECONNECT_ALARM\)[\s\S]*?recover\(\)/
  );
  assert.doesNotMatch(
    worker,
    /alarm\.name === HEALTH_ALARM \|\| alarm\.name === RECONNECT_ALARM/
  );
});

test("popup requires an active PAC and never advertises direct sync bypass", () => {
  assert.match(
    popupScript,
    /status\.state === "active" && status\.proxyActive === true/
  );
  assert.doesNotMatch(popupScript, /Ordinary ICANN browsing remains direct/);
  assert.doesNotMatch(popupScript, /mandatory HNS proxy is paused/);
});

test("a rejected native policy is never persisted", () => {
  const setPolicyCase = worker.match(
    /case "setPolicy": \{[\s\S]*?\n    \}\n    case "diagnostics":/
  )?.[0];
  assert.ok(setPolicyCase, "setPolicy handler");
  assert.ok(
    setPolicyCase.indexOf("await startRuntime(policy)") <
      setPolicyCase.indexOf("await storageSet({ policy })"),
    "native activation must succeed before persistent storage changes"
  );
});

test("interception recovery controls are explicit, clearable, and privacy-disclosed", () => {
  assert.match(options, /id="recursive-hns-doh-url"/);
  assert.match(options, /placeholder="https:\/\/hnsdoh\.com\/dns-query"/);
  assert.doesNotMatch(options, /value="https:\/\/hnsdoh\.com\/dns-query"/);
  assert.match(options, /qnames and qtypes/);
  assert.match(options, /source IP/);
  assert.match(options, /sends nothing[\s\S]*field is blank/);
  assert.match(options, /requester-only/);
  assert.match(options, /DNSSEC and DANE[\s\S]*verified locally/);
  assert.match(optionsScript, /clear-recursive-hns-doh[\s\S]*value = ""/);
  assert.match(popup, /requester-only P2P DNS relay/);
  assert.match(popup, /explicit recursive HNS DoH recovery URL/);
});

test("latest main-frame security details precede the complete header-chain panel", () => {
  const latestMainFrame = popup.indexOf("<h2>Latest browser main frame</h2>");
  const headerChain = popup.indexOf("<h2>Header chain</h2>");
  const retry = popup.indexOf('id="retry"');
  const recoveryGuidance = popup.indexOf("Network intercepting port 53?");
  const syncHeaders = popup.indexOf('id="sync-headers"');

  assert.ok(latestMainFrame >= 0, "latest main-frame section");
  assert.ok(retry > latestMainFrame, "main-frame actions follow page status");
  assert.ok(recoveryGuidance > retry, "recovery guidance stays with page status");
  assert.ok(headerChain > recoveryGuidance, "header-chain section is the final panel");
  assert.ok(syncHeaders > headerChain, "header sync control stays inside the lower section");
});

test("popup security status is scoped to the active Chromium tab", () => {
  assert.match(popupScript, /chrome\.tabs\.query\(\{ active: true, currentWindow: true \}\)/);
  assert.match(
    popupScript,
    /type: "getStatus",[\s\S]*?tabId: await activeTabId\(\)/
  );
  assert.match(worker, /store\.receiptForTab\(validTabId, status\)/);
  assert.match(worker, /latestMainFrameSecurity: scoped\.receipt/);
  assert.match(
    worker,
    /latestMainFrameConnectDecisionReceipt: scoped\.connectDecisionReceipt/
  );
  assert.match(worker, /chrome\.storage\.session\.set/);
  assert.match(worker, /store\.completeMaintenance\(authoritativeStatus\)/);
  assert.match(
    worker,
    /store\.completeMaintenance\(authoritativeStatus\)[\s\S]*?await navigationGate\.open\(syncControlEpoch\)/
  );
  assert.doesNotMatch(
    worker,
    /headerSyncInProgress: true,[\s\S]{0,180}latestMainFrameSecurity: null/
  );
  assert.match(worker, /securityMaintenanceEpoch/);
  assert.match(
    worker,
    /captureCompletedMainFrame[\s\S]*?await refreshNativeStatus\(\)[\s\S]*?store\.completeRequest\(details, status\)/
  );
  assert.match(popup, /id="security-receipt-source"/);
  assert.match(popupScript, /Chromium owns end-to-end WebPKI for this document/);
});

test("MeshMine selection changes clear stale display-only values before submission", () => {
  assert.match(popup, /id="pool-name"/);
  assert.match(popup, /id="pool-endpoint"/);
  assert.match(
    popupScript,
    /\["#pool-name", "#pool-endpoint"\][\s\S]*?addEventListener\("input", markPoolSelectionChanged\)/
  );
  assert.match(
    popupScript,
    /function markPoolSelectionChanged\(\) \{[\s\S]*?\+\+poolOperationGeneration;[\s\S]*?resetPoolStatsDisplay\("Selection pending \/ unverified"\)/
  );
  assert.match(
    popupScript,
    /const operationGeneration = \+\+poolOperationGeneration;[\s\S]*?await fetchPoolStats\(endpoint, expectedName\);[\s\S]*?if \(operationGeneration !== poolOperationGeneration\) return;/
  );
  assert.match(
    popupScript,
    /async function clearPoolStats\(\) \{[\s\S]*?await chrome\.storage\.local\.remove\([\s\S]*?input\.value = "";[\s\S]*?resetPoolStatsDisplay\(\);[\s\S]*?Could not clear the saved pool selection:/
  );
});

test("the unpacked Chromium build carries the generated dependency notices", () => {
  assert.match(
    buildScript,
    /extension\/THIRD_PARTY_NOTICES\.txt[\s\S]*output.*THIRD_PARTY_NOTICES\.txt/
  );
  assert.match(buildScript, /cpSync\("LICENSE", `\$\{output\}\/LICENSE`\)/);
  assert.match(
    buildScript,
    /docs\/privacy-policy\.md[\s\S]*output.*PRIVACY\.md/
  );
  assert.match(buildScript, /sourceRepository/);
  assert.match(buildScript, /github\.com\/sponsors\/denuoweb/);
});

test("first install opens the embedded Setup and Complete Uninstall flow", () => {
  assert.match(
    worker,
    /details\.reason === "install"[\s\S]*?chrome\.runtime\.getURL\("src\/setup\.html"\)/
  );
  assert.match(setup, /matching local Rust native/);
  assert.match(setup, /Shakescape Setup/);
  assert.match(setup, /contains Shakescape Setup version/);
  assert.match(setup, /non-system runtime dependencies/);
  assert.match(setup, /id="download-setup"[^>]*download/);
  assert.match(setup, /catalog extension IDs are built into/);
  assert.match(setup, /every browser you use/);
  assert.match(setup, /block 300,000/);
  assert.match(setup, /Complete Uninstall/);
  assert.match(setup, /id="complete-uninstall"/);
  assert.match(setup, /per-user local CA/);
  assert.match(setup, /handshake-rs\/hns-dane-browser-extension/);
  assert.match(setup, /legal\.html#license/);
  assert.match(setup, /legal\.html#privacy/);
  assert.match(setup, /legal\.html#agreement/);
  assert.match(setup, /legal\.html#notices/);
  assert.match(setup, /github\.com\/sponsors\/denuoweb/);
  assert.match(setup, /Donations do not unlock features/);
  assert.match(setup, /ChromeOS and mobile Chromium do not/);
  assert.match(setupScript, /\^\[a-p\]\{32\}\$/);
  assert.match(setupScript, /runtime\?\.getManifest\?\.\(\)/);
  assert.match(setupScript, /navigator\.clipboard\.writeText\(extensionId\)/);
  assert.match(setupScript, /runtime\.getPlatformInfo\(\)/);
  assert.match(setupScript, /runtime\.getURL\("installers\/index\.json"\)/);
  assert.match(setupScript, /selectEmbeddedInstaller/);
  assert.match(setupScript, /runtime\.getURL\(selection\.path\)/);
  assert.match(setup, /project self-signed Authenticode certificate/i);
  assert.match(setup, /RFC 3161[\s\S]*SHA-256 timestamp/);
  assert.match(setup, /not publicly trusted/);
  assert.match(setup, /Windows SmartScreen/);
  assert.match(setup, /Unknown Publisher/);
  assert.match(setup, /Archive SHA-256/);
  assert.match(setup, /Certificate SHA-256/);
  assert.match(setupScript, /selfSignedAuthenticodeAndTimestamped/);
  assert.match(setupScript, /certificateTrust !== "notPubliclyTrusted"/);
  assert.match(setupScript, /signerCertificateSha256/);
  const trustValidation = setupScript.indexOf(
    "validateWindowsInstallerTrust(index, selection)"
  );
  const downloadEnablement = setupScript.indexOf(
    'configureDownload("#download-setup"'
  );
  assert.ok(
    trustValidation >= 0 && trustValidation < downloadEnablement,
    "Windows trust metadata must validate before a download link is exposed"
  );
  assert.match(popup, /id="setup"/);
  assert.match(popup, /id="complete-uninstall"/);
  assert.match(popupScript, /openSetup\("complete-uninstall"\)/);
  assert.match(popupScript, /src\/setup\.html/);
});
