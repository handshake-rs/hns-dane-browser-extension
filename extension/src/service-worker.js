import {
  MAX_REQUEST_TIMEOUT_MS,
  NativeClient
} from "./native-client.js";
import {
  automaticHeaderSyncDueAt,
  headerSyncUrgentRetryWindow,
  needsAutomaticHeaderSync,
  nextAutomaticHeaderSyncAttemptAt,
  normalizedHeaderSyncUrgentRetryWindow
} from "./header-sync-schedule.js";
import {
  DEFAULT_POLICY,
  LEGACY_HNS_DOH_KEYS,
  migrateStoredSettings,
  normalizePolicy
} from "./policy.js";
import {
  NavigationReceiptStore,
  registerNavigationLifecycle
} from "./navigation-receipts.js";
import {
  NavigationGateController,
  validNavigationGateTarget
} from "./navigation-gate.js";
import {
  isProviderBridgeMessage,
  protocolError,
  providerErrorPayload,
  validatePageRequest,
  WALLET_NATIVE_ABI_VERSION
} from "./wallet-provider-protocol.js";
import { WalletProviderRouter } from "./wallet-provider-router.js";
import {
  projectWalletAbiStatus,
  unavailableWalletAbiStatus
} from "./wallet-status.js";
import {
  approvalStorageKey,
  validateApprovalDecision,
  validateApprovalId,
  validateApprovalPrompt
} from "./wallet-approval.js";
import {
  currentConnectSecurityDecision,
  currentSecurityResult
} from "./security-result.js";
import {
  inspectNativeComponent,
  nativeSetupPromptRequired
} from "./native-component.js";
import {
  authoritativeHeaderSync,
  currentHeaderSync,
  headerSyncRefreshError,
  headerSyncReadyForProxyActivation,
  validHeaderSyncEnvelope
} from "./header-status.js";
import {
  BLOCKING_PAC_SCRIPT,
  SerializedEpochMutationController,
  SerializedMandatoryPacController,
  headerReadinessFailClosed,
  installPacForCurrentNativeGeneration,
  runtimeControlToken,
  runtimeControlTokenIsCurrent,
  sameLiveProxyGeneration,
  settleLifecycleBarrier
} from "./proxy-lifecycle.js";

const NATIVE_HOST = "com.denuoweb.hns_dane_browser";
const EXTENSION_VERSION = chrome.runtime.getManifest().version;
const NATIVE_SETUP_PROMPTED_VERSION_KEY = "nativeSetupPromptedVersion";
const HEALTH_ALARM = "hns-runtime-health";
const RECONNECT_ALARM = "hns-runtime-reconnect";
const HEADER_SYNC_DEADLINE_ALARM = "hns-header-sync-deadline";
const HEADER_EVIDENCE_EXPIRY_ALARM = "hns-header-evidence-expiry";
// Chrome alarms and MV3 worker wakeups are not real-time. Close the
// synchronous navigation gate well before Rust's authenticated evidence hard
// deadline so a delayed callback cannot expose native rejection pages.
const HEADER_EVIDENCE_GATE_LEAD_MS = 30 * 1000;
const NAVIGATION_GATE_BOOTSTRAP_TARGET_TTL_MS = 60 * 1000;
const LEGACY_HEADER_SYNC_ALARM = "hns-header-sync";
const HEALTH_PERIOD_MINUTES = 5;
const HEADER_SYNC_LAST_ATTEMPT_KEY = "headerSyncLastAttemptAt";
const HEADER_SYNC_URGENT_RETRY_WINDOW_KEY =
  "headerSyncUrgentRetryWindow";
const NAVIGATION_RECEIPTS_STORAGE_KEY = "navigationSecurityReceipts";
const MAX_NATIVE_CONNECT_SECURITY_DECISIONS = 32;
const WALLET_APPROVAL_CLEANUP_ALARM = "wallet-approval-cleanup";
const WALLET_APPROVAL_STORAGE_PREFIX = "walletApproval:";
const MAX_PENDING_WALLET_APPROVALS = 8;
const MAX_PENDING_WALLET_APPROVALS_PER_ORIGIN = 2;
const RECOVERABLE_PROXY_NAVIGATION_ERRORS = new Set([
  "net::ERR_FAILED",
  "net::ERR_PROXY_CONNECTION_FAILED",
  "net::ERR_TUNNEL_CONNECTION_FAILED"
]);
const client = new NativeClient(chrome, NATIVE_HOST);
const walletProviderRouter = new WalletProviderRouter({
  nativeRequest: walletProviderNativeRequest,
  authorityForSender: walletProviderAuthority,
  deliverEvent: deliverWalletProviderEvent
});
let controlEpoch = 0;
const navigationGateBootstrapTargets = new Map();
const admittedMainFrameNavigations = new Map();
const navigationGate = new NavigationGateController({
  updateDynamicRules: (update) =>
    chromeCall(
      chrome.declarativeNetRequest.updateDynamicRules,
      chrome.declarativeNetRequest,
      update
    ),
  updateSessionRules: (update) =>
    chromeCall(
      chrome.declarativeNetRequest.updateSessionRules,
      chrome.declarativeNetRequest,
      update
    ),
  waitPageUrl: chrome.runtime.getURL("src/proxy-wait.html"),
  isCurrent: (expectedControlEpoch) => expectedControlEpoch === controlEpoch,
  runtimeReady: (status, nowUnixSeconds) =>
    status?.state === "active" &&
    status?.proxyActive === true &&
    credentials != null &&
    client.currentConnectionEpoch() != null &&
    headerSyncReadyForNavigationGate(
      status?.headerSync,
      nowUnixSeconds * 1000
    )
});
const pacController = new SerializedMandatoryPacController(
  (pacScript) => setMandatoryPac(pacScript),
  () => readMandatoryPacScript(),
  (expectedControlEpoch) => expectedControlEpoch === controlEpoch
);
const alarmMutations = new SerializedEpochMutationController(
  (expectedControlEpoch) => expectedControlEpoch === controlEpoch
);

let runtimeLifecyclePending = 0;
let recoveryOperation = null;
let headerSyncOperation = null;
let headerMaintenanceOperation = null;
let nativeDisconnectCleanupOperation = null;
let proxyNavigationRecoveryOperation = null;
let lastHeaderSyncAttemptAt = null;
let lastHeaderSyncAttemptLoaded = false;
let retainedHeaderSyncUrgentRetryWindow = null;
let retainedHeaderSyncUrgentRetryWindowLoaded = false;
let navigationReceiptStore = null;
let navigationReceiptQueue = Promise.resolve();
let nativeSetupPromptedVersion = null;
const walletApprovalContexts = new Map();
const walletApprovalClaims = new Set();
const walletApprovalWindows = new Map();
let credentials = null;
let publicStatus = {
  state: "starting",
  reason: null,
  extensionVersion: EXTENSION_VERSION,
  nativeHostVersion: null,
  nativeComponentState: "checking",
  runtimeSession: null,
  runtimeGeneration: null,
  policyGeneration: 0,
  securityMaintenanceEpoch: null,
  caReady: false,
  proxyActive: false,
  headerSync: null,
  headerSyncInProgress: false,
  headerSyncError: null,
  walletAbi: unavailableWalletAbiStatus(),
  latestMainFrameSecurity: null,
  latestMainFrameSecurityUnavailableReason: null,
  recentConnectSecurityDecisions: []
};

client.onDisconnect((disconnectedConnectionEpoch) => {
  walletProviderRouter.forgetAll();
  void invalidateAllWalletApprovals("walletDisconnected");
  void handleNativeDisconnect(disconnectedConnectionEpoch);
});

client.onEvent((event) => {
  if (event?.type !== "walletProviderEvent") return;
  void walletProviderRouter.deliverNativeEvent(event).catch(() => {});
});

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    void chrome.tabs.create({
      url: chrome.runtime.getURL("src/setup.html")
    });
  }
  void migrateAndRecover();
});

chrome.runtime.onStartup.addListener(() => {
  void recover();
});

chrome.runtime.onSuspend.addListener(() => {
  // Keep the PAC and its native port as one generation. A suspend callback
  // cannot wait for confirmed proxy removal, so tearing down the port here
  // can strand Chromium on a PAC whose listener has already disappeared.
});

chrome.runtime.onSuspendCanceled.addListener(() => {
  // No teardown was started by onSuspend, so the live generation remains
  // authoritative when Chromium cancels suspension.
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HEALTH_ALARM) {
    void enforceHeaderEvidenceExpiry()
      .then((expired) => {
        if (!expired) return maintainHeaderFreshness(true);
        return publicStatus;
      })
      .catch(() => {});
  } else if (alarm.name === RECONNECT_ALARM) {
    void recover();
  } else if (alarm.name === HEADER_SYNC_DEADLINE_ALARM) {
    void maintainHeaderFreshness(true).catch(() => {});
  } else if (alarm.name === HEADER_EVIDENCE_EXPIRY_ALARM) {
    // This path is deliberately independent from headerMaintenanceOperation
    // and headerSyncOperation so a hung native sync cannot outlive evidence.
    void enforceHeaderEvidenceExpiry().catch(() => {});
  } else if (alarm.name === WALLET_APPROVAL_CLEANUP_ALARM) {
    void cleanupWalletApprovals().catch(() => {});
  }
});

chrome.windows.onRemoved.addListener((windowId) => {
  const approvalId = walletApprovalWindows.get(windowId);
  if (approvalId) void rejectClosedWalletApproval(approvalId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !message || typeof message.type !== "string") {
    return false;
  }
  if (isProviderBridgeMessage(message)) {
    void handleWalletProviderMessage(message, sender)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) =>
        sendResponse({ ok: false, error: providerErrorPayload(error) })
      );
    return true;
  }
  void handleUiMessage(message, sender)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) =>
      sendResponse({ ok: false, error: error instanceof Error ? error.message : String(error) })
    );
  return true;
});

chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    const challenger = details.challenger;
    if (
      details.isProxy === true &&
      credentials &&
      challenger &&
      challenger.host === "127.0.0.1" &&
      challenger.port === credentials.port
    ) {
      callback({
        authCredentials: {
          username: credentials.username,
          password: credentials.password
        }
      });
      return;
    }
    callback({});
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);

registerNavigationLifecycle(chrome, {
  beforeRequest(details) {
    const gateTarget = validNavigationGateRequest(details);
    if (gateTarget) {
      const candidate = {
        requestId: details.requestId,
        tabId: details.tabId,
        target: gateTarget,
        capturedAtUnixMs: Date.now()
      };
      if (navigationGate.logicallyOpen(publicStatus)) {
        navigationGateBootstrapTargets.delete(details.tabId);
        admittedMainFrameNavigations.set(details.requestId, candidate);
      } else {
        // An enabled static rule normally performs this transfer. Repeating it
        // from the request event also catches a session allow left behind by
        // worker suspension or OS sleep before asynchronous startup can close
        // that rule.
        rememberNavigationGateBootstrapTarget(candidate);
        void transferMainFrameNavigation(candidate).catch(() => {});
      }
    }
    const statusAtRequest = publicStatus;
    void withNavigationReceiptStore((store) =>
      store.beginRequest(details, statusAtRequest)
    );
  },
  beforeRedirect(details) {
    const admitted = admittedMainFrameNavigations.get(details.requestId);
    const redirectedTarget = validNavigationGateTarget(details.redirectUrl);
    if (admitted && redirectedTarget) {
      admitted.target = redirectedTarget;
    }
    void withNavigationReceiptStore((store) => store.redirectRequest(details));
  },
  completed(details) {
    admittedMainFrameNavigations.delete(details.requestId);
    void captureCompletedMainFrame(details);
  },
  requestError(details) {
    const admitted = admittedMainFrameNavigations.get(details.requestId);
    const recoverableProxyError = normalizedProxyNavigationError(details.error);
    const failedTarget = validNavigationGateRequest(details);
    const failedCandidate =
      admitted ??
      (failedTarget == null
        ? null
        : {
            requestId: details.requestId,
            tabId: details.tabId,
            target: failedTarget,
            capturedAtUnixMs: Date.now()
          });
    if (failedCandidate && recoverableProxyError != null) {
      // A navigation can outlive an MV3 worker instance. Retain (or rebuild)
      // the exact failed GET so both this recovery and a concurrent lifecycle
      // close can move it off Chromium's raw proxy error page.
      admittedMainFrameNavigations.set(
        failedCandidate.requestId,
        failedCandidate
      );
      const failureControlEpoch = controlEpoch;
      const failureRuntimeControl = captureHeaderMaintenanceControl();
      void recoverProxyNavigationFailure(
        failedCandidate,
        failureControlEpoch,
        failureRuntimeControl
      ).catch(() => {});
    } else {
      admittedMainFrameNavigations.delete(details.requestId);
    }
    void withNavigationReceiptStore((store) => store.failRequest(details));
  },
  committed(details) {
    invalidateWalletProviderDocument(details, "navigationChanged");
    void withNavigationReceiptStore((store) =>
      store.commitDocument(
        details,
        Array.isArray(details.transitionQualifiers) &&
          details.transitionQualifiers.includes("forward_back")
          ? "historyDocumentReceiptUnavailable"
          : "mainFrameSecurityPending"
      )
    );
  },
  historyUpdated(details) {
    invalidateWalletProviderDocument(details, "navigationChanged");
    void withNavigationReceiptStore((store) => store.updateDocumentUrl(details))
      .then((updated) => {
        if (updated) return notifyWalletProviderBootstrap(details);
        return undefined;
      });
  },
  navigationError(details) {
    void withNavigationReceiptStore((store) => store.failNavigation(details));
  },
  tabRemoved(tabId) {
    walletProviderRouter.forgetTab(tabId);
    navigationGateBootstrapTargets.delete(tabId);
    forgetAdmittedMainFrameNavigations(tabId);
    void invalidateWalletApprovalsForTab(tabId, null, "tabClosed");
    void withNavigationReceiptStore((store) => store.removeTab(tabId));
  },
  tabReplaced(addedTabId, removedTabId) {
    walletProviderRouter.forgetTab(removedTabId);
    walletProviderRouter.forgetTab(addedTabId);
    navigationGateBootstrapTargets.delete(removedTabId);
    navigationGateBootstrapTargets.delete(addedTabId);
    forgetAdmittedMainFrameNavigations(removedTabId);
    forgetAdmittedMainFrameNavigations(addedTabId);
    void invalidateWalletApprovalsForTab(removedTabId, null, "tabReplaced");
    void withNavigationReceiptStore((store) =>
      store.replaceTab(addedTabId, removedTabId)
    );
  }
});

chrome.alarms.create(HEALTH_ALARM, { periodInMinutes: HEALTH_PERIOD_MINUTES });
chrome.alarms.create(WALLET_APPROVAL_CLEANUP_ALARM, { periodInMinutes: 1 });
void chrome.alarms.clear(LEGACY_HEADER_SYNC_ALARM);
void recover();

async function migrateAndRecover() {
  const stored = await storageGet(null);
  const migrated = migrateStoredSettings(stored);
  await storageSet({
    policy: migrated.policy,
    hnsPolicyMigration: migrated.migration
  });
  if (migrated.removedLegacyKeys.length > 0) {
    await storageRemove(migrated.removedLegacyKeys);
  }
  return recover();
}

function handleNativeDisconnect(disconnectedConnectionEpoch) {
  if (nativeDisconnectCleanupOperation) {
    return nativeDisconnectCleanupOperation;
  }
  const cleanupControlEpoch = beginControlGeneration();
  setStatus({
    state: "deactivating",
    reason: "nativeHostDisconnected",
    proxyActive: credentials != null,
    headerSyncInProgress: false,
    headerSyncError: "Native host disconnected",
    walletAbi: unavailableWalletAbiStatus("walletNativeHostDisconnected"),
    securityMaintenanceEpoch: null,
    latestMainFrameSecurity: null,
    latestMainFrameSecurityUnavailableReason: null,
    recentConnectSecurityDecisions: []
  });
  let restartAfterCleanup = false;
  let trackedCleanup;
  const cleanup = (async () => {
    // Persist recovery intent before changing the PAC. If the worker is
    // terminated during cleanup, a fresh worker will finish replacement.
    let gateCloseFailure = null;
    try {
      await closeNavigationGateAndTransfer(cleanupControlEpoch);
      requireControlGeneration(cleanupControlEpoch);
    } catch (error) {
      if (isSupersededControlError(error)) return publicStatus;
      gateCloseFailure = error;
      // The listener is already gone, so the PAC still has to become a fixed
      // blocker. Retry the independent gate closure once before that change;
      // a later recovery generation will keep retrying if Chromium's rules API
      // remains unavailable.
      try {
        await closeNavigationGateAndTransfer(cleanupControlEpoch);
        requireControlGeneration(cleanupControlEpoch);
        gateCloseFailure = null;
      } catch (retryError) {
        if (isSupersededControlError(retryError)) return publicStatus;
        gateCloseFailure = retryError;
      }
    }
    try {
      await createAlarmForControl(
        RECONNECT_ALARM,
        { delayInMinutes: 1 },
        cleanupControlEpoch
      );
    } catch (error) {
      if (isSupersededControlError(error)) return publicStatus;
    }
    let failure = gateCloseFailure
      ? new Error(
          `native host disconnected and the navigation gate could not be confirmed closed: ${boundedError(gateCloseFailure)}`
        )
      : new Error("Native host disconnected");
    try {
      // Replace the now-dead live PAC with a fixed mandatory blocker. There is
      // never an interval in which Chromium falls back to DIRECT.
      await installBlockingPac(cleanupControlEpoch);
      requireControlGeneration(cleanupControlEpoch);
      credentials = null;
    } catch (error) {
      if (isSupersededControlError(error)) return publicStatus;
      failure = new Error(
        `native host disconnected and the mandatory blocking PAC could not be installed: ${boundedError(error)}`
      );
      setStatus({
        state: "degraded",
        reason: "blockingPacInstallFailed",
        proxyActive: false,
        headerSyncInProgress: false,
        headerSyncError: boundedError(failure),
        securityMaintenanceEpoch: null,
        latestMainFrameSecurity: null,
        latestMainFrameSecurityUnavailableReason: null,
        recentConnectSecurityDecisions: []
      });
      try {
        await createAlarmForControl(
          RECONNECT_ALARM,
          { delayInMinutes: 1 },
          cleanupControlEpoch
        );
      } catch {
        // A newer control generation now owns recovery scheduling.
      }
      return publicStatus;
    }
    setStatus({
      state: "degraded",
      reason:
        gateCloseFailure == null
          ? "nativeHostDisconnected"
          : "navigationGateCloseFailed",
      proxyActive: false,
      headerSyncInProgress: false,
      headerSyncError: boundedError(failure),
      securityMaintenanceEpoch: null,
      latestMainFrameSecurity: null,
      latestMainFrameSecurityUnavailableReason: null,
      recentConnectSecurityDecisions: []
    });
    await clearAlarmForControl(
      HEADER_SYNC_DEADLINE_ALARM,
      cleanupControlEpoch
    );
    await clearAlarmForControl(
      HEADER_EVIDENCE_EXPIRY_ALARM,
      cleanupControlEpoch
    );
    await createAlarmForControl(
      RECONNECT_ALARM,
      { delayInMinutes: 1 },
      cleanupControlEpoch
    );
    restartAfterCleanup =
      disconnectedConnectionEpoch != null &&
      cleanupControlEpoch === controlEpoch;
    return publicStatus;
  })();
  trackedCleanup = cleanup.finally(() => {
    if (nativeDisconnectCleanupOperation === trackedCleanup) {
      nativeDisconnectCleanupOperation = null;
    }
    if (restartAfterCleanup) void recover();
  });
  nativeDisconnectCleanupOperation = trackedCleanup;
  return trackedCleanup;
}

function recover() {
  if (recoveryOperation) return recoveryOperation;
  if (headerMaintenanceRuntimeAvailable() && headerReadinessFailClosed(publicStatus)) {
    recoveryOperation = maintainHeaderFreshness(true)
      .catch((error) => {
        if (headerReadinessFailClosed(publicStatus)) {
          setStatus({
            headerSyncInProgress: false,
            headerSyncError: boundedError(error)
          });
          void createAlarmForControl(
            RECONNECT_ALARM,
            { delayInMinutes: 1 },
            controlEpoch
          ).catch(() => {});
        }
        return publicStatus;
      })
      .finally(() => {
        recoveryOperation = null;
      });
    return recoveryOperation;
  }
  recoveryOperation = enqueueRuntimeLifecycle(() =>
    startRuntime().catch((error) => {
        if (isSupersededControlError(error)) return publicStatus;
        if (error?.code === "navigationGateTransitionFailed") {
          return publicStatus;
        }
        if (
          error?.code === "nativeComponentUpdateRequired" ||
          error?.code === "nativeComponentIncompatible"
        ) {
          return publicStatus;
        }
        setStatus({
          state: publicStatus.state === "blocked" ? "blocked" : "degraded",
          reason: error instanceof Error ? error.message : String(error),
          headerSyncInProgress: false,
          headerSyncError: "Native runtime startup failed",
          securityMaintenanceEpoch: null,
          latestMainFrameSecurity: null,
          latestMainFrameSecurityUnavailableReason: null,
          recentConnectSecurityDecisions: []
        });
        if (publicStatus.state !== "blocked") {
          void createAlarmForControl(
            RECONNECT_ALARM,
            { delayInMinutes: 1 },
            controlEpoch
          ).catch(() => {});
        }
        return publicStatus;
      })
  ).finally(() => {
    recoveryOperation = null;
  });
  return recoveryOperation;
}

function enqueueRuntimeLifecycle(operation) {
  runtimeLifecyclePending += 1;
  const disconnectCleanupAtEnqueue = nativeDisconnectCleanupOperation;
  const result = settleLifecycleBarrier(
    disconnectCleanupAtEnqueue
  ).then(() => {
    // Long native work is deliberately not serialized. A newer start changes
    // controlEpoch, installs the blocker, and disconnects captured A so a
    // pending 15-minute sync rejects promptly. PAC mutations serialize inside
    // SerializedMandatoryPacController.
    return operation();
  });
  return result.finally(() => {
    runtimeLifecyclePending -= 1;
  });
}

async function startRuntime(policyOverride) {
  const priorStatus = publicStatus;
  const priorCredentials = credentials;
  const startControlEpoch = beginControlGeneration();
  const replacedConnectionEpoch = client.currentConnectionEpoch();
  let activationConnectionEpoch = null;
  let activationStatus = null;
  let blockerConfirmed = false;
  let livePacConfirmed = false;
  let navigationGateClosed = false;
  let replacedConnectionDisconnected = false;
  let nativeHelloAttempted = false;
  let nativeHelloReceived = false;
  setStatus({
    state: "starting",
    reason: null,
    extensionVersion: EXTENSION_VERSION,
    nativeHostVersion: null,
    nativeComponentState: "checking",
    proxyActive:
      priorStatus.proxyActive === true && priorCredentials != null,
    headerSyncInProgress: false,
    headerSyncError: null,
    walletAbi: unavailableWalletAbiStatus("walletStatusChecking"),
    latestMainFrameSecurity: null,
    latestMainFrameSecurityUnavailableReason: null,
    recentConnectSecurityDecisions: []
  });
  try {
    // Close the synchronous main-frame gate before selecting a PAC whose
    // listener is deliberately unavailable during replacement.
    await closeNavigationGateAndTransfer(startControlEpoch);
    requireControlGeneration(startControlEpoch);
    navigationGateClosed = true;
    // A replacement always transitions live PAC -> mandatory blocker before
    // disconnecting the captured old native connection. DIRECT is never used.
    await installBlockingPac(startControlEpoch);
    requireControlGeneration(startControlEpoch);
    blockerConfirmed = true;
    credentials = null;
    setStatus({
      state: "starting",
      reason: null,
      proxyActive: false,
      headerSync: null,
      headerSyncInProgress: false,
      headerSyncError: null,
      securityMaintenanceEpoch: null
    });
    if (replacedConnectionEpoch != null) {
      replacedConnectionDisconnected =
        client.disconnectIfCurrent(replacedConnectionEpoch);
    }
    await clearAlarmForControl(
      HEADER_SYNC_DEADLINE_ALARM,
      startControlEpoch
    );
    await clearAlarmForControl(
      HEADER_EVIDENCE_EXPIRY_ALARM,
      startControlEpoch
    );
    const stored = await storageGet(["policy"]);
    requireControlGeneration(startControlEpoch);
    const policy = normalizePolicy(
      policyOverride ?? stored.policy ?? DEFAULT_POLICY
    );
    nativeHelloAttempted = true;
    const hello = await client.request("hello");
    nativeHelloReceived = true;
    requireControlGeneration(startControlEpoch);
    activationConnectionEpoch = client.currentConnectionEpoch();
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    const nativeComponent = inspectNativeComponent(hello, EXTENSION_VERSION);
    setStatus({
      extensionVersion: nativeComponent.extensionVersion,
      nativeHostVersion: nativeComponent.nativeHostVersion,
      nativeComponentState: nativeComponent.state,
      walletAbi: projectWalletAbiStatus(hello?.walletAbi)
    });
    if (nativeComponent.state !== "ready") {
      const failure = new Error(
        nativeComponent.state === "versionMismatch"
          ? `native component ${nativeComponent.nativeHostVersion} does not match extension ${EXTENSION_VERSION}`
          : `native component did not report a compatible version for extension ${EXTENSION_VERSION}`
      );
      failure.code =
        nativeComponent.state === "versionMismatch"
          ? "nativeComponentUpdateRequired"
          : "nativeComponentIncompatible";
      throw failure;
    }
    const result = await client.request("start", { policy });
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    validateStartResult(result);
    setStatus({ walletAbi: projectWalletAbiStatus(result.walletAbi) });

    if (result.ca.state !== "installed") {
      throw new Error("local CA installation is required before the HNS PAC can activate");
    }

    if (!headerSyncReadyForNavigationGate(result.headerSync)) {
      // Select the authenticated live listener before the potentially long
      // initial sync. Main-frame GET navigation remains on the extension wait
      // page until the independently corroborated tree root is ready.
      credentials = {
        port: result.proxy.port,
        username: result.proxy.username,
        password: result.proxy.password
      };
      blockerConfirmed = false;
      await installPacForCurrentNativeGeneration(
        () => installLivePac(result.pacScript, startControlEpoch),
        () =>
          runtimeControlIsCurrent(
            startControlEpoch,
            activationConnectionEpoch
          ),
        () => {
          setStatus({
            state: "degraded",
            reason: "headerReadinessUnavailable",
            proxyActive: true,
            runtimeSession: result.runtimeSession,
            runtimeGeneration: result.runtimeGeneration,
            policyGeneration: result.policyGeneration,
            securityMaintenanceEpoch: result.securityMaintenanceEpoch,
            caReady: true,
            headerSync: currentHeaderSync(result.headerSync),
            headerSyncInProgress: true,
            headerSyncError: null,
            walletAbi: projectWalletAbiStatus(result.walletAbi),
            recentConnectSecurityDecisions: []
          });
        }
      );
      livePacConfirmed = true;
    }

    activationStatus = await establishStartupHeaderReadiness(
      result,
      startControlEpoch,
      activationConnectionEpoch
    );
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    if (!headerSyncReadyForNavigationGate(activationStatus.headerSync)) {
      throw new Error(
        "validated header target evidence expired before PAC activation"
      );
    }

    if (!livePacConfirmed) {
      // Credentials must exist before the PAC becomes visible so an immediate
      // browser request cannot race the proxy authentication callback.
      credentials = {
        port: result.proxy.port,
        username: result.proxy.username,
        password: result.proxy.password
      };
      // Until this mutation is confirmed, either the blocker or B's live PAC
      // may be selected. A failure must re-confirm the blocker before B stops.
      blockerConfirmed = false;
      await installPacForCurrentNativeGeneration(
        () => installLivePac(result.pacScript, startControlEpoch),
        () =>
          runtimeControlIsCurrent(
            startControlEpoch,
            activationConnectionEpoch
          ),
        () => {
          if (!headerSyncReadyForNavigationGate(activationStatus.headerSync)) {
            throw new Error(
              "validated header target evidence expired during PAC activation"
            );
          }
        }
      );
      livePacConfirmed = true;
    }
    await navigationGate.open(startControlEpoch);
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    setStatus({
      state: "active",
      reason: null,
      proxyActive: true,
      runtimeSession: activationStatus.runtimeSession,
      runtimeGeneration: activationStatus.runtimeGeneration,
      policyGeneration: activationStatus.policyGeneration,
      securityMaintenanceEpoch:
        activationStatus.securityMaintenanceEpoch,
      caReady: true,
      headerSync: currentHeaderSync(activationStatus.headerSync),
      headerSyncInProgress: false,
      headerSyncError: null,
      walletAbi: projectWalletAbiStatus(activationStatus.walletAbi),
      latestMainFrameSecurity: null,
      latestMainFrameSecurityUnavailableReason: null,
      recentConnectSecurityDecisions: []
    });
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    await withNavigationReceiptStore((store) => store.ensureRuntime(publicStatus));
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    await clearRetainedHeaderSyncUrgentRetryWindow();
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    await scheduleHeaderSyncDeadline(
      publicStatus.headerSync,
      Date.now(),
      startControlEpoch
    );
    await clearAlarmForControl(RECONNECT_ALARM, startControlEpoch);
    requireRuntimeControl(
      startControlEpoch,
      activationConnectionEpoch
    );
    return publicStatus;
  } catch (error) {
    if (
      startControlEpoch !== controlEpoch ||
      isSupersededControlError(error)
    ) {
      throw supersededControlError();
    }
    let failure = error;
    if (!navigationGateClosed) {
      // No PAC or native-listener mutation has occurred. Keep the prior live
      // generation intact and, when it was ready, repair its allow rule before
      // a later recovery attempt retries the replacement.
      credentials = priorCredentials;
      let priorGateRestored = false;
      if (
        priorStatus.proxyActive === true &&
        priorCredentials != null &&
        headerSyncReadyForNavigationGate(priorStatus.headerSync)
      ) {
        try {
          await navigationGate.open(startControlEpoch);
          requireControlGeneration(startControlEpoch);
          priorGateRestored = true;
        } catch (restoreError) {
          if (isSupersededControlError(restoreError)) {
            throw supersededControlError();
          }
          failure = new Error(
            `navigation gate could not be closed or restored: ${boundedError(restoreError)}`
          );
        }
      }
      setStatus(
        priorGateRestored
          ? {
              ...priorStatus,
              headerSyncError: `Runtime replacement postponed: ${boundedError(failure)}`
            }
          : {
              ...priorStatus,
              state: "degraded",
              reason: "navigationGateTransitionFailed",
              proxyActive:
                priorStatus.proxyActive === true && priorCredentials != null,
              headerSyncInProgress: false,
              headerSyncError: boundedError(failure)
            }
      );
      await createAlarmForControl(
        RECONNECT_ALARM,
        { delayInMinutes: 1 },
        startControlEpoch
      );
      failure.code = "navigationGateTransitionFailed";
      throw failure;
    }
    if (
      livePacConfirmed &&
      activationConnectionEpoch != null &&
      runtimeControlIsCurrent(
        startControlEpoch,
        activationConnectionEpoch
      ) &&
      credentials != null
    ) {
      // A live authenticated proxy remains useful when initial HNS header
      // synchronization fails or times out: ICANN requests can continue and
      // Rust keeps HNS resolution fail-closed. Retain this generation and let
      // the bounded retry scheduler restore header readiness.
      setStatus({
        state: "degraded",
        reason: "headerReadinessUnavailable",
        proxyActive: true,
        headerSyncInProgress: false,
        headerSyncError: boundedError(failure),
        latestMainFrameSecurity: null,
        latestMainFrameSecurityUnavailableReason: null,
        recentConnectSecurityDecisions: []
      });
      await clearAlarmForControl(
        HEADER_EVIDENCE_EXPIRY_ALARM,
        startControlEpoch
      );
      await createAlarmForControl(
        RECONNECT_ALARM,
        { delayInMinutes: 1 },
        startControlEpoch
      );
      return publicStatus;
    }
    if (!blockerConfirmed) {
      try {
        await installBlockingPac(startControlEpoch);
        requireControlGeneration(startControlEpoch);
        blockerConfirmed = true;
      } catch (blockingError) {
        if (isSupersededControlError(blockingError)) {
          throw supersededControlError();
        }
        failure = new Error(
          `could not confirm the mandatory blocking PAC: ${boundedError(blockingError)}`
        );
      }
    }
    if (!blockerConfirmed) {
      // The selected PAC is uncertain but still mandatory: it can only be the
      // previous live PAC, B's live PAC, or the fixed blocker. Keep the
      // corresponding native connection alive until a blocker is confirmed.
      if (!replacedConnectionDisconnected) {
        credentials = priorCredentials;
      }
      const retainedStatus = replacedConnectionDisconnected
        ? publicStatus
        : priorStatus;
      setStatus({
        ...retainedStatus,
        state: "degraded",
        reason: "blockingPacInstallFailed",
        proxyActive: credentials != null,
        headerSyncInProgress: false,
        headerSyncError: boundedError(failure)
      });
      await createAlarmForControl(
        RECONNECT_ALARM,
        { delayInMinutes: 1 },
        startControlEpoch
      );
      throw failure;
    }
    credentials = null;
    if (activationConnectionEpoch != null) {
      client.disconnectIfCurrent(activationConnectionEpoch);
    } else if (
      replacedConnectionEpoch != null &&
      !replacedConnectionDisconnected
    ) {
      client.disconnectIfCurrent(replacedConnectionEpoch);
    }
    const disconnectedWalletAbi = unavailableWalletAbiStatus(
      "walletNativeHostDisconnected"
    );
    const localCaRequired =
      failure instanceof Error &&
      failure.message.includes("local CA installation is required");
    const nativeComponentFailure =
      failure?.code === "nativeComponentUpdateRequired" ||
      failure?.code === "nativeComponentIncompatible";
    if (nativeComponentFailure) {
      const nativeComponentState =
        failure.code === "nativeComponentUpdateRequired"
          ? "versionMismatch"
          : "incompatible";
      setStatus({
        state: "blocked",
        reason: failure.code,
        extensionVersion: EXTENSION_VERSION,
        nativeComponentState,
        walletAbi: disconnectedWalletAbi,
        proxyActive: false,
        caReady: false,
        headerSync: null,
        headerSyncInProgress: false,
        headerSyncError: boundedError(failure),
        securityMaintenanceEpoch: null,
        latestMainFrameSecurity: null,
        latestMainFrameSecurityUnavailableReason: null,
        recentConnectSecurityDecisions: []
      });
      await promptForNativeSetupOnce();
    } else if (localCaRequired) {
      setStatus({
        state: "blocked",
        reason: "localCaRequired",
        proxyActive: false,
        caReady: false,
        walletAbi: disconnectedWalletAbi
      });
    } else {
      setStatus({
        state: "degraded",
        reason: boundedError(failure),
        nativeComponentState:
          nativeHelloAttempted && !nativeHelloReceived
            ? "unavailable"
            : publicStatus.nativeComponentState,
        proxyActive: false,
        walletAbi: disconnectedWalletAbi,
        headerSyncInProgress: false,
        headerSyncError: "Proxy activation requires current validated headers",
        securityMaintenanceEpoch: null,
        latestMainFrameSecurity: null,
        latestMainFrameSecurityUnavailableReason: null,
        recentConnectSecurityDecisions: []
      });
      await createAlarmForControl(
        RECONNECT_ALARM,
        { delayInMinutes: 1 },
        startControlEpoch
      );
    }
    throw failure;
  }
}

async function establishStartupHeaderReadiness(
  startResult,
  expectedControlEpoch,
  expectedConnectionEpoch
) {
  if (headerSyncReadyForNavigationGate(startResult.headerSync)) {
    return startResult;
  }

  setStatus({
    runtimeSession: startResult.runtimeSession,
    runtimeGeneration: startResult.runtimeGeneration,
    policyGeneration: startResult.policyGeneration,
    securityMaintenanceEpoch: startResult.securityMaintenanceEpoch,
    caReady: true,
    headerSync: currentHeaderSync(startResult.headerSync),
    headerSyncInProgress: true,
    headerSyncError: null,
    walletAbi: projectWalletAbiStatus(startResult.walletAbi)
  });
  await recordHeaderSyncAttempt(Date.now());
  requireRuntimeControl(
    expectedControlEpoch,
    expectedConnectionEpoch
  );
  const synchronized = await client.request(
    "syncOnce",
    {},
    { timeoutMs: MAX_REQUEST_TIMEOUT_MS }
  );
  requireRuntimeControl(
    expectedControlEpoch,
    expectedConnectionEpoch
  );
  const refreshError = headerSyncRefreshError(synchronized);
  if (refreshError) {
    throw new Error(refreshError);
  }
  if (!headerSyncReadyForNavigationGate(synchronized)) {
    throw new Error(
      "header synchronization did not establish current unexpired target evidence"
    );
  }

  const status = await client.request("status");
  requireRuntimeControl(
    expectedControlEpoch,
    expectedConnectionEpoch
  );
  validateStatusResult(status, startResult);
  if (!headerSyncReadyForNavigationGate(status.headerSync)) {
    throw new Error(
      "native status did not retain current unexpired target evidence"
    );
  }
  return status;
}

async function handleUiMessage(message, sender) {
  switch (message.type) {
    case "getStatus": {
      const status = await refreshNativeStatus();
      return statusForTab(status, message.tabId);
    }
    case "navigationGateStatus":
      return navigationGate.status(publicStatus);
    case "navigationGateBootstrap":
      return navigationGateBootstrapTarget(sender?.tab?.id);
    case "restart":
      // An explicit restart preempts a long-running header sync: startRuntime
      // first confirms the blocker, then disconnects only captured A.
      return enqueueRuntimeLifecycle(() => startRuntime());
    case "syncHeadersNow": {
      const status = await synchronizeHeaders();
      return statusForTab(status, message.tabId);
    }
    case "setPolicy": {
      const policy = normalizePolicy(message.policy);
      return enqueueRuntimeLifecycle(async () => {
        const result = await startRuntime(policy);
        await storageSet({ policy });
        return result;
      });
    }
    case "diagnostics":
      return client.request("diagnostics");
    case "walletApprovalGet":
      return walletApprovalGet(message.approvalId);
    case "walletApprovalDecision":
      return walletApprovalDecision(message.approvalId, message.decision);
    default:
      throw new Error("unsupported extension message");
  }
}

async function navigationGateBootstrapTarget(tabId) {
  if (!Number.isSafeInteger(tabId) || tabId < 0) {
    return { target: null };
  }
  const candidate = navigationGateBootstrapTargets.get(tabId);
  const age = Date.now() - candidate?.capturedAtUnixMs;
  if (
    !candidate ||
    candidate.tabId !== tabId ||
    !Number.isSafeInteger(candidate.capturedAtUnixMs) ||
    !Number.isSafeInteger(age) ||
    age < 0 ||
    age > NAVIGATION_GATE_BOOTSTRAP_TARGET_TTL_MS
  ) {
    navigationGateBootstrapTargets.delete(tabId);
    return { target: null };
  }
  navigationGateBootstrapTargets.delete(tabId);
  return { target: validNavigationGateTarget(candidate.target) };
}

function rememberNavigationGateBootstrapTarget(candidate) {
  navigationGateBootstrapTargets.set(candidate.tabId, candidate);
  setTimeout(() => {
    if (navigationGateBootstrapTargets.get(candidate.tabId) === candidate) {
      navigationGateBootstrapTargets.delete(candidate.tabId);
    }
  }, NAVIGATION_GATE_BOOTSTRAP_TARGET_TTL_MS);
}

function validNavigationGateRequest(details) {
  if (
    details?.type !== "main_frame" ||
    details?.method !== "GET" ||
    !Number.isSafeInteger(details?.tabId) ||
    details.tabId < 0
  ) {
    return null;
  }
  return validNavigationGateTarget(details.url);
}

function forgetAdmittedMainFrameNavigations(tabId) {
  for (const [requestId, candidate] of admittedMainFrameNavigations) {
    if (candidate.tabId === tabId) {
      admittedMainFrameNavigations.delete(requestId);
    }
  }
}

async function transferMainFrameNavigation(candidate) {
  const target = validNavigationGateTarget(candidate?.target);
  if (
    target == null ||
    !Number.isSafeInteger(candidate?.tabId) ||
    candidate.tabId < 0
  ) {
    throw new Error("main-frame navigation transfer target is invalid");
  }
  await chromeCall(
    chrome.tabs.update,
    chrome.tabs,
    candidate.tabId,
    {
      url: `${chrome.runtime.getURL("src/proxy-wait.html")}#${target}`
    }
  );
  if (navigationGateBootstrapTargets.get(candidate.tabId) === candidate) {
    navigationGateBootstrapTargets.delete(candidate.tabId);
  }
  if (typeof candidate.requestId === "string") {
    admittedMainFrameNavigations.delete(candidate.requestId);
  }
}

async function transferAdmittedMainFrameNavigations() {
  const pending = [...admittedMainFrameNavigations.values()];
  let firstFailure = null;
  for (const candidate of pending) {
    try {
      await transferMainFrameNavigation(candidate);
    } catch (error) {
      if (!admittedMainFrameNavigations.has(candidate.requestId)) {
        continue;
      }
      firstFailure ??= new Error(
        `could not move an admitted main-frame GET to the waiting page: ${boundedError(error)}`
      );
    }
  }
  if (firstFailure) throw firstFailure;
}

async function closeNavigationGateAndTransfer(expectedControlEpoch) {
  let closeFailure = null;
  try {
    await navigationGate.close(expectedControlEpoch);
  } catch (error) {
    closeFailure = error;
  }
  let transferFailure = null;
  try {
    // Moving a GET to an extension page is safe even if a newer lifecycle
    // superseded this close: an already-open newer gate simply resumes it.
    // Always make the attempt, including after a physical allow removal whose
    // dynamic-rule repair or generation check failed.
    await transferAdmittedMainFrameNavigations();
  } catch (error) {
    transferFailure = error;
  }
  if (closeFailure) throw closeFailure;
  requireControlGeneration(expectedControlEpoch);
  if (transferFailure) throw transferFailure;
}

function normalizedProxyNavigationError(error) {
  if (typeof error !== "string") return null;
  const normalized = error.startsWith("net::") ? error : `net::${error}`;
  return RECOVERABLE_PROXY_NAVIGATION_ERRORS.has(normalized)
    ? normalized
    : null;
}

async function recoverProxyNavigationFailure(
  candidate,
  failureControlEpoch,
  failureRuntimeControl
) {
  // Transfer first and without an epoch precondition. Native disconnect is a
  // common companion to a tunnel error and may advance controlEpoch before a
  // generation-bound health decision can run.
  await transferMainFrameNavigation(candidate);
  if (failureControlEpoch !== controlEpoch) return publicStatus;

  if (
    proxyNavigationRecoveryOperation?.controlEpoch ===
    failureControlEpoch
  ) {
    return proxyNavigationRecoveryOperation.promise;
  }

  const operation = (async () => {
    requireControlGeneration(failureControlEpoch);
    if (failureRuntimeControl != null) {
      requireHeaderMaintenanceControl(failureRuntimeControl);
      // An isolated origin can legitimately reject CONNECT. Revalidate the
      // current native generation without rotating the gate revision or
      // restarting a healthy runtime. A not-ready native response takes the
      // normal fail-closed deactivation path inside refreshNativeStatus.
      return refreshNativeStatus();
    }
    if (headerMaintenanceRuntimeAvailable()) {
      // The same lifecycle became ready after the failure was observed. The
      // waiting page can resume against it without an old error restarting it.
      return publicStatus;
    }
    return recover();
  })();
  let tracked;
  tracked = operation.finally(() => {
    if (proxyNavigationRecoveryOperation?.promise === tracked) {
      proxyNavigationRecoveryOperation = null;
    }
  });
  proxyNavigationRecoveryOperation = {
    controlEpoch: failureControlEpoch,
    promise: tracked
  };
  return tracked;
}

async function handleWalletProviderMessage(message, sender) {
  if (message.type === "walletProviderInitialize") {
    const initialized = await walletProviderRouter.initialize(message, sender);
    await chromeCall(
      chrome.scripting.executeScript,
      chrome.scripting,
      {
        target: {
          tabId: sender.tab.id,
          documentIds: [sender.documentId]
        },
        files: ["src/provider-inpage.js"],
        world: "MAIN",
        injectImmediately: true
      }
    );
    return initialized;
  }
  if (message.type === "walletProviderRequest") {
    const result = await walletProviderRouter.request(message, sender);
    return registerWalletApproval(result, message, sender);
  }
  throw protocolError("unsupportedMessage", "unsupported wallet provider bridge message");
}

async function registerWalletApproval(result, message, sender) {
  if (!result || typeof result !== "object" || !result.approvalRequired) {
    return result;
  }
  const request = validatePageRequest(message.request);
  const approval = validateApprovalPrompt(
    result.approvalRequired,
    message.binding,
    request
  );
  if (
    walletApprovalContexts.size >= MAX_PENDING_WALLET_APPROVALS ||
    [...walletApprovalContexts.values()].filter(
      (context) => context.prompt.origin === approval.origin
    ).length >= MAX_PENDING_WALLET_APPROVALS_PER_ORIGIN
  ) {
    throw protocolError("rateLimited", "too many wallet approvals are pending");
  }
  const storageKey = approvalStorageKey(approval.approvalId);
  if (walletApprovalContexts.has(approval.approvalId)) {
    throw protocolError("invalidApproval", "wallet approval identifier was reused");
  }
  const existing = await chromeCall(
    chrome.storage.session.get,
    chrome.storage.session,
    storageKey
  );
  if (existing?.[storageKey]) {
    throw protocolError("invalidApproval", "wallet approval identifier was reused");
  }
  let resolveRequest;
  let rejectRequest;
  const completion = new Promise((resolve, reject) => {
    resolveRequest = resolve;
    rejectRequest = reject;
  });
  const context = {
    prompt: approval,
    request,
    binding: message.binding,
    sender: publicWalletProviderSender(sender),
    resolveRequest,
    rejectRequest,
    windowId: null
  };
  walletApprovalContexts.set(approval.approvalId, context);
  try {
    await chromeCall(
      chrome.storage.session.set,
      chrome.storage.session,
      { [storageKey]: approval }
    );
    const approvalWindow = await chromeCall(
      chrome.windows.create,
      chrome.windows,
      {
        url: chrome.runtime.getURL(
          `src/wallet-approval.html?id=${encodeURIComponent(approval.approvalId)}`
        ),
        type: "popup",
        width: 460,
        height: 650,
        focused: true
      }
    );
    if (Number.isSafeInteger(approvalWindow?.id)) {
      context.windowId = approvalWindow.id;
      walletApprovalWindows.set(approvalWindow.id, approval.approvalId);
    }
  } catch (error) {
    walletApprovalContexts.delete(approval.approvalId);
    await chromeCall(
      chrome.storage.session.remove,
      chrome.storage.session,
      storageKey
    );
    throw error;
  }
  return completion;
}

async function walletApprovalGet(rawApprovalId) {
  const approvalId = validateApprovalId(rawApprovalId);
  const context = walletApprovalContexts.get(approvalId);
  const storageKey = approvalStorageKey(approvalId);
  const stored = await chromeCall(
    chrome.storage.session.get,
    chrome.storage.session,
    storageKey
  );
  const approval = stored?.[storageKey];
  if (
    !context ||
    !approval ||
    approval.approvalId !== context.prompt.approvalId ||
    approval.origin !== context.prompt.origin ||
    approval.method !== context.prompt.method ||
    approval.expiresAtUnixMs !== context.prompt.expiresAtUnixMs ||
    approval.expiresAtUnixMs <= Date.now()
  ) {
    if (context) expireWalletApproval(approvalId, "approvalExpired");
    await chromeCall(
      chrome.storage.session.remove,
      chrome.storage.session,
      storageKey
    );
    return null;
  }
  return context.prompt;
}

async function walletApprovalDecision(rawApprovalId, rawDecision) {
  const approvalId = validateApprovalId(rawApprovalId);
  const decision = validateApprovalDecision(rawDecision);
  if (walletApprovalClaims.has(approvalId)) {
    throw protocolError("approvalConsumed", "wallet approval is already being decided");
  }
  walletApprovalClaims.add(approvalId);
  let context = null;
  try {
    const approval = await walletApprovalGet(approvalId);
    if (!approval) {
      throw protocolError("approvalExpired", "wallet approval is unavailable or expired");
    }
    context = walletApprovalContexts.get(approvalId);
    consumeWalletApprovalContext(approvalId);
    await chromeCall(
      chrome.storage.session.remove,
      chrome.storage.session,
      approvalStorageKey(approvalId)
    );
    const dispatch = await walletProviderRouter.revalidateApproval(context);
    const result = await walletProviderNativeRequest(
      "walletProviderApprovalDecision",
      {
        providerAbiVersion: WALLET_NATIVE_ABI_VERSION,
        approvalId,
        decision,
        authority: dispatch.authority,
        request: context.request
      }
    );
    const publicResult = await walletProviderRouter.completeApproval(
      dispatch,
      result
    );
    if (decision === "approve") {
      context.resolveRequest(publicResult);
    } else {
      context.rejectRequest(protocolError("userRejected", "wallet request was rejected"));
    }
    return { completed: true, decision };
  } catch (error) {
    context?.rejectRequest(error);
    throw error;
  } finally {
    walletApprovalClaims.delete(approvalId);
  }
}

function consumeWalletApprovalContext(approvalId) {
  const context = walletApprovalContexts.get(approvalId) ?? null;
  walletApprovalContexts.delete(approvalId);
  if (Number.isSafeInteger(context?.windowId)) {
    walletApprovalWindows.delete(context.windowId);
  }
  return context;
}

function expireWalletApproval(approvalId, code) {
  const context = consumeWalletApprovalContext(approvalId);
  context?.rejectRequest(
    protocolError(code, "wallet approval is unavailable or no longer current")
  );
}

async function rejectClosedWalletApproval(approvalId) {
  if (walletApprovalClaims.has(approvalId)) return;
  const context = consumeWalletApprovalContext(approvalId);
  if (!context) return;
  await chromeCall(
    chrome.storage.session.remove,
    chrome.storage.session,
    approvalStorageKey(approvalId)
  ).catch(() => {});
  context.rejectRequest(protocolError("userRejected", "wallet approval window was closed"));
  try {
    const dispatch = await walletProviderRouter.revalidateApproval(context);
    await walletProviderNativeRequest("walletProviderApprovalDecision", {
      providerAbiVersion: WALLET_NATIVE_ABI_VERSION,
      approvalId,
      decision: "reject",
      authority: dispatch.authority,
      request: context.request
    });
  } catch {
    // A closed window cannot revive stale browser or wallet authority.
  }
}

async function cleanupWalletApprovals() {
  const now = Date.now();
  const removals = [];
  for (const [approvalId, context] of walletApprovalContexts) {
    if (context.prompt.expiresAtUnixMs <= now) {
      expireWalletApproval(approvalId, "approvalExpired");
      removals.push(approvalStorageKey(approvalId));
    }
  }
  const stored = await chromeCall(
    chrome.storage.session.get,
    chrome.storage.session,
    null
  );
  for (const key of Object.keys(stored ?? {})) {
    if (!key.startsWith(WALLET_APPROVAL_STORAGE_PREFIX)) continue;
    const approvalId = key.slice(WALLET_APPROVAL_STORAGE_PREFIX.length);
    if (!walletApprovalContexts.has(approvalId)) removals.push(key);
  }
  if (removals.length > 0) {
    await chromeCall(
      chrome.storage.session.remove,
      chrome.storage.session,
      [...new Set(removals)]
    );
  }
}

async function invalidateAllWalletApprovals(code) {
  const approvalIds = [...walletApprovalContexts.keys()];
  for (const approvalId of approvalIds) expireWalletApproval(approvalId, code);
  if (approvalIds.length > 0) {
    await chromeCall(
      chrome.storage.session.remove,
      chrome.storage.session,
      approvalIds.map(approvalStorageKey)
    ).catch(() => {});
  }
}

async function invalidateWalletApprovalsForTab(tabId, documentId, code) {
  const approvalIds = [];
  for (const [approvalId, context] of walletApprovalContexts) {
    if (
      context.sender.tab.id === tabId &&
      (documentId == null || context.sender.documentId === documentId)
    ) {
      approvalIds.push(approvalId);
    }
  }
  for (const approvalId of approvalIds) expireWalletApproval(approvalId, code);
  if (approvalIds.length > 0) {
    await chromeCall(
      chrome.storage.session.remove,
      chrome.storage.session,
      approvalIds.map(approvalStorageKey)
    ).catch(() => {});
  }
}

function publicWalletProviderSender(sender) {
  return Object.freeze({
    id: sender.id,
    origin: sender.origin,
    url: sender.url,
    frameId: sender.frameId,
    documentId: sender.documentId,
    tab: Object.freeze({ id: sender.tab.id })
  });
}

async function walletProviderAuthority(sender, origin) {
  const status = await refreshNativeStatus();
  const authority = await withNavigationReceiptStore(
    (store) =>
      store.providerAuthorityForDocument(
        sender.tab.id,
        sender.documentId,
        origin,
        status,
        sender.url
      ),
    false
  );
  if (!authority) {
    throw protocolError(
      "browserAuthorityDenied",
      "the browser trust layer did not approve this exact document origin"
    );
  }
  return authority;
}

async function walletProviderNativeRequest(command, fields) {
  try {
    return await client.request(command, fields);
  } catch (error) {
    if (command === "walletProviderCapabilities") {
      const unavailableCode = [
        "walletArtifactMissing",
        "walletArtifactPlatformUnsupported",
        "walletArtifactDirectoryUnsafe",
        "walletArtifactManifestUnsafe",
        "walletArtifactManifestSize",
        "walletArtifactManifestInvalid",
        "walletArtifactContractMismatch",
        "walletArtifactUnsafe",
        "walletArtifactSize",
        "walletArtifactDigestMismatch",
        "walletArtifactUnreadable",
        "walletArtifactAuthenticityUnavailable",
        "walletAbiVersionMismatch",
        "walletServiceTransportUnavailable",
        "providerAuthorityUnavailable"
      ].includes(error?.code)
        ? error.code
        : "walletUnavailable";
      throw protocolError(
        unavailableCode,
        "the independently released wallet ABI or browser-authority join is unavailable"
      );
    }
    const code = [
      "staleContext",
      "permissionGenerationChanged",
      "walletSessionChanged",
      "approvalExpired",
      "approvalConsumed"
    ].includes(error?.code)
      ? error.code
      : typeof error?.code === "string"
        ? `native:${error.code}`
        : "nativeUnavailable";
    throw protocolError(code, "the native wallet rejected the typed provider request");
  }
}

async function deliverWalletProviderEvent(sender, binding, event) {
  try {
    await chromeCall(
      chrome.tabs.sendMessage,
      chrome.tabs,
      sender.tab.id,
      {
        type: "walletProviderEvent",
        schemaVersion: 1,
        binding,
        event: event.event,
        payload: event.payload
      },
      { documentId: sender.documentId }
    );
  } catch {
    // The exact document can disappear between native completion and delivery.
  }
}

async function refreshNativeStatus(allowDuringHeaderSync = false) {
  if (!headerMaintenanceRuntimeAvailable()) return publicStatus;
  if (headerSyncOperation && !allowDuringHeaderSync) return publicStatus;
  const requestedRuntime = publicStatus;
  const requestedHeaderSyncOperation = headerSyncOperation;
  const requestedControlEpoch = controlEpoch;
  const requestedConnectionEpoch = client.currentConnectionEpoch();
  if (requestedConnectionEpoch == null) return publicStatus;
  const requestedRuntimeControl = runtimeControlToken(
    requestedControlEpoch,
    requestedConnectionEpoch,
    requestedRuntime
  );
  if (requestedRuntimeControl == null) return publicStatus;
  let validatedNativeStatus = false;
  let validatedNativeReady = null;
  let validatedNativeStatusPatch = null;
  try {
    const result = await client.request("status");
    if (
      requestedControlEpoch !== controlEpoch ||
      !client.connectionIsCurrent(requestedConnectionEpoch) ||
      !sameLiveProxyGeneration(requestedRuntime, publicStatus) ||
      requestedHeaderSyncOperation !== headerSyncOperation
    ) {
      return publicStatus;
    }
    validateStatusResult(result, requestedRuntime);
    const latestMainFrameSecurity = currentSecurityResult(
      result.latestMainFrameSecurity,
      result
    );
    const recentConnectSecurityDecisions =
      validatedConnectSecurityDecisions(result);
    const headerSync = currentHeaderSync(result.headerSync);
    const ready = headerSyncReadyForNavigationGate(headerSync);
    validatedNativeReady = ready;
    validatedNativeStatusPatch = {
      runtimeSession: result.runtimeSession,
      runtimeGeneration: result.runtimeGeneration,
      policyGeneration: result.policyGeneration,
      securityMaintenanceEpoch: result.securityMaintenanceEpoch,
      caReady: result.caReady === true,
      headerSync,
      headerSyncInProgress: false,
      headerSyncError:
        ready
          ? null
          : result.headerSync == null &&
              typeof result.headerSyncUnavailableReason === "string"
            ? "Validated header status unavailable"
            : "Validated header target evidence is unavailable or expired",
      latestMainFrameSecurity,
      latestMainFrameSecurityUnavailableReason:
        latestMainFrameSecurity == null &&
        typeof result.latestMainFrameSecurityUnavailableReason === "string"
          ? result.latestMainFrameSecurityUnavailableReason
          : null,
      walletAbi: projectWalletAbiStatus(result.walletAbi),
      recentConnectSecurityDecisions
    };
    validatedNativeStatus = true;
    if (!ready) {
      return await deactivateProxyForHeaderReadiness(
        new Error("validated header target evidence is unavailable or expired"),
        requestedRuntimeControl,
        validatedNativeStatusPatch
      );
    }
    if (allowDuringHeaderSync) {
      await closeNavigationGateAndTransfer(requestedControlEpoch);
    } else {
      await navigationGate.open(requestedControlEpoch);
    }
    requireRuntimeControl(
      requestedControlEpoch,
      requestedConnectionEpoch
    );
    setStatus({
      state: "active",
      reason: null,
      proxyActive: true,
      ...validatedNativeStatusPatch
    });
    if (ready) {
      await scheduleHeaderSyncDeadline(
        headerSync,
        Date.now(),
        requestedControlEpoch
      );
      await clearAlarmForControl(
        RECONNECT_ALARM,
        requestedControlEpoch
      );
    }
  } catch (error) {
    if (
      requestedControlEpoch !== controlEpoch ||
      !client.connectionIsCurrent(requestedConnectionEpoch) ||
      !sameLiveProxyGeneration(requestedRuntime, publicStatus) ||
      requestedHeaderSyncOperation !== headerSyncOperation
    ) {
      return publicStatus;
    }
    if (allowDuringHeaderSync) throw error;
    if (validatedNativeStatus) {
      // A validated native response is authoritative. A navigation-rule or
      // alarm failure after that response must never be mistaken for a status
      // timeout and must never restore an allow rule from stale public state.
      return await deactivateProxyForHeaderReadiness(
        new Error(
          `${
            validatedNativeReady
              ? "navigation gate could not publish validated readiness"
              : "validated header target evidence is unavailable or expired"
          }: ${boundedError(error)}`
        ),
        requestedRuntimeControl,
        validatedNativeStatusPatch ?? {}
      );
    }
    if (
      publicStatus.proxyActive === true &&
      credentials != null &&
      headerSyncReadyForNavigationGate(publicStatus.headerSync)
    ) {
      // A status timeout is not proof that the proxy listener died. Retain the
      // last authenticated generation until its independent hard deadline;
      // the NativeClient disconnect observer handles an actual dead process.
      await navigationGate.open(requestedControlEpoch);
      requireRuntimeControl(
        requestedControlEpoch,
        requestedConnectionEpoch
      );
      setStatus({
        state: "active",
        reason: null,
        headerSyncInProgress: false,
        headerSyncError: `Native runtime status unavailable: ${boundedError(error)}`
      });
      await scheduleHeaderSyncDeadline(
        publicStatus.headerSync,
        Date.now() + 60 * 1000,
        requestedControlEpoch
      );
      return publicStatus;
    }
    await deactivateProxyForHeaderReadiness(
      error,
      requestedRuntimeControl
    );
  }
  return publicStatus;
}

function maintainHeaderFreshness(refreshStatus) {
  if (headerMaintenanceOperation) return headerMaintenanceOperation;
  if (runtimeLifecyclePending > 0) return Promise.resolve(publicStatus);
  const maintenanceControl = captureHeaderMaintenanceControl();
  if (maintenanceControl == null) return Promise.resolve(publicStatus);
  headerMaintenanceOperation = (async () => {
    requireHeaderMaintenanceControl(maintenanceControl);
    let status = refreshStatus ? await refreshNativeStatus() : publicStatus;
    requireHeaderMaintenanceControl(maintenanceControl, status);
    requireHeaderMaintenanceControl(maintenanceControl);
    if (!headerSyncReadyForNavigationGate(status.headerSync)) {
      const readinessError = new Error(
        "validated header target evidence is unavailable or expired"
      );
      await deactivateProxyForHeaderReadiness(
        readinessError,
        maintenanceControl
      );
      requireHeaderMaintenanceControl(maintenanceControl);
      status = publicStatus;
    }
    if (
      headerSyncReadyForNavigationGate(status.headerSync) &&
      !needsAutomaticHeaderSync(status.headerSync)
    ) {
      await scheduleHeaderSyncDeadline(
        status.headerSync,
        Date.now(),
        maintenanceControl.controlEpoch
      );
      requireHeaderMaintenanceControl(maintenanceControl);
      await clearSupersededHeaderSyncUrgentRetryWindow(
        publicStatus.headerSync,
        maintenanceControl
      );
      requireHeaderMaintenanceControl(maintenanceControl);
      return publicStatus;
    }
    const lastAttemptAt = await loadLastHeaderSyncAttempt();
    requireHeaderMaintenanceControl(maintenanceControl);
    const retainedUrgentWindow =
      await loadRetainedHeaderSyncUrgentRetryWindow();
    requireHeaderMaintenanceControl(maintenanceControl);
    status = publicStatus;
    const now = Date.now();
    const allowedAt = nextAutomaticHeaderSyncAttemptAt(
      status.headerSync,
      lastAttemptAt,
      retainedUrgentWindow,
      now
    );
    if (allowedAt != null && allowedAt > now) {
      await scheduleHeaderSyncDeadline(
        status.headerSync,
        allowedAt,
        maintenanceControl.controlEpoch
      );
      requireHeaderMaintenanceControl(maintenanceControl);
      return publicStatus;
    }
    requireHeaderMaintenanceControl(maintenanceControl);
    return synchronizeHeaders();
  })().finally(() => {
    headerMaintenanceOperation = null;
  });
  return headerMaintenanceOperation;
}

function synchronizeHeaders() {
  if (headerSyncOperation) return headerSyncOperation;
  if (runtimeLifecyclePending > 0) {
    return Promise.reject(new Error("header sync is unavailable during runtime replacement"));
  }
  if (!headerMaintenanceRuntimeAvailable()) {
    return Promise.reject(new Error("header sync requires a live native runtime"));
  }

  const attemptedAgainstHeaderSync = publicStatus.headerSync;
  const syncRuntimeControl = captureHeaderMaintenanceControl();
  if (syncRuntimeControl == null) {
    return Promise.reject(new Error("header sync requires a connected native runtime"));
  }
  const syncControlEpoch = syncRuntimeControl.controlEpoch;
  let receiptMaintenanceStarted = false;
  let nativeSyncAttempted = false;
  walletProviderRouter.invalidateAuthority();
  void invalidateAllWalletApprovals("headerMaintenanceStarted");
  headerSyncOperation = (async () => {
    await closeNavigationGateAndTransfer(syncControlEpoch);
    requireHeaderMaintenanceControl(syncRuntimeControl);
    setStatus({
      headerSyncInProgress: true,
      headerSyncError: null
    });
    const maintenanceStarted = await withNavigationReceiptStore((store) =>
      store.beginMaintenance(publicStatus)
    );
    requireHeaderMaintenanceControl(syncRuntimeControl);
    if (!maintenanceStarted) {
      throw new Error("header maintenance could not invalidate navigation authority");
    }
    receiptMaintenanceStarted = true;
    await recordHeaderSyncAttempt(Date.now());
    requireHeaderMaintenanceControl(syncRuntimeControl);
    let syncError = null;
    try {
      nativeSyncAttempted = true;
      const result = await client.request(
        "syncOnce",
        {},
        { timeoutMs: MAX_REQUEST_TIMEOUT_MS }
      );
      requireHeaderMaintenanceControl(syncRuntimeControl);
      const refreshError = headerSyncRefreshError(result);
      if (refreshError) {
        throw new Error(refreshError);
      }
    } catch (error) {
      syncError = error;
    }

    requireHeaderMaintenanceControl(syncRuntimeControl);
    const authoritativeStatus = await refreshNativeStatus(true);
    requireHeaderMaintenanceControl(
      syncRuntimeControl,
      authoritativeStatus
    );
    requireHeaderMaintenanceControl(syncRuntimeControl);
    if (headerMaintenanceRuntimeAvailable(authoritativeStatus)) {
      const adopted = await withNavigationReceiptStore((store) =>
        store.completeMaintenance(authoritativeStatus)
      );
      requireHeaderMaintenanceControl(syncRuntimeControl);
      if (!adopted) {
        syncError ??= new Error(
          "native host returned an invalid security maintenance epoch"
        );
      } else if (headerSyncReadyForNavigationGate(authoritativeStatus.headerSync)) {
        await navigationGate.open(syncControlEpoch);
        requireHeaderMaintenanceControl(syncRuntimeControl);
      }
    } else {
      syncError ??= new Error(
        authoritativeStatus.reason ??
          "authoritative native status unavailable after header sync"
      );
    }
    if (syncError) {
      if (!headerMaintenanceRuntimeAvailable()) {
        throw syncError;
      }
      if (!headerSyncReadyForNavigationGate(publicStatus.headerSync)) {
        await deactivateProxyForHeaderReadiness(
          syncError,
          syncRuntimeControl
        );
        requireHeaderMaintenanceControl(syncRuntimeControl);
      }
      setStatus({
        headerSyncInProgress: false,
        headerSyncError: boundedError(syncError)
      });
      await scheduleHeaderSyncRetry(
        attemptedAgainstHeaderSync,
        syncRuntimeControl
      );
      requireHeaderMaintenanceControl(syncRuntimeControl);
      throw syncError;
    }
    if (!headerSyncReadyForNavigationGate(publicStatus.headerSync)) {
      const readinessError = new Error(
        "header synchronization did not establish current unexpired target evidence"
      );
      await deactivateProxyForHeaderReadiness(
        readinessError,
        syncRuntimeControl
      );
      requireHeaderMaintenanceControl(syncRuntimeControl);
      await scheduleHeaderSyncRetry(
        attemptedAgainstHeaderSync,
        syncRuntimeControl
      );
      requireHeaderMaintenanceControl(syncRuntimeControl);
      throw readinessError;
    }
    if (needsAutomaticHeaderSync(publicStatus.headerSync)) {
      const refreshError = new Error(
        "header synchronization did not refresh authenticated target evidence"
      );
      setStatus({
        headerSyncInProgress: false,
        headerSyncError: boundedError(refreshError)
      });
      await scheduleHeaderSyncRetry(
        attemptedAgainstHeaderSync,
        syncRuntimeControl
      );
      requireHeaderMaintenanceControl(syncRuntimeControl);
      throw refreshError;
    }
    await clearRetainedHeaderSyncUrgentRetryWindow();
    requireHeaderMaintenanceControl(syncRuntimeControl);
    await scheduleHeaderSyncDeadline(
      publicStatus.headerSync,
      Date.now(),
      syncControlEpoch
    );
    requireHeaderMaintenanceControl(syncRuntimeControl);
    await clearAlarmForControl(RECONNECT_ALARM, syncControlEpoch);
    requireHeaderMaintenanceControl(syncRuntimeControl);
    return publicStatus;
  })().catch(async (error) => {
    if (
      headerMaintenanceControlIsCurrent(syncRuntimeControl) &&
      headerSyncReadyForNavigationGate(publicStatus.headerSync) &&
      !nativeSyncAttempted
    ) {
      if (receiptMaintenanceStarted) {
        const restored = await withNavigationReceiptStore((store) =>
          store.completeMaintenance(publicStatus)
        );
        requireHeaderMaintenanceControl(syncRuntimeControl);
        if (!restored) throw error;
      }
      await navigationGate.open(syncControlEpoch);
      requireHeaderMaintenanceControl(syncRuntimeControl);
    }
    throw error;
  }).finally(() => {
    headerSyncOperation = null;
  });
  return headerSyncOperation;
}

async function deactivateProxyForHeaderReadiness(
  error,
  expectedRuntimeControl = captureHeaderMaintenanceControl(),
  statusPatch = {}
) {
  if (expectedRuntimeControl == null) return publicStatus;
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  const degradedControlEpoch = expectedRuntimeControl.controlEpoch;
  let gateCloseFailure = null;
  try {
    await closeNavigationGateAndTransfer(degradedControlEpoch);
  } catch (closeError) {
    if (isSupersededControlError(closeError)) throw closeError;
    gateCloseFailure = closeError;
    try {
      await closeNavigationGateAndTransfer(degradedControlEpoch);
      gateCloseFailure = null;
    } catch (retryError) {
      if (isSupersededControlError(retryError)) throw retryError;
      gateCloseFailure = retryError;
    }
  }
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  // Keep the live mandatory PAC and native listener. Rust independently
  // rejects stale header work, so degraded browsing remains genuinely
  // fail-closed instead of silently falling back to DIRECT/WebPKI.
  setStatus({
    ...statusPatch,
    state: "degraded",
    reason:
      gateCloseFailure == null
        ? "headerReadinessUnavailable"
        : "navigationGateCloseFailed",
    proxyActive: true,
    headerSyncInProgress: false,
    headerSyncError:
      gateCloseFailure == null
        ? boundedError(error)
        : `Navigation gate could not be confirmed closed: ${boundedError(gateCloseFailure)}; ${boundedError(error)}`,
    latestMainFrameSecurity: null,
    latestMainFrameSecurityUnavailableReason: null,
    recentConnectSecurityDecisions: []
  });
  await clearAlarmForControl(
    HEADER_EVIDENCE_EXPIRY_ALARM,
    degradedControlEpoch
  );
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  await scheduleHeaderSyncDeadline(
    publicStatus.headerSync,
    Date.now() + 60 * 1000,
    degradedControlEpoch
  );
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  await createAlarmForControl(
    RECONNECT_ALARM,
    { delayInMinutes: 1 },
    degradedControlEpoch
  );
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  return publicStatus;
}

async function enforceHeaderEvidenceExpiry() {
  if (
    publicStatus.state !== "active" ||
    publicStatus.proxyActive !== true
  ) {
    // State transitions own their alarm mutations. A health callback that
    // observed "starting" must not clear an expiry alarm installed moments
    // later by the same control generation.
    return false;
  }
  const sync = authoritativeHeaderSync(publicStatus.headerSync);
  const closesAt = headerEvidenceGateClosesAt(sync);
  if (closesAt != null && Date.now() < closesAt) {
    await scheduleHeaderEvidenceExpiry(publicStatus.headerSync);
    return false;
  }
  await deactivateProxyForHeaderReadiness(
    new Error("validated header target evidence is approaching expiry")
  );
  return true;
}

async function scheduleHeaderSyncRetry(
  attemptedAgainst,
  expectedRuntimeControl
) {
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  const now = Date.now();
  const attemptedWindow = headerSyncUrgentRetryWindow(attemptedAgainst);
  if (attemptedWindow && attemptedWindow.endsAt >= now) {
    await rememberHeaderSyncUrgentRetryWindow(attemptedWindow);
    requireHeaderMaintenanceControl(expectedRuntimeControl);
  }
  const retainedUrgentWindow =
    await loadRetainedHeaderSyncUrgentRetryWindow();
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  const currentCandidate = publicStatus.headerSync;
  const allowedAt = nextAutomaticHeaderSyncAttemptAt(
    currentCandidate,
    lastHeaderSyncAttemptAt,
    retainedUrgentWindow,
    Date.now()
  );
  await scheduleHeaderSyncDeadline(
    currentCandidate,
    allowedAt == null ? Date.now() : allowedAt,
    expectedRuntimeControl.controlEpoch
  );
  requireHeaderMaintenanceControl(expectedRuntimeControl);
}

async function clearSupersededHeaderSyncUrgentRetryWindow(
  candidate,
  expectedRuntimeControl
) {
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  let currentWindow = headerSyncUrgentRetryWindow(candidate);
  if (!currentWindow) return;
  const retainedWindow =
    await loadRetainedHeaderSyncUrgentRetryWindow();
  requireHeaderMaintenanceControl(expectedRuntimeControl);
  currentWindow = headerSyncUrgentRetryWindow(publicStatus.headerSync);
  if (!currentWindow) return;
  if (
    retainedWindow &&
    (retainedWindow.network !== currentWindow.network ||
      retainedWindow.endsAt < currentWindow.endsAt)
  ) {
    await clearRetainedHeaderSyncUrgentRetryWindow();
    requireHeaderMaintenanceControl(expectedRuntimeControl);
  }
}

async function scheduleHeaderSyncDeadline(
  candidate,
  notBefore = Date.now(),
  expectedControlEpoch = controlEpoch
) {
  requireControlGeneration(expectedControlEpoch);
  if (!headerMaintenanceRuntimeAvailable()) {
    await clearAlarmForControl(
      HEADER_SYNC_DEADLINE_ALARM,
      expectedControlEpoch
    );
    await clearAlarmForControl(
      HEADER_EVIDENCE_EXPIRY_ALARM,
      expectedControlEpoch
    );
    return;
  }
  if (publicStatus.state === "active") {
    await scheduleHeaderEvidenceExpiry(
      candidate,
      expectedControlEpoch
    );
  } else {
    await clearAlarmForControl(
      HEADER_EVIDENCE_EXPIRY_ALARM,
      expectedControlEpoch
    );
  }
  const now = Date.now();
  const dueAt = automaticHeaderSyncDueAt(candidate);
  const floor =
    Number.isSafeInteger(notBefore) && notBefore >= now ? notBefore : now;
  const requestedAt =
    Number.isSafeInteger(dueAt) && dueAt >= 0 ? dueAt : now;
  await createAlarmForControl(
    HEADER_SYNC_DEADLINE_ALARM,
    { when: Math.max(now + 1000, floor, requestedAt) },
    expectedControlEpoch
  );
}

async function scheduleHeaderEvidenceExpiry(
  candidate,
  expectedControlEpoch = controlEpoch
) {
  requireControlGeneration(expectedControlEpoch);
  if (
    publicStatus.state !== "active" ||
    publicStatus.proxyActive !== true
  ) {
    await clearAlarmForControl(
      HEADER_EVIDENCE_EXPIRY_ALARM,
      expectedControlEpoch
    );
    return;
  }
  const sync = authoritativeHeaderSync(candidate);
  const now = Date.now();
  const expiresAt =
    sync &&
    Number.isSafeInteger(sync.targetEvidenceValidUntilUnix) &&
    sync.targetEvidenceValidUntilUnix <=
      Math.floor(Number.MAX_SAFE_INTEGER / 1000)
      ? sync.targetEvidenceValidUntilUnix * 1000
      : now;
  await createAlarmForControl(
    HEADER_EVIDENCE_EXPIRY_ALARM,
    {
      when: Math.max(
        now + 1000,
        expiresAt - HEADER_EVIDENCE_GATE_LEAD_MS
      )
    },
    expectedControlEpoch
  );
}

function headerEvidenceGateClosesAt(candidate) {
  const sync = authoritativeHeaderSync(candidate);
  if (
    !sync ||
    !Number.isSafeInteger(sync.targetEvidenceValidUntilUnix) ||
    sync.targetEvidenceValidUntilUnix >
      Math.floor(Number.MAX_SAFE_INTEGER / 1000)
  ) {
    return null;
  }
  return Math.max(
    0,
    sync.targetEvidenceValidUntilUnix * 1000 -
      HEADER_EVIDENCE_GATE_LEAD_MS
  );
}

function headerSyncReadyForNavigationGate(
  candidate,
  nowUnixMs = Date.now()
) {
  if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 0) return false;
  const closesAt = headerEvidenceGateClosesAt(candidate);
  return (
    closesAt != null &&
    closesAt > nowUnixMs &&
    headerSyncReadyForProxyActivation(
      candidate,
      Math.floor(nowUnixMs / 1000)
    )
  );
}

async function loadLastHeaderSyncAttempt() {
  const now = Date.now();
  if (lastHeaderSyncAttemptLoaded) {
    if (
      Number.isSafeInteger(lastHeaderSyncAttemptAt) &&
      lastHeaderSyncAttemptAt > now
    ) {
      lastHeaderSyncAttemptAt = null;
      try {
        await storageSet({ [HEADER_SYNC_LAST_ATTEMPT_KEY]: null });
      } catch {
        // The normalized in-memory value still restores forward progress.
      }
    }
    return lastHeaderSyncAttemptAt;
  }
  let stored = {};
  try {
    stored = await storageGet([HEADER_SYNC_LAST_ATTEMPT_KEY]);
  } catch {
    // Missing storage cannot suppress a necessary maintenance attempt.
  }
  const candidate = stored[HEADER_SYNC_LAST_ATTEMPT_KEY];
  lastHeaderSyncAttemptAt =
    Number.isSafeInteger(candidate) && candidate >= 0 && candidate <= now
      ? candidate
      : null;
  lastHeaderSyncAttemptLoaded = true;
  if (Number.isSafeInteger(candidate) && candidate > now) {
    try {
      await storageSet({ [HEADER_SYNC_LAST_ATTEMPT_KEY]: null });
    } catch {
      // The normalized in-memory value still restores forward progress.
    }
  }
  return lastHeaderSyncAttemptAt;
}

async function loadRetainedHeaderSyncUrgentRetryWindow() {
  const now = Date.now();
  let shouldClearStoredWindow = false;
  if (!retainedHeaderSyncUrgentRetryWindowLoaded) {
    let stored = {};
    try {
      stored = await storageGet([HEADER_SYNC_URGENT_RETRY_WINDOW_KEY]);
    } catch {
      // Missing storage falls back to the general fail-closed schedule.
    }
    const storedWindow = stored[HEADER_SYNC_URGENT_RETRY_WINDOW_KEY];
    retainedHeaderSyncUrgentRetryWindow =
      normalizedHeaderSyncUrgentRetryWindow(
        storedWindow,
        now
      );
    shouldClearStoredWindow =
      storedWindow != null && retainedHeaderSyncUrgentRetryWindow == null;
    retainedHeaderSyncUrgentRetryWindowLoaded = true;
  } else {
    const priorWindow = retainedHeaderSyncUrgentRetryWindow;
    retainedHeaderSyncUrgentRetryWindow =
      normalizedHeaderSyncUrgentRetryWindow(
        priorWindow,
        now
      );
    shouldClearStoredWindow =
      priorWindow != null && retainedHeaderSyncUrgentRetryWindow == null;
  }
  if (shouldClearStoredWindow) {
    try {
      await storageSet({ [HEADER_SYNC_URGENT_RETRY_WINDOW_KEY]: null });
    } catch {
      // An expired window is already absent from the in-memory scheduler.
    }
  }
  return retainedHeaderSyncUrgentRetryWindow;
}

async function rememberHeaderSyncUrgentRetryWindow(window) {
  const normalized = normalizedHeaderSyncUrgentRetryWindow(window);
  if (!normalized) return;
  retainedHeaderSyncUrgentRetryWindow = normalized;
  retainedHeaderSyncUrgentRetryWindowLoaded = true;
  try {
    await storageSet({ [HEADER_SYNC_URGENT_RETRY_WINDOW_KEY]: normalized });
  } catch {
    // The in-memory window still bounds urgent retries for this worker.
  }
}

async function clearRetainedHeaderSyncUrgentRetryWindow() {
  retainedHeaderSyncUrgentRetryWindow = null;
  retainedHeaderSyncUrgentRetryWindowLoaded = true;
  try {
    await storageSet({ [HEADER_SYNC_URGENT_RETRY_WINDOW_KEY]: null });
  } catch {
    // The in-memory window is already cleared.
  }
}

async function recordHeaderSyncAttempt(attemptedAt) {
  lastHeaderSyncAttemptAt = attemptedAt;
  lastHeaderSyncAttemptLoaded = true;
  try {
    await storageSet({ [HEADER_SYNC_LAST_ATTEMPT_KEY]: attemptedAt });
  } catch {
    // The in-memory timestamp still prevents an automatic retry storm.
  }
}

function validateStartResult(result) {
  if (
    !result ||
    result.state !== "active" ||
    typeof result.pacScript !== "string" ||
    !result.pacScript.includes("FindProxyForURL") ||
    !result.proxy ||
    result.proxy.host !== "127.0.0.1" ||
    !Number.isInteger(result.proxy.port) ||
    result.proxy.port < 1 ||
    typeof result.proxy.username !== "string" ||
    typeof result.proxy.password !== "string" ||
    typeof result.runtimeSession !== "string" ||
    !Number.isSafeInteger(result.runtimeGeneration) ||
    result.runtimeGeneration < 1 ||
    !Number.isSafeInteger(result.policyGeneration) ||
    result.policyGeneration < 1 ||
    !Number.isSafeInteger(result.securityMaintenanceEpoch) ||
    result.securityMaintenanceEpoch < 1 ||
    !Array.isArray(result.recentConnectSecurityDecisions) ||
    result.recentConnectSecurityDecisions.length !== 0 ||
    !result.ca ||
    !validHeaderSyncEnvelope(result)
  ) {
    throw new Error("native host returned an invalid proxy generation");
  }
}

function validateStatusResult(result, expectedRuntime = publicStatus) {
  if (
    !result ||
    result.state !== "active" ||
    typeof result.runtimeSession !== "string" ||
    result.runtimeSession !== expectedRuntime.runtimeSession ||
    !Number.isSafeInteger(result.runtimeGeneration) ||
    result.runtimeGeneration !== expectedRuntime.runtimeGeneration ||
    !Number.isSafeInteger(result.policyGeneration) ||
    result.policyGeneration !== expectedRuntime.policyGeneration ||
    !Number.isSafeInteger(result.securityMaintenanceEpoch) ||
    result.securityMaintenanceEpoch < 1 ||
    (Number.isSafeInteger(expectedRuntime.securityMaintenanceEpoch) &&
      result.securityMaintenanceEpoch < expectedRuntime.securityMaintenanceEpoch) ||
    !Array.isArray(result.recentConnectSecurityDecisions) ||
    result.recentConnectSecurityDecisions.length >
      MAX_NATIVE_CONNECT_SECURITY_DECISIONS ||
    result.caReady !== true ||
    !validHeaderSyncEnvelope(result)
  ) {
    throw new Error("native host returned a stale or invalid runtime status");
  }
}

function validatedConnectSecurityDecisions(result) {
  let previousEventSequence = 0;
  const decisions = [];
  for (const candidate of result.recentConnectSecurityDecisions) {
    const decision = currentConnectSecurityDecision(candidate, result);
    if (!decision || decision.eventSequence <= previousEventSequence) {
      throw new Error("native host returned invalid CONNECT security decisions");
    }
    previousEventSequence = decision.eventSequence;
    decisions.push(decision);
  }
  return Object.freeze(decisions);
}

function beginControlGeneration() {
  if (controlEpoch >= Number.MAX_SAFE_INTEGER) {
    throw new Error("proxy control generation is exhausted");
  }
  walletProviderRouter.forgetAll();
  void invalidateAllWalletApprovals("runtimeGenerationChanged");
  controlEpoch += 1;
  return controlEpoch;
}

function supersededControlError() {
  const error = new Error("proxy control generation was superseded");
  error.code = "controlEpochSuperseded";
  return error;
}

function isSupersededControlError(error) {
  return error?.code === "controlEpochSuperseded";
}

function requireControlGeneration(expectedControlEpoch) {
  if (expectedControlEpoch !== controlEpoch) {
    throw supersededControlError();
  }
}

function runtimeControlIsCurrent(
  expectedControlEpoch,
  expectedConnectionEpoch
) {
  return (
    expectedControlEpoch === controlEpoch &&
    client.connectionIsCurrent(expectedConnectionEpoch)
  );
}

function requireRuntimeControl(
  expectedControlEpoch,
  expectedConnectionEpoch
) {
  requireControlGeneration(expectedControlEpoch);
  if (!client.connectionIsCurrent(expectedConnectionEpoch)) {
    throw supersededControlError();
  }
}

function headerMaintenanceRuntimeAvailable(candidate = publicStatus) {
  return (
    candidate != null &&
    candidate.proxyActive === true &&
    credentials != null &&
    client.currentConnectionEpoch() != null &&
    (candidate.state === "active" ||
      headerReadinessFailClosed(candidate))
  );
}

function captureHeaderMaintenanceControl(candidate = publicStatus) {
  if (!headerMaintenanceRuntimeAvailable(candidate)) return null;
  return runtimeControlToken(
    controlEpoch,
    client.currentConnectionEpoch(),
    candidate
  );
}

function headerMaintenanceControlIsCurrent(
  expected,
  candidate = publicStatus
) {
  return (
    headerMaintenanceRuntimeAvailable(candidate) &&
    runtimeControlTokenIsCurrent(
      expected,
      controlEpoch,
      client.currentConnectionEpoch(),
      candidate
    )
  );
}

function requireHeaderMaintenanceControl(
  expected,
  candidate = publicStatus
) {
  if (!headerMaintenanceControlIsCurrent(expected, candidate)) {
    throw supersededControlError();
  }
}

function installBlockingPac(expectedControlEpoch) {
  return pacController.install(
    BLOCKING_PAC_SCRIPT,
    expectedControlEpoch
  );
}

function installLivePac(pacScript, expectedControlEpoch) {
  return pacController.install(pacScript, expectedControlEpoch);
}

function setMandatoryPac(pacScript) {
  return chromeCall(chrome.proxy.settings.set, chrome.proxy.settings, {
    value: {
      mode: "pac_script",
      pacScript: {
        data: pacScript,
        mandatory: true
      }
    },
    scope: "regular"
  });
}

async function readMandatoryPacScript() {
  const result = await chromeCall(
    chrome.proxy.settings.get,
    chrome.proxy.settings,
    { incognito: false }
  );
  const value = result?.value;
  if (
    result?.levelOfControl !== "controlled_by_this_extension" ||
    value?.mode !== "pac_script" ||
    value?.pacScript?.mandatory !== true ||
    typeof value.pacScript.data !== "string"
  ) {
    return null;
  }
  return value.pacScript.data;
}

function mutateAlarmForControl(expectedControlEpoch, mutation) {
  return alarmMutations.run(expectedControlEpoch, mutation);
}

function clearAlarmForControl(name, expectedControlEpoch) {
  return mutateAlarmForControl(
    expectedControlEpoch,
    () => chrome.alarms.clear(name)
  );
}

function createAlarmForControl(name, alarmInfo, expectedControlEpoch) {
  return mutateAlarmForControl(
    expectedControlEpoch,
    () => chrome.alarms.create(name, alarmInfo)
  );
}

function setStatus(update) {
  publicStatus = Object.freeze({ ...publicStatus, ...update });
  const proxyReady =
    publicStatus.state === "active" && publicStatus.proxyActive === true;
  const nativeUpdateRequired =
    publicStatus.nativeComponentState === "versionMismatch" ||
    publicStatus.nativeComponentState === "incompatible";
  void chrome.action.setBadgeText({
    text: proxyReady ? "HNS" : nativeUpdateRequired ? "UP" : "!"
  });
  void chrome.action.setBadgeBackgroundColor({
    color: proxyReady ? "#177245" : "#9b2c2c"
  });
}

function boundedError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message.slice(0, 512);
}

function storageGet(keys) {
  return chromeCall(chrome.storage.local.get, chrome.storage.local, keys);
}

function storageSet(values) {
  return chromeCall(chrome.storage.local.set, chrome.storage.local, values);
}

function storageRemove(keys) {
  const boundedKeys = keys.filter((key) => LEGACY_HNS_DOH_KEYS.includes(key));
  return chromeCall(chrome.storage.local.remove, chrome.storage.local, boundedKeys);
}

async function promptForNativeSetupOnce() {
  if (
    !nativeSetupPromptRequired(
      nativeSetupPromptedVersion,
      EXTENSION_VERSION
    )
  ) {
    return;
  }
  try {
    const stored = await chromeCall(
      chrome.storage.session.get,
      chrome.storage.session,
      [NATIVE_SETUP_PROMPTED_VERSION_KEY]
    );
    if (
      !nativeSetupPromptRequired(
        stored?.[NATIVE_SETUP_PROMPTED_VERSION_KEY],
        EXTENSION_VERSION
      )
    ) {
      nativeSetupPromptedVersion = EXTENSION_VERSION;
      return;
    }
    await chromeCall(
      chrome.storage.session.set,
      chrome.storage.session,
      { [NATIVE_SETUP_PROMPTED_VERSION_KEY]: EXTENSION_VERSION }
    );
  } catch {
    // The in-memory marker still prevents a prompt loop in this worker.
  }
  nativeSetupPromptedVersion = EXTENSION_VERSION;
  const setupUrl = new URL(chrome.runtime.getURL("src/setup.html"));
  setupUrl.searchParams.set("reason", "native-component-update");
  if (typeof publicStatus.nativeHostVersion === "string") {
    setupUrl.searchParams.set("installed", publicStatus.nativeHostVersion);
  }
  setupUrl.hash = "install";
  try {
    await chromeCall(chrome.tabs.create, chrome.tabs, {
      url: setupUrl.href
    });
  } catch {
    // The popup continues to expose the same Setup action if tab creation fails.
  }
}

async function captureCompletedMainFrame(details) {
  const status = await refreshNativeStatus();
  const completed = await withNavigationReceiptStore((store) =>
    store.completeRequest(details, status)
  );
  if (completed) await notifyWalletProviderBootstrap(details);
}

function invalidateWalletProviderDocument(details, reason) {
  if (
    !Number.isSafeInteger(details?.tabId) ||
    typeof details?.documentId !== "string"
  ) {
    return;
  }
  walletProviderRouter.forgetDocument(details.tabId, details.documentId);
  void invalidateWalletApprovalsForTab(
    details.tabId,
    details.documentId,
    reason
  );
  void chromeCall(
    chrome.tabs.sendMessage,
    chrome.tabs,
    details.tabId,
    {
      type: "walletProviderInvalidate",
      schemaVersion: 1,
      reason
    },
    { documentId: details.documentId }
  ).catch(() => {});
}

async function notifyWalletProviderBootstrap(details) {
  if (!Number.isSafeInteger(details?.tabId)) return;
  let documentId =
    typeof details.documentId === "string" ? details.documentId : null;
  if (!documentId) {
    const frame = await chromeCall(
      chrome.webNavigation.getFrame,
      chrome.webNavigation,
      { tabId: details.tabId, frameId: 0 }
    ).catch(() => null);
    documentId = typeof frame?.documentId === "string" ? frame.documentId : null;
  }
  if (!documentId) return;
  await chromeCall(
    chrome.tabs.sendMessage,
    chrome.tabs,
    details.tabId,
    {
      type: "walletProviderBootstrapReady",
      schemaVersion: 1
    },
    { documentId }
  ).catch(() => {});
}

async function statusForTab(status, tabId) {
  const validTabId = Number.isSafeInteger(tabId) && tabId >= 0 ? tabId : null;
  if (validTabId != null) {
    try {
      const frame = await chromeCall(
        chrome.webNavigation.getFrame,
        chrome.webNavigation,
        { tabId: validTabId, frameId: 0 }
      );
      if (frame && typeof frame.documentId === "string") {
        await withNavigationReceiptStore((store) =>
          store.commitDocument(
            {
              tabId: validTabId,
              frameId: 0,
              documentId: frame.documentId,
              url: frame.url,
              transitionQualifiers: []
            },
            "activeDocumentReceiptUnavailable"
          )
        );
      }
    } catch {
      // The tab may have closed between popup activation and frame inspection.
    }
  }
  const scoped = await withNavigationReceiptStore(
    (store) => store.receiptForTab(validTabId, status),
    false
  );
  const { recentConnectSecurityDecisions: _internalDecisions, ...uiStatus } =
    status;
  return {
    ...uiStatus,
    latestMainFrameSecurity: scoped.receipt,
    latestMainFrameConnectDecisionReceipt: scoped.connectDecisionReceipt,
    latestMainFrameSecurityUnavailableReason: scoped.unavailableReason,
    latestMainFrameSecurityReceiptState: scoped.state,
    latestMainFrameSecurityReceiptSource: scoped.source
  };
}

function withNavigationReceiptStore(operation, persist = true) {
  const result = navigationReceiptQueue.then(async () => {
    const store = await loadNavigationReceiptStore();
    const value = await operation(store);
    if (persist) await persistNavigationReceiptStore(store);
    return value;
  });
  navigationReceiptQueue = result.then(
    () => undefined,
    () => undefined
  );
  return result;
}

async function loadNavigationReceiptStore() {
  if (navigationReceiptStore) return navigationReceiptStore;
  try {
    const stored = await chromeCall(
      chrome.storage.session.get,
      chrome.storage.session,
      [NAVIGATION_RECEIPTS_STORAGE_KEY]
    );
    navigationReceiptStore = new NavigationReceiptStore(
      stored?.[NAVIGATION_RECEIPTS_STORAGE_KEY]
    );
  } catch {
    navigationReceiptStore = new NavigationReceiptStore();
  }
  return navigationReceiptStore;
}

async function persistNavigationReceiptStore(store) {
  try {
    await chromeCall(
      chrome.storage.session.set,
      chrome.storage.session,
      { [NAVIGATION_RECEIPTS_STORAGE_KEY]: store.snapshot() }
    );
  } catch {
    // The bounded in-memory receipts remain valid for this live worker.
  }
}

function chromeCall(method, receiver, ...arguments_) {
  return new Promise((resolve, reject) => {
    method.call(receiver, ...arguments_, (result) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
      } else {
        resolve(result);
      }
    });
  });
}
