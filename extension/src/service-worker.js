import {
  MAX_REQUEST_TIMEOUT_MS,
  NativeClient
} from "./native-client.js";
import {
  AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS,
  automaticHeaderSyncAllowed,
  needsAutomaticHeaderSync
} from "./header-sync-schedule.js";
import {
  DEFAULT_POLICY,
  LEGACY_HNS_DOH_KEYS,
  migrateStoredSettings,
  normalizePolicy
} from "./policy.js";
import { currentSecurityResult } from "./security-result.js";
import {
  authoritativeHeaderSync,
  currentHeaderSync,
  validHeaderSyncEnvelope
} from "./header-status.js";

const NATIVE_HOST = "com.denuoweb.hns_dane_browser";
const HEALTH_ALARM = "hns-runtime-health";
const RECONNECT_ALARM = "hns-runtime-reconnect";
const HEADER_SYNC_ALARM = "hns-header-sync";
const HEALTH_PERIOD_MINUTES = 5;
const HEADER_SYNC_PERIOD_MINUTES =
  AUTOMATIC_HEADER_SYNC_MIN_INTERVAL_MS / (60 * 1000);
const HEADER_SYNC_LAST_ATTEMPT_KEY = "headerSyncLastAttemptAt";
const client = new NativeClient(chrome, NATIVE_HOST);

let activeOperation = null;
let headerSyncOperation = null;
let headerMaintenanceOperation = null;
let lastHeaderSyncAttemptAt = null;
let lastHeaderSyncAttemptLoaded = false;
let credentials = null;
let publicStatus = {
  state: "starting",
  reason: null,
  runtimeSession: null,
  runtimeGeneration: null,
  policyGeneration: 0,
  caReady: false,
  headerSync: null,
  headerSyncInProgress: false,
  headerSyncError: null,
  latestMainFrameSecurity: null,
  latestMainFrameSecurityUnavailableReason: null
};

client.onDisconnect(() => {
  credentials = null;
  setStatus({
    state: "degraded",
    reason: "nativeHostDisconnected",
    headerSync: null,
    headerSyncInProgress: false,
    headerSyncError: "Native host disconnected",
    latestMainFrameSecurity: null,
    latestMainFrameSecurityUnavailableReason: null
  });
  void clearProxy();
  chrome.alarms.create(RECONNECT_ALARM, { delayInMinutes: 1 });
});

chrome.runtime.onInstalled.addListener(() => {
  void migrateAndRecover();
});

chrome.runtime.onStartup.addListener(() => {
  void recover();
});

chrome.runtime.onSuspend.addListener(() => {
  credentials = null;
  chrome.proxy.settings.clear({ scope: "regular" }, () => {});
  client.disconnect();
});

chrome.runtime.onSuspendCanceled.addListener(() => {
  void recover();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HEALTH_ALARM) {
    void refreshNativeStatus();
  } else if (alarm.name === RECONNECT_ALARM) {
    void recover();
  } else if (alarm.name === HEADER_SYNC_ALARM) {
    void maintainHeaderFreshness(true).catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !message || typeof message.type !== "string") {
    return false;
  }
  void handleUiMessage(message)
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

chrome.alarms.create(HEALTH_ALARM, { periodInMinutes: HEALTH_PERIOD_MINUTES });
chrome.alarms.create(HEADER_SYNC_ALARM, {
  periodInMinutes: HEADER_SYNC_PERIOD_MINUTES
});
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

function recover() {
  if (activeOperation) return activeOperation;
  activeOperation = startRuntime()
    .catch((error) => {
      setStatus({
        state: publicStatus.state === "blocked" ? "blocked" : "degraded",
        reason: error instanceof Error ? error.message : String(error),
        headerSyncInProgress: false,
        headerSyncError: "Native runtime startup failed",
        latestMainFrameSecurity: null,
        latestMainFrameSecurityUnavailableReason: null
      });
      return publicStatus;
    })
    .finally(() => {
      activeOperation = null;
    });
  return activeOperation;
}

async function startRuntime(policyOverride) {
  setStatus({
    state: "starting",
    reason: null,
    headerSync: null,
    headerSyncInProgress: false,
    headerSyncError: null,
    latestMainFrameSecurity: null,
    latestMainFrameSecurityUnavailableReason: null
  });
  const stored = await storageGet(["policy"]);
  const policy = normalizePolicy(policyOverride ?? stored.policy ?? DEFAULT_POLICY);
  try {
    await client.request("hello");
    const result = await client.request("start", { policy });
    validateStartResult(result);

    if (result.ca.state !== "installed") {
      throw new Error("local CA installation is required before the HNS PAC can activate");
    }

    // Credentials must exist before the PAC becomes visible so an immediate
    // browser request cannot race the proxy authentication callback.
    credentials = {
      port: result.proxy.port,
      username: result.proxy.username,
      password: result.proxy.password
    };
    await installPac(result.pacScript);
    setStatus({
      state: "active",
      reason: null,
      runtimeSession: result.runtimeSession,
      runtimeGeneration: result.runtimeGeneration,
      policyGeneration: result.policyGeneration,
      caReady: true,
      headerSync: currentHeaderSync(result.headerSync),
      headerSyncInProgress: false,
      headerSyncError:
        result.headerSync == null ? "Validated header status unavailable" : null,
      latestMainFrameSecurity: null,
      latestMainFrameSecurityUnavailableReason: null
    });
    void maintainHeaderFreshness(false).catch(() => {});
    return publicStatus;
  } catch (error) {
    await clearProxy();
    credentials = null;
    try {
      await client.request("stop");
    } catch {
      client.disconnect();
    }
    const localCaRequired =
      error instanceof Error && error.message.includes("local CA installation is required");
    if (localCaRequired) {
      setStatus({
        state: "blocked",
        reason: "localCaRequired",
        caReady: false
      });
    }
    throw error;
  }
}

async function handleUiMessage(message) {
  switch (message.type) {
    case "getStatus":
      return refreshNativeStatus();
    case "restart":
      return recover();
    case "syncHeadersNow":
      return synchronizeHeaders();
    case "setPolicy": {
      const policy = normalizePolicy(message.policy);
      const result = await startRuntime(policy);
      await storageSet({ policy });
      return result;
    }
    case "diagnostics":
      return client.request("diagnostics");
    default:
      throw new Error("unsupported extension message");
  }
}

async function refreshNativeStatus() {
  if (publicStatus.state !== "active") return publicStatus;
  if (headerSyncOperation) return publicStatus;
  try {
    const result = await client.request("status");
    validateStatusResult(result);
    const latestMainFrameSecurity = currentSecurityResult(
      result.latestMainFrameSecurity,
      result
    );
    setStatus({
      state: "active",
      reason: null,
      runtimeSession: result.runtimeSession,
      runtimeGeneration: result.runtimeGeneration,
      policyGeneration: result.policyGeneration,
      caReady: result.caReady === true,
      headerSync: currentHeaderSync(result.headerSync),
      headerSyncInProgress: false,
      headerSyncError:
        result.headerSync == null &&
        typeof result.headerSyncUnavailableReason === "string"
          ? "Validated header status unavailable"
          : null,
      latestMainFrameSecurity,
      latestMainFrameSecurityUnavailableReason:
        latestMainFrameSecurity == null &&
        typeof result.latestMainFrameSecurityUnavailableReason === "string"
          ? result.latestMainFrameSecurityUnavailableReason
          : null
    });
  } catch (error) {
    await clearProxy();
    client.disconnect();
    setStatus({
      state: "degraded",
      reason: error instanceof Error ? error.message : String(error),
      headerSync: null,
      headerSyncInProgress: false,
      headerSyncError: "Native runtime status unavailable",
      latestMainFrameSecurity: null,
      latestMainFrameSecurityUnavailableReason: null
    });
  }
  return publicStatus;
}

function maintainHeaderFreshness(refreshStatus) {
  if (headerMaintenanceOperation) return headerMaintenanceOperation;
  headerMaintenanceOperation = (async () => {
    if (publicStatus.state !== "active") return publicStatus;
    const status = refreshStatus ? await refreshNativeStatus() : publicStatus;
    if (!needsAutomaticHeaderSync(status.headerSync)) return status;
    const lastAttemptAt = await loadLastHeaderSyncAttempt();
    if (!automaticHeaderSyncAllowed(lastAttemptAt)) return status;
    return synchronizeHeaders();
  })().finally(() => {
    headerMaintenanceOperation = null;
  });
  return headerMaintenanceOperation;
}

function synchronizeHeaders() {
  if (headerSyncOperation) return headerSyncOperation;
  if (publicStatus.state !== "active") {
    return Promise.reject(new Error("header sync requires an active native runtime"));
  }

  setStatus({
    headerSyncInProgress: true,
    headerSyncError: null,
    latestMainFrameSecurity: null,
    latestMainFrameSecurityUnavailableReason: "headerSyncInProgress"
  });
  headerSyncOperation = (async () => {
    await recordHeaderSyncAttempt(Date.now());
    try {
      const result = await client.request(
        "syncOnce",
        {},
        { timeoutMs: MAX_REQUEST_TIMEOUT_MS }
      );
      const headerSync = authoritativeHeaderSync(result);
      if (!headerSync) throw new Error("native host returned invalid header sync status");
      setStatus({
        headerSync,
        headerSyncInProgress: false,
        headerSyncError: null
      });
      return publicStatus;
    } catch (error) {
      setStatus({
        headerSyncInProgress: false,
        headerSyncError: boundedError(error)
      });
      throw error;
    }
  })().finally(() => {
    headerSyncOperation = null;
  });
  return headerSyncOperation;
}

async function loadLastHeaderSyncAttempt() {
  if (lastHeaderSyncAttemptLoaded) return lastHeaderSyncAttemptAt;
  const stored = await storageGet([HEADER_SYNC_LAST_ATTEMPT_KEY]);
  const candidate = stored[HEADER_SYNC_LAST_ATTEMPT_KEY];
  const now = Date.now();
  lastHeaderSyncAttemptAt =
    Number.isSafeInteger(candidate) && candidate >= 0 && candidate <= now
      ? candidate
      : null;
  lastHeaderSyncAttemptLoaded = true;
  return lastHeaderSyncAttemptAt;
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
    !result.ca ||
    !validHeaderSyncEnvelope(result)
  ) {
    throw new Error("native host returned an invalid proxy generation");
  }
}

function validateStatusResult(result) {
  if (
    !result ||
    result.state !== "active" ||
    typeof result.runtimeSession !== "string" ||
    result.runtimeSession !== publicStatus.runtimeSession ||
    !Number.isSafeInteger(result.runtimeGeneration) ||
    result.runtimeGeneration !== publicStatus.runtimeGeneration ||
    !Number.isSafeInteger(result.policyGeneration) ||
    result.policyGeneration !== publicStatus.policyGeneration ||
    result.caReady !== true ||
    !validHeaderSyncEnvelope(result)
  ) {
    throw new Error("native host returned a stale or invalid runtime status");
  }
}

async function installPac(pacScript) {
  await chromeCall(chrome.proxy.settings.set, chrome.proxy.settings, {
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

async function clearProxy() {
  credentials = null;
  try {
    await chromeCall(chrome.proxy.settings.clear, chrome.proxy.settings, {
      scope: "regular"
    });
  } catch {
    // Clearing is best-effort during process teardown; no direct fallback is installed here.
  }
}

function setStatus(update) {
  publicStatus = Object.freeze({ ...publicStatus, ...update });
  void chrome.action.setBadgeText({
    text: publicStatus.state === "active" ? "HNS" : "!"
  });
  void chrome.action.setBadgeBackgroundColor({
    color: publicStatus.state === "active" ? "#177245" : "#9b2c2c"
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
