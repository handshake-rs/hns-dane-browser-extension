import { NativeClient } from "./native-client.js";
import {
  DEFAULT_POLICY,
  LEGACY_HNS_DOH_KEYS,
  migrateStoredSettings,
  normalizePolicy
} from "./policy.js";

const NATIVE_HOST = "com.denuoweb.hns_dane_browser";
const HEALTH_ALARM = "hns-runtime-health";
const RECONNECT_ALARM = "hns-runtime-reconnect";
const HEALTH_PERIOD_MINUTES = 5;
const client = new NativeClient(chrome, NATIVE_HOST);

let activeOperation = null;
let credentials = null;
let publicStatus = {
  state: "starting",
  reason: null,
  runtimeSession: null,
  runtimeGeneration: null,
  policyGeneration: 0,
  caReady: false
};

client.onDisconnect(() => {
  credentials = null;
  setStatus({ state: "degraded", reason: "nativeHostDisconnected" });
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
  if (alarm.name === HEALTH_ALARM || alarm.name === RECONNECT_ALARM) {
    void recover();
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
        reason: error instanceof Error ? error.message : String(error)
      });
      return publicStatus;
    })
    .finally(() => {
      activeOperation = null;
    });
  return activeOperation;
}

async function startRuntime(policyOverride) {
  setStatus({ state: "starting", reason: null });
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
      caReady: true
    });
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
      return publicStatus;
    case "restart":
      return recover();
    case "setPolicy": {
      const policy = normalizePolicy(message.policy);
      await storageSet({ policy });
      return startRuntime(policy);
    }
    case "diagnostics":
      return client.request("diagnostics");
    default:
      throw new Error("unsupported extension message");
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
    !result.ca
  ) {
    throw new Error("native host returned an invalid proxy generation");
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
