import test from "node:test";
import assert from "node:assert/strict";
import {
  BLOCKING_PAC_SCRIPT,
  SerializedEpochMutationController,
  SerializedMandatoryPacController,
  deactivateIfHeaderEvidenceExpired,
  installPacForCurrentNativeGeneration,
  runtimeControlToken,
  runtimeControlTokenIsCurrent,
  sameLiveProxyGeneration,
  settleLifecycleBarrier
} from "../src/proxy-lifecycle.js";
import { NativeClient } from "../src/native-client.js";
import { needsAutomaticHeaderSync } from "../src/header-sync-schedule.js";

const LIVE_A =
  'function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:4101"; }';
const LIVE_B =
  'function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:4102"; }';

function headerSync(overrides = {}) {
  return {
    network: "mainnet",
    status: "up_to_date",
    attempted: 3,
    successful: 3,
    bestHeight: 339_927,
    bestPeerHeight: 339_929,
    estimatedTipHeight: 339_930,
    effectiveTargetHeight: 339_929,
    lagBlocks: 2,
    freshness: "current",
    freshnessThresholdBlocks: 2,
    targetSource: "corroboratedPeers",
    targetPeerGroups: 3,
    targetEvidenceExpired: false,
    targetEvidenceValidUntilUnix: 2_000_000,
    error: null,
    ...overrides
  };
}

test("replacement is live A to blocker to captured-A disconnect to live B", async () => {
  let epoch = 1;
  let selectedPac = null;
  const events = [];
  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");
  const controller = new SerializedMandatoryPacController(
    async (pacScript) => {
      selectedPac = pacScript;
      events.push(
        pacScript === BLOCKING_PAC_SCRIPT
          ? "blocking-pac"
          : pacScript === LIVE_A
            ? "live-a"
            : "live-b"
      );
    },
    async () => selectedPac,
    (expected) => expected === epoch,
    5
  );

  await controller.install(LIVE_A, epoch);
  const pendingA = client.request("syncOnce");
  const portA = native.ports[0];
  const connectionA = client.currentConnectionEpoch();
  epoch += 1;
  await controller.install(BLOCKING_PAC_SCRIPT, epoch);
  assert.equal(client.disconnectIfCurrent(connectionA), true);
  await assert.rejects(pendingA, /native host disconnected/);
  events.push("disconnect-a");
  events.push("prepare-b");
  const pendingB = client.request("hello");
  const portB = native.ports[1];
  const connectionB = client.currentConnectionEpoch();
  portA.emitDisconnect();
  assert.equal(client.connectionIsCurrent(connectionB), true);
  assert.equal(portB.disconnectCalls, 0);
  await controller.install(LIVE_B, epoch);

  const hello = portB.messages[0];
  portB.emitMessage({
    schemaVersion: 1,
    requestId: hello.requestId,
    runtimeSession: "session-b",
    eventSequence: 1,
    ok: true,
    result: { status: "active" }
  });
  await pendingB;

  assert.deepEqual(events, [
    "live-a",
    "blocking-pac",
    "disconnect-a",
    "prepare-b",
    "live-b"
  ]);
  assert.equal(selectedPac, LIVE_B);
  assert.match(BLOCKING_PAC_SCRIPT, /PROXY 127\.0\.0\.1:1/);
  assert.doesNotMatch(BLOCKING_PAC_SCRIPT, /\bDIRECT\b/);
});

test("a dropped PAC callback is accepted only after exact readback", async () => {
  let selectedPac = LIVE_A;
  let disconnected = false;
  const controller = new SerializedMandatoryPacController(
    (pacScript) => {
      selectedPac = pacScript;
      return new Promise(() => {});
    },
    async () => selectedPac,
    (expected) => expected === 2,
    5
  );

  await controller.install(BLOCKING_PAC_SCRIPT, 2);
  disconnected = true;

  assert.equal(disconnected, true);
  assert.equal(selectedPac, BLOCKING_PAC_SCRIPT);
});

test("unconfirmed PAC replacement retains the captured native listener", async () => {
  let disconnected = false;
  const controller = new SerializedMandatoryPacController(
    () => new Promise(() => {}),
    async () => LIVE_A,
    (expected) => expected === 2,
    5
  );

  await assert.rejects(
    controller.install(BLOCKING_PAC_SCRIPT, 2),
    (error) => error?.code === "proxyMutationUnconfirmed"
  );

  assert.equal(disconnected, false);
});

test("a late stale PAC mutation is repaired to the newest generation", async () => {
  let epoch = 1;
  let selectedPac = null;
  let delayNextMutation = false;
  let completeLateMutation;
  const events = [];
  const controller = new SerializedMandatoryPacController(
    (pacScript) => {
      if (delayNextMutation) {
        delayNextMutation = false;
        return new Promise((resolve) => {
          completeLateMutation = () => {
            selectedPac = pacScript;
            events.push("late-stale-mutation");
            resolve();
          };
        });
      }
      selectedPac = pacScript;
      events.push(pacScript);
    },
    async () => selectedPac,
    (expected) => expected === epoch,
    5
  );

  await controller.install(LIVE_A, epoch);
  epoch = 2;
  delayNextMutation = true;
  await assert.rejects(
    controller.install(BLOCKING_PAC_SCRIPT, epoch),
    (error) => error?.code === "proxyMutationUnconfirmed"
  );

  epoch = 3;
  await controller.install(LIVE_B, epoch);
  assert.equal(selectedPac, LIVE_B);

  completeLateMutation();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(selectedPac, LIVE_B);
  assert.equal(events.at(-2), "late-stale-mutation");
  assert.equal(events.at(-1), LIVE_B);
});

test("a late same-epoch live mutation is repaired after the blocker is confirmed", async () => {
  const epoch = 2;
  let selectedPac = BLOCKING_PAC_SCRIPT;
  let completeLateLiveMutation;
  let nativeBDisconnected = false;
  let delayNextMutation = true;
  const events = [];
  const controller = new SerializedMandatoryPacController(
    (pacScript) => {
      if (delayNextMutation) {
        delayNextMutation = false;
        return new Promise((resolve) => {
          completeLateLiveMutation = () => {
            selectedPac = pacScript;
            events.push("late-live-b");
            resolve();
          };
        });
      }
      selectedPac = pacScript;
      events.push(
        pacScript === BLOCKING_PAC_SCRIPT ? "blocking-pac" : "live-b"
      );
    },
    async () => selectedPac,
    (expected) => expected === epoch,
    5
  );

  await assert.rejects(
    controller.install(LIVE_B, epoch),
    (error) => error?.code === "proxyMutationUnconfirmed"
  );
  await controller.install(BLOCKING_PAC_SCRIPT, epoch);
  nativeBDisconnected = true;
  assert.equal(selectedPac, BLOCKING_PAC_SCRIPT);

  completeLateLiveMutation();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(nativeBDisconnected, true);
  assert.equal(selectedPac, BLOCKING_PAC_SCRIPT);
  assert.deepEqual(events.slice(-2), ["late-live-b", "blocking-pac"]);
});

test("a rejected PAC readback still arms repair for a late mutation", async () => {
  const epoch = 6;
  let selectedPac = BLOCKING_PAC_SCRIPT;
  let completeLateLiveMutation;
  let delayNextMutation = true;
  let rejectReadback = true;
  const controller = new SerializedMandatoryPacController(
    (pacScript) => {
      if (delayNextMutation) {
        delayNextMutation = false;
        return new Promise((resolve) => {
          completeLateLiveMutation = () => {
            selectedPac = pacScript;
            resolve();
          };
        });
      }
      selectedPac = pacScript;
    },
    async () => {
      if (rejectReadback) throw new Error("proxy settings unavailable");
      return selectedPac;
    },
    (expected) => expected === epoch,
    5
  );

  await assert.rejects(
    controller.install(LIVE_B, epoch),
    (error) => error?.code === "proxyMutationUnconfirmed"
  );
  rejectReadback = false;
  await controller.install(BLOCKING_PAC_SCRIPT, epoch);
  completeLateLiveMutation();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(selectedPac, BLOCKING_PAC_SCRIPT);
});

test("epoch-gated alarm mutations serialize a late old write behind the current write", async () => {
  let epoch = 1;
  let completeOldMutation;
  const calls = [];
  const mutations = new SerializedEpochMutationController(
    (expected) => expected === epoch
  );
  const oldMutation = mutations.run(1, () => {
    calls.push("old-started");
    return new Promise((resolve) => {
      completeOldMutation = () => {
        calls.push("old-finished");
        resolve();
      };
    });
  });

  await new Promise((resolve) => setImmediate(resolve));
  epoch = 2;
  const currentMutation = mutations.run(2, () => {
    calls.push("current");
  });
  completeOldMutation();

  await assert.rejects(
    oldMutation,
    (error) => error?.code === "controlEpochSuperseded"
  );
  await currentMutation;
  assert.deepEqual(calls, ["old-started", "old-finished", "current"]);
});

test("an already superseded queued alarm mutation never reaches Chromium", async () => {
  let epoch = 1;
  let releaseFirst;
  let staleCalls = 0;
  const mutations = new SerializedEpochMutationController(
    (expected) => expected === epoch
  );
  const first = mutations.run(1, () =>
    new Promise((resolve) => {
      releaseFirst = resolve;
    })
  );
  const stale = mutations.run(1, () => {
    staleCalls += 1;
  });

  await new Promise((resolve) => setImmediate(resolve));
  epoch = 2;
  releaseFirst();
  await assert.rejects(
    first,
    (error) => error?.code === "controlEpochSuperseded"
  );
  await assert.rejects(
    stale,
    (error) => error?.code === "controlEpochSuperseded"
  );
  assert.equal(staleCalls, 0);
});

test("a maintenance continuation cannot adopt a replacement runtime after storage awaits", async () => {
  let controlEpoch = 4;
  let connectionEpoch = 9;
  let runtime = {
    runtimeSession: "session-a",
    runtimeGeneration: 2,
    policyGeneration: 5
  };
  const captured = runtimeControlToken(
    controlEpoch,
    connectionEpoch,
    runtime
  );
  let releaseStorage;
  let alarmMutated = false;
  const storage = new Promise((resolve) => {
    releaseStorage = resolve;
  });
  const continuation = storage.then(() => {
    if (
      !runtimeControlTokenIsCurrent(
        captured,
        controlEpoch,
        connectionEpoch,
        runtime
      )
    ) {
      const error = new Error("runtime control was superseded");
      error.code = "controlEpochSuperseded";
      throw error;
    }
    alarmMutated = true;
  });

  controlEpoch = 5;
  connectionEpoch = 11;
  runtime = {
    runtimeSession: "session-b",
    runtimeGeneration: 3,
    policyGeneration: 6
  };
  releaseStorage();

  await assert.rejects(
    continuation,
    (error) => error?.code === "controlEpochSuperseded"
  );
  assert.equal(alarmMutated, false);
  assert.equal(
    runtimeControlTokenIsCurrent(
      captured,
      controlEpoch,
      connectionEpoch,
      runtime
    ),
    false
  );
});

test("native generation change during live PAC install never publishes active", async () => {
  let generationCurrent = true;
  let completeInstall;
  let published = false;
  const activation = installPacForCurrentNativeGeneration(
    () =>
      new Promise((resolve) => {
        completeInstall = resolve;
      }),
    () => generationCurrent,
    () => {
      published = true;
    }
  );

  generationCurrent = false;
  completeInstall();

  await assert.rejects(activation, /native host generation changed/);
  assert.equal(published, false);
});

test("a replacement still waits for an actual-disconnect cleanup", async () => {
  let finishCleanup;
  let replacementStarted = false;
  const cleanup = new Promise((resolve) => {
    finishCleanup = resolve;
  });
  const replacement = settleLifecycleBarrier(cleanup).then(() => {
    replacementStarted = true;
  });

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(replacementStarted, false);
  finishCleanup();
  await replacement;
  assert.equal(replacementStarted, true);
});

test("a due but unexpired refresh failure retains the authenticated proxy", async () => {
  const dueButValid = headerSync();
  const nowMilliseconds = 1_999_500_000;
  let markedDegraded = false;

  assert.equal(needsAutomaticHeaderSync(dueButValid, nowMilliseconds), true);
  assert.equal(
    await deactivateIfHeaderEvidenceExpired(
      dueButValid,
      () => {
        markedDegraded = true;
      },
      Math.floor(nowMilliseconds / 1000)
    ),
    false
  );
  assert.equal(markedDegraded, false);
});

test("hard expiry is enforceable while an unrelated sync remains hung", async () => {
  const hungSync = new Promise(() => {});
  let markedDegraded = false;
  const expiry = deactivateIfHeaderEvidenceExpired(
    headerSync(),
    () => {
      markedDegraded = true;
    },
    2_000_000
  ).then(() => "expired");

  assert.equal(await Promise.race([hungSync, expiry]), "expired");
  assert.equal(markedDegraded, true);
});

test("late status responses cannot cross live proxy generations", () => {
  const active = {
    state: "active",
    reason: null,
    proxyActive: true,
    runtimeSession: "session-a",
    runtimeGeneration: 4,
    policyGeneration: 7,
    securityMaintenanceEpoch: 9
  };
  const degradedLive = {
    ...active,
    state: "degraded",
    reason: "headerReadinessUnavailable"
  };

  assert.equal(sameLiveProxyGeneration(active, { ...active }), true);
  assert.equal(
    sameLiveProxyGeneration(degradedLive, { ...degradedLive }),
    true
  );
  for (const changed of [
    degradedLive,
    { ...active, state: "degraded", proxyActive: false },
    { ...active, runtimeSession: "session-b" },
    { ...active, runtimeGeneration: 5 },
    { ...active, policyGeneration: 8 },
    { ...active, securityMaintenanceEpoch: 10 }
  ]) {
    assert.equal(sameLiveProxyGeneration(active, changed), false);
  }
});

function fakeNativePort() {
  const ports = [];
  return {
    ports,
    chrome: {
      runtime: {
        connectNative() {
          const messageListeners = [];
          const disconnectListeners = [];
          const port = {
            messages: [],
            disconnectCalls: 0,
            onMessage: {
              addListener(listener) {
                messageListeners.push(listener);
              }
            },
            onDisconnect: {
              addListener(listener) {
                disconnectListeners.push(listener);
              }
            },
            postMessage(message) {
              this.messages.push(message);
            },
            disconnect() {
              this.disconnectCalls += 1;
            },
            emitMessage(message) {
              for (const listener of messageListeners) listener(message);
            },
            emitDisconnect() {
              for (const listener of disconnectListeners) listener();
            }
          };
          ports.push(port);
          return port;
        }
      }
    }
  };
}
