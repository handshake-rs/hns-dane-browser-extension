import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_REQUEST_TIMEOUT_MS,
  MAX_REQUEST_TIMEOUT_MS,
  NativeClient
} from "../src/native-client.js";

test("native client retains the ordinary timeout and permits a bounded sync override", async () => {
  assert.equal(DEFAULT_REQUEST_TIMEOUT_MS, 15_000);
  assert.equal(MAX_REQUEST_TIMEOUT_MS, 15 * 60 * 1000);

  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");
  const request = client.request(
    "syncOnce",
    {},
    { timeoutMs: MAX_REQUEST_TIMEOUT_MS }
  );
  const port = native.ports[0];
  const sent = port.messages[0];
  port.emitMessage({
    schemaVersion: 1,
    requestId: sent.requestId,
    runtimeSession: "session-a",
    eventSequence: 1,
    ok: true,
    result: { status: "synced" }
  });

  assert.deepEqual(await request, { status: "synced" });
  assert.equal(sent.command, "syncOnce");
});

test("native client applies and bounds a per-request timeout", async () => {
  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");

  await assert.rejects(
    client.request("status", {}, { timeoutMs: 5 }),
    /native request timed out: status/
  );
  await assert.rejects(
    client.request("syncOnce", {}, { timeoutMs: MAX_REQUEST_TIMEOUT_MS + 1 }),
    /native request timeout is out of bounds/
  );
});

test("native client ignores delayed callbacks from a disconnected port", async () => {
  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");
  let disconnects = 0;
  client.onDisconnect(() => {
    disconnects += 1;
  });

  const firstRequest = client.request("status");
  const firstPort = native.ports[0];
  const firstEpoch = client.currentConnectionEpoch();
  assert.equal(client.connectionIsCurrent(firstEpoch), true);
  client.disconnect();
  await assert.rejects(firstRequest, /native host disconnected/);
  assert.equal(client.connectionIsCurrent(firstEpoch), false);

  const secondRequest = client.request("status");
  const secondPort = native.ports[1];
  const secondMessage = secondPort.messages[0];
  const secondEpoch = client.currentConnectionEpoch();
  assert.notEqual(secondEpoch, firstEpoch);
  assert.equal(client.connectionIsCurrent(secondEpoch), true);
  assert.equal(client.disconnectIfCurrent(firstEpoch), false);

  firstPort.emitMessage({ invalid: true });
  firstPort.emitDisconnect();

  assert.equal(client.port, secondPort);
  assert.equal(firstPort.disconnectCalls, 1);
  assert.equal(secondPort.disconnectCalls, 0);
  assert.equal(disconnects, 0);
  assert.equal(client.connectionIsCurrent(firstEpoch), false);
  assert.equal(client.connectionIsCurrent(secondEpoch), true);

  secondPort.emitMessage({
    schemaVersion: 1,
    requestId: secondMessage.requestId,
    runtimeSession: "session-b",
    eventSequence: 1,
    ok: true,
    result: { status: "active" }
  });
  assert.deepEqual(await secondRequest, { status: "active" });
});

test("captured connection IDs cannot disconnect a replacement port", async () => {
  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");
  const firstRequest = client.request("status");
  const firstEpoch = client.currentConnectionEpoch();
  client.disconnectIfCurrent(firstEpoch);
  await assert.rejects(firstRequest, /native host disconnected/);

  const secondRequest = client.request("status");
  const secondPort = native.ports[1];
  const secondEpoch = client.currentConnectionEpoch();
  assert.equal(client.disconnectIfCurrent(firstEpoch), false);
  assert.equal(client.connectionIsCurrent(secondEpoch), true);
  assert.equal(secondPort.disconnectCalls, 0);

  const sent = secondPort.messages[0];
  secondPort.emitMessage({
    schemaVersion: 1,
    requestId: sent.requestId,
    runtimeSession: "session-b",
    eventSequence: 1,
    ok: true,
    result: { status: "active" }
  });
  assert.deepEqual(await secondRequest, { status: "active" });
});

test("restart disconnects a pending long sync promptly without touching B", async () => {
  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");
  const sync = client
    .request("syncOnce", {}, { timeoutMs: MAX_REQUEST_TIMEOUT_MS })
    .then(
      () => "resolved",
      (error) => error.message
    );
  const firstPort = native.ports[0];
  const firstEpoch = client.currentConnectionEpoch();

  assert.equal(client.disconnectIfCurrent(firstEpoch), true);
  assert.match(
    await Promise.race([
      sync,
      new Promise((resolve) => setImmediate(() => resolve("still pending")))
    ]),
    /native host disconnected/
  );

  const secondRequest = client.request("status");
  const secondPort = native.ports[1];
  const secondEpoch = client.currentConnectionEpoch();
  firstPort.emitDisconnect();
  assert.equal(client.connectionIsCurrent(secondEpoch), true);
  assert.equal(secondPort.disconnectCalls, 0);

  const sent = secondPort.messages[0];
  secondPort.emitMessage({
    schemaVersion: 1,
    requestId: sent.requestId,
    runtimeSession: "session-b",
    eventSequence: 1,
    ok: true,
    result: { status: "active" }
  });
  assert.deepEqual(await secondRequest, { status: "active" });
});

test("native client disconnects the current port on an invalid message", async () => {
  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");
  let disconnects = 0;
  let disconnectedEpoch = null;
  client.onDisconnect((epoch) => {
    disconnects += 1;
    disconnectedEpoch = epoch;
  });
  const request = client.request("status");
  const port = native.ports[0];
  const expectedEpoch = client.currentConnectionEpoch();

  port.emitMessage({ invalid: true });

  assert.equal(client.port, null);
  assert.equal(port.disconnectCalls, 1);
  assert.equal(disconnects, 1);
  assert.equal(disconnectedEpoch, expectedEpoch);
  await assert.rejects(request, /native host disconnected/);

  port.emitDisconnect();
  assert.equal(disconnects, 1);
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
