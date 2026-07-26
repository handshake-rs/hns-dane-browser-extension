import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_REQUEST_TIMEOUT_MS,
  MAX_REQUEST_TIMEOUT_MS,
  NativeClient
} from "../src/native-client.js";

test("native client retains the ordinary timeout and permits a bounded sync override", async () => {
  assert.equal(DEFAULT_REQUEST_TIMEOUT_MS, 15_000);
  assert.equal(MAX_REQUEST_TIMEOUT_MS, 120_000);

  const native = fakeNativePort();
  const client = new NativeClient(native.chrome, "com.example.native");
  const request = client.request(
    "syncOnce",
    {},
    { timeoutMs: MAX_REQUEST_TIMEOUT_MS }
  );
  const sent = native.messages[0];
  client.handleMessage({
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

function fakeNativePort() {
  const messages = [];
  const port = {
    onMessage: { addListener() {} },
    onDisconnect: { addListener() {} },
    postMessage(message) {
      messages.push(message);
    },
    disconnect() {}
  };
  return {
    messages,
    chrome: {
      runtime: {
        connectNative() {
          return port;
        }
      }
    }
  };
}
