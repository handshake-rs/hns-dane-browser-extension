import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { projectWalletAbiStatus } from "../src/wallet-status.js";

const cargoTargetDir = resolve(
  process.env.CARGO_TARGET_DIR ??
    JSON.parse(
      execFileSync(
        "cargo",
        [
          "+1.92.0",
          "metadata",
          "--no-deps",
          "--format-version",
          "1",
          "--manifest-path",
          "rust/Cargo.toml"
        ],
        { encoding: "utf8" }
      )
    ).target_directory
);
const nativeHost = join(
  cargoTargetDir,
  "debug",
  process.platform === "win32"
    ? "hns-chromium-native-host.exe"
    : "hns-chromium-native-host"
);
const missingWalletArtifactCode =
  process.platform === "win32"
    ? "walletArtifactPlatformUnsupported"
    : "walletArtifactMissing";

test("native host exchanges bounded framed schema and monotonic events", () => {
  const dataDir = mkdtempSync(join(tmpdir(), "hns-native-message-"));
  try {
    const input = Buffer.concat([
      frame({ command: "hello", schemaVersion: 1, requestId: "hello-1" }),
      frame({ command: "status", schemaVersion: 1, requestId: "status-1" }),
      frame({
        command: "walletProviderCapabilities",
        schemaVersion: 1,
        requestId: "wallet-1",
        providerAbiVersion: 2
      }),
      frame({ command: "shutdown", schemaVersion: 1, requestId: "shutdown-1" })
    ]);
    const result = spawnSync(
      nativeHost,
      ["--data-dir", dataDir, "--network", "regtest"],
      { input, maxBuffer: 1024 * 1024 }
    );
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr?.toString() ?? "native host failed");
    const responses = decodeFrames(result.stdout);
    assert.equal(responses.length, 4);
    assert.equal(responses[0].ok, true);
    assert.equal(responses[0].schemaVersion, 1);
    assert.equal(responses[0].requestId, "hello-1");
    assert.equal(responses[0].eventSequence, 1);
    assert.equal(responses[0].result.capabilities.chromiumSecurityResults, true);
    assert.equal(responses[0].result.capabilities.meshminePoolStatsVerifierCore, true);
    assert.equal(
      responses[0].result.capabilities.meshminePoolStatsVerifierSchemaVersion,
      1
    );
    assert.equal(responses[0].result.capabilities.meshmineVerifiedPoolStats, false);
    assert.equal(responses[0].result.capabilities.handshakeWalletProvider, false);
    assert.equal(responses[0].result.walletAbi.available, false);
    assert.equal(responses[0].result.walletAbi.runtimeNegotiated, false);
    assert.equal(
      responses[0].result.walletAbi.serviceTransportAvailable,
      false
    );
    assert.equal(
      responses[0].result.walletAbi.providerAuthorityContextAvailable,
      false
    );
    assert.notEqual(
      projectWalletAbiStatus(responses[0].result.walletAbi).reason,
      "walletStatusInvalid"
    );
    assert.equal(responses[1].requestId, "status-1");
    assert.equal(responses[1].eventSequence, 2);
    assert.equal(responses[1].result.headerSync.network, "regtest");
    assert.equal(responses[1].result.headerSync.bestHeight, 0);
    assert.equal(
      responses[1].result.headerSync.targetEvidenceValidUntilUnix,
      null
    );
    assert.equal(responses[1].result.headerSyncUnavailableReason, null);
    assert.equal(responses[1].result.walletAbi.available, false);
    assert.equal(
      responses[1].result.walletAbi.serviceTransportAvailable,
      false
    );
    assert.equal(responses[1].result.walletAbi.runtimeNegotiated, false);
    assert.equal(
      responses[1].result.walletAbi.providerAuthorityContextAvailable,
      false
    );
    assert.notEqual(
      projectWalletAbiStatus(responses[1].result.walletAbi).reason,
      "walletStatusInvalid"
    );
    assert.equal(responses[2].requestId, "wallet-1");
    assert.equal(responses[2].ok, false);
    assert.equal(responses[2].error.code, missingWalletArtifactCode);
    assert.equal(responses[3].requestId, "shutdown-1");
    assert.equal(responses[3].eventSequence, 4);
    assert.equal(responses[0].runtimeSession, responses[3].runtimeSession);
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
});

function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length);
  return Buffer.concat([prefix, body]);
}

function decodeFrames(buffer) {
  const values = [];
  let offset = 0;
  while (offset < buffer.length) {
    assert.ok(offset + 4 <= buffer.length);
    const length = buffer.readUInt32LE(offset);
    offset += 4;
    assert.ok(length > 0 && length <= 256 * 1024);
    assert.ok(offset + length <= buffer.length);
    values.push(JSON.parse(buffer.subarray(offset, offset + length).toString("utf8")));
    offset += length;
  }
  return values;
}
