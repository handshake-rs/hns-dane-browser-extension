import assert from "node:assert/strict";
import test from "node:test";

import {
  expectedPoolAuthority,
  fetchPoolStats,
  parsePoolStatsDocument,
  poolStatsUrl
} from "../src/pool-stats.js";

test("expected pool authority is an independent exact canonical HNS label", () => {
  assert.deepEqual(expectedPoolAuthority("pool-1"), {
    name: "pool-1",
    nameHash: "073bfbaf6b85e537a1b109e2367c4198787b4c564944b04c1bb455516052587a"
  });
  for (const name of [
    "",
    "Pool",
    "-pool",
    "pool-",
    "pool_name",
    "pool.name",
    "a".repeat(64)
  ]) {
    assert.throws(() => expectedPoolAuthority(name), /exact lowercase Handshake pool name/);
  }
});

test("pool statistics parser accepts the bounded profile and exposes display fields", () => {
  const snapshot = parsePoolStatsDocument(documentFixture());
  assert.equal(snapshot.verified, false);
  assert.equal(snapshot.mode, "Mining");
  assert.equal(snapshot.connectedMiners, 2);
  assert.equal(snapshot.connectedMeshPeers, 3);
  assert.equal(snapshot.acceptedShares, 5n);
  assert.equal(snapshot.endpointSequence, 1n);
  assert.equal(snapshot.sequence, 9n);
});

test("pool statistics parser rejects trailing and oversized inputs", () => {
  const trailing = documentFixture();
  trailing.snapshot += "00";
  assert.throws(() => parsePoolStatsDocument(trailing), /Trailing/);

  const oversized = documentFixture();
  oversized.service_authorization = "aa".repeat(1025);
  assert.throws(() => parsePoolStatsDocument(oversized), /service authorization/);

  const zeroEndpointSequence = documentFixture();
  const bytes = Buffer.from(zeroEndpointSequence.snapshot, "hex");
  bytes.fill(0, 71, 79);
  zeroEndpointSequence.snapshot = bytes.toString("hex");
  assert.throws(() => parsePoolStatsDocument(zeroEndpointSequence), /snapshot fields/);
});

test("pool endpoint normalization strips paths and rejects credentials", () => {
  assert.equal(
    poolStatsUrl("https://pool.example/status?q=1#x").href,
    "https://pool.example/api/v1/pool-stats"
  );
  assert.throws(() => poolStatsUrl("https://user:pass@pool.example"), /credentials/);
  assert.throws(() => poolStatsUrl("file:///tmp/feed"), /HTTP or HTTPS/);
});

test("pool fetch fixes expected identity before contacting the endpoint", async () => {
  let request;
  const result = await fetchPoolStats(
    "https://pool.example",
    "pool-1",
    async (url, options) => {
      request = { url, options };
      return new Response(JSON.stringify(documentFixture()), {
        headers: { "content-type": "application/json" }
      });
    }
  );
  assert.equal(request.url.href, "https://pool.example/api/v1/pool-stats");
  assert.equal(request.options.credentials, "omit");
  assert.equal(request.options.redirect, "error");
  assert.equal(result.expectedAuthority.name, "pool-1");
  assert.equal(result.snapshot.tipHeight, 100);

  let contacted = false;
  await assert.rejects(
    fetchPoolStats("https://pool.example", "Pool-1", async () => {
      contacted = true;
      throw new Error("must not be reached");
    }),
    /exact lowercase Handshake pool name/
  );
  assert.equal(contacted, false);
});

function documentFixture() {
  const parts = [];
  const u8 = (value) => parts.push(value);
  const little = (value, length) => {
    let remaining = BigInt(value);
    for (let index = 0; index < length; index += 1) {
      parts.push(Number(remaining & 0xffn));
      remaining >>= 8n;
    }
  };
  const fixed = (value, length) => parts.push(...new Array(length).fill(value));
  u8(1);
  little(0x5b6ef2d3, 4);
  little(0xff00, 2);
  fixed(1, 32);
  fixed(2, 32);
  little(1, 8);
  little(9, 8);
  little(1_700_000_000, 8);
  little(1_700_000_060, 8);
  fixed(3, 32);
  little(100, 4);
  fixed(4, 32);
  little(2, 4);
  little(3, 4);
  little(5, 8);
  little(1, 8);
  little(0, 4);
  u8(0);
  u8(1);
  u8(0);
  u8(1);
  u8(0x30);
  return {
    schema: "meshmine-pool-stats-v1",
    service_name: "pool-stats",
    profile_id: 0xff00,
    service_authorization: "aa",
    endpoint_delegation: "bb",
    snapshot: Buffer.from(parts).toString("hex")
  };
}
