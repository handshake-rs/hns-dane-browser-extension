import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import vm from "node:vm";

const nativeHost = resolve("rust/target/debug/hns-chromium-native-host");
const port = 43123;
const pac = runNative(["--print-pac", String(port)]);

const cases = [
  ["welcome", "hns"],
  ["sub.welcome", "hns"],
  ["sub.unregistered-hns-root", "hns"],
  ["example.com", "icann"],
  ["xn--bcher-kva.com", "icann"],
  ["localhost", "icann"],
  ["sub.localhost", "icann"],
  ["example.onion", "icann"],
  ["127.0.0.1", "icann"],
  ["2001:db8::1", "icann"],
  ["", "search"],
  ["contains space", "search"],
  ["dane-test.denuoweb.com", "nativeGateway"]
];

test("Rust-generated PAC agrees with native Rust classification", () => {
  for (const [host, expectedClass] of cases) {
    const nativeClass = runNative(["--classify", host]).trim();
    assert.equal(nativeClass, expectedClass, host);
    const decision = vm.runInNewContext(
      `${pac}\nFindProxyForURL("", ${JSON.stringify(host)});`
    );
    assert.equal(
      decision,
      expectedClass === "hns" ? `PROXY 127.0.0.1:${port}` : "DIRECT",
      host
    );
  }
});

function runNative(arguments_) {
  const result = spawnSync(nativeHost, arguments_, {
    encoding: "utf8",
    maxBuffer: 1024 * 1024
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}
