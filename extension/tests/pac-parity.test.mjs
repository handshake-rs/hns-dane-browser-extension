import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import vm from "node:vm";

const nativeHost = resolve("rust/target/debug/hns-chromium-native-host");
const port = 43123;
const pac = runNative(["--print-pac", String(port)]);

const cases = [
  ["welcome", "hns", "https://welcome/", true],
  ["sub.welcome", "hns", "wss://sub.welcome/socket", true],
  ["sub.unregistered-hns-root", "hns", "http://sub.unregistered-hns-root/", true],
  ["example.com", "icann", "https://example.com/", true],
  ["example.com", "icann", "http://example.com/", false],
  ["xn--bcher-kva.com", "icann", "wss://xn--bcher-kva.com/socket", true],
  ["localhost", "icann", "https://localhost/", false],
  ["sub.localhost", "icann", "https://sub.localhost/", false],
  ["example.onion", "icann", "https://example.onion/", false],
  ["127.0.0.1", "icann", "https://127.0.0.1/", false],
  ["2001:db8::1", "icann", "https://[2001:db8::1]/", false],
  ["", "search", "https:///", false],
  ["contains space", "search", "https://contains space/", false],
  ["dane-test.denuoweb.com", "icann", "https://dane-test.denuoweb.com/", true]
];

test("Rust-generated PAC applies scheme-aware native DANE admission", () => {
  for (const [host, expectedClass, url, shouldProxy] of cases) {
    const nativeClass = runNative(["--classify", host]).trim();
    assert.equal(nativeClass, expectedClass, host);
    const decision = vm.runInNewContext(
      `${pac}\nFindProxyForURL(${JSON.stringify(url)}, ${JSON.stringify(host)});`
    );
    assert.equal(
      decision,
      shouldProxy ? `PROXY 127.0.0.1:${port}` : "DIRECT",
      `${url} (${host})`
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
