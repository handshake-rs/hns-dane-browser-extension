import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import vm from "node:vm";

const nativeHost = resolve("rust/target/debug/hns-chromium-native-host");
const port = 43123;
const pac = runNative(["--print-pac", String(port)]);

const cases = [
  ["welcome", "https://welcome/", true],
  ["sub.welcome", "wss://sub.welcome/socket", true],
  ["sub.unregistered-hns-root", "http://sub.unregistered-hns-root/", true],
  ["example.com", "https://example.com/", true],
  ["example.com", "http://example.com/", true],
  ["example.com", "ws://example.com/socket", true],
  ["xn--bcher-kva.com", "wss://xn--bcher-kva.com/socket", true],
  ["localhost", "https://localhost/", false],
  ["sub.localhost", "https://sub.localhost/", false],
  ["example.onion", "https://example.onion/", false],
  ["127.0.0.1", "https://127.0.0.1/", false],
  ["2001:db8::1", "https://[2001:db8::1]/", false],
  ["", "https:///", false],
  ["contains space", "https://contains space/", false],
  ["dane-test.denuoweb.com", "https://dane-test.denuoweb.com/", true],
  ["example.com", "ftp://example.com/file", false]
];

test("Rust-generated PAC sends every web DNS name to dual-root resolution", () => {
  assert.doesNotMatch(pac, /HNS_ICANN_TLDS|dnsResolve\s*\(/);
  for (const [host, url, shouldProxy] of cases) {
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
