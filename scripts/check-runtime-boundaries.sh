#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mobile_paths=(
  android
  ios
  rust/crates/android-ffi
  rust/crates/ios-ffi
  dist/app-store
  dist/play-store
  docs/assets/branding
)
if tracked_mobile="$(git ls-files -- "${mobile_paths[@]}")" && [[ -n "$tracked_mobile" ]]; then
  echo "ERROR: mobile product paths remain tracked in the Chromium repository." >&2
  printf '%s\n' "$tracked_mobile" >&2
  exit 1
fi

for crate in hns-chromium-platform-runtime hns-loopback-proxy; do
  dependency_tree="$(cargo +1.92.0 tree --locked \
    --manifest-path rust/Cargo.toml \
    --package "$crate" \
    --prefix none)"
  if grep -Eq '^(android-ffi|ios-ffi|jni(-sys)?) v[0-9]' <<<"$dependency_tree"; then
    echo "ERROR: $crate depends on a removed mobile or JNI crate." >&2
    exit 1
  fi
done

if matches="$(rg -n \
  --glob 'Cargo.toml' \
  --glob '*.rs' \
  '(^|[^[:alnum:]_])(jni::|JNIEnv|JNIEXPORT|JNICALL|Java_[[:alnum:]_]+)([^[:alnum:]_]|$)|extern[[:space:]]+"system"' \
  rust/crates/hns-chromium-platform-runtime \
  rust/crates/hns-loopback-proxy || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: the Chromium runtime contains a JNI boundary." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

legacy_runtime_pattern='BrowserNameClass|BrowserHostClass|classify_browser_name|classify_browser_host|browser_hns_root_label|browser_websocket_scope_policy_script|chromium_hns_only_pac_script|start_hns_only_proxy|start_whole_browser_proxy|WholeBrowserIcannNetwork|BrowserProxyAdmission'
if matches="$(rg -n "$legacy_runtime_pattern" \
  rust/crates/hns-chromium-platform-runtime/src/lib.rs || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: a removed static-IANA or mobile runtime surface remains." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

legacy_proxy_pattern='ProxyRoutingMode::(HnsOnly|WholeBrowser)|ProxyConfig::(hns_only|whole_browser)|IcannNetwork'
if matches="$(rg -n "$legacy_proxy_pattern" \
  rust/crates/hns-loopback-proxy/src \
  rust/crates/hns-chromium-platform-runtime/src/lib.rs || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: a removed HnsOnly/WholeBrowser forwarding surface remains." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

runtime_source="rust/crates/hns-chromium-platform-runtime/src/lib.rs"
native_host_source="rust/crates/hns-chromium-native-host/src/lib.rs"
for required in \
  'pub fn chromium_dane_pac_script' \
  'pub fn start_dane_browser_proxy_with_certificate_authority_and_observer' \
  'ProxyConfig::dane_browser'; do
  if ! grep -Fq "$required" "$runtime_source"; then
    echo "ERROR: active DaneBrowser runtime boundary is missing: $required" >&2
    exit 1
  fi
done
if ! grep -Fq '.start_dane_browser_proxy_with_certificate_authority_and_observer(' \
  "$native_host_source"; then
  echo "ERROR: the native host does not start the active DaneBrowser proxy." >&2
  exit 1
fi

active_pac="$(sed -n \
  '/^pub fn chromium_dane_pac_script/,/^fn pac_lookup_object/p' \
  "$runtime_source")"
if matches="$(rg -n 'HNS_ICANN_TLDS|dnsResolve[[:space:]]*\(' \
  <<<"$active_pac" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: the active Chromium PAC still classifies authority from an IANA list or DNS lookup." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi
if matches="$(rg -n 'browser_icann_tld_snapshot[[:space:]]*\(' \
  "$runtime_source" || true)" && [[ -n "$matches" ]]; then
  echo "ERROR: the Chromium runtime still calls the static IANA classifier snapshot." >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

if rg -n 'id="hnsr"|fields[.]hnsr|HNSR_MODES' \
  extension/src/options.html extension/src/options.js extension/src/policy.js; then
  echo "ERROR: the Chromium UI exposes the unimplemented HNSR role." >&2
  exit 1
fi
if ! grep -Fq 'p2pDnsRelay: false' extension/src/policy.js ||
  ! grep -Fq 'p2p_dns_relay: false' "$native_host_source"; then
  echo "ERROR: explicit browser requester consent is no longer the default." >&2
  exit 1
fi

echo "Chromium-only runtime, PAC, requester-consent, and proxy boundaries passed."
