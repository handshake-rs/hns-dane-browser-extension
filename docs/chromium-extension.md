# Chromium Extension and Native Host

## Scope

The Manifest V3 extension routes only names classified as Handshake through an
authenticated IPv4-loopback HTTP/CONNECT proxy. Rust generates the PAC from
the same vendored IANA and special-use snapshots used at the proxy admission
boundary. ICANN, special-use, search, and IP-literal targets remain `DIRECT`
and are rejected if they reach the HNS-only proxy anyway.

The native host owns sync, HNS proof validation, delegated DNSSEC, TLSA/DANE,
origin transport, proxy credentials, certificate issuance, policy revisions,
and monotonic runtime status. JavaScript owns only browser APIs, native-message
transport, bounded settings, and UI.

No production path sends an HNS name to a public recursive resolver or accepts
WebPKI for HNS HTTPS. ICANN traffic remains on the browser's normal DNS and
WebPKI path.

## Rust-owned security results

The loopback proxy observes typed internal response metadata before removing
the private `X-HNS-*` fields from the browser-visible response. The native
host converts that observation into security-result schema 1. Each result is
bound to the exact runtime session, runtime generation, policy generation, and
one monotonic event sequence. A proxy stop or policy restart clears all
retained results before revoking the old proxy generation.

The result reports the network and chain-currentness anchor, actual selected
DNS transport, local HNS-proof state, local DNSSEC state, TLSA state, DANE
state, peer/proxy/target identities where applicable, privacy policy, registry
profile, and fallback/separation outcomes. A relayed result continues to name
the delegated nameserver as the authority and identifies the relay only as an
intermediary.

Only a bounded 32-result in-memory diagnostic window and the latest main-frame
result are retained. The native host deliberately discards the raw resolution
trace because it can contain a complete URL and certificate material. The
popup displays only the sanitized Rust result using fixed labels. Before
rendering, the service worker requires exact session, runtime-generation, and
policy-generation matches; stale results render as unavailable.

The periodic health alarm requests status from the existing generation. It
does not restart a healthy proxy. Reconnection alone creates a new generation,
new credentials, and a new PAC installation.

## Build

Required development tools are Rust 1.92.0 and Node.js 22 or later.

```sh
cargo +1.92.0 build --release --locked \
  --manifest-path rust/Cargo.toml \
  -p hns-chromium-native-host
npm run check:extension
```

The unpacked extension is written to `dist/chromium-extension`. The build does
not bundle a native executable or a trust anchor into the extension.

## Install

First load `dist/chromium-extension` through the target browser's extensions
developer page and copy its 32-character extension ID. Close every selected
browser before registering the native host and local CA.

Linux and macOS:

```sh
extension/install/install.sh \
  --extension-id abcdefghijklmnopabcdefghijklmnop \
  --browser all
```

Windows PowerShell:

```powershell
extension\install\install.ps1 `
  -ExtensionId abcdefghijklmnopabcdefghijklmnop `
  -Browser all
```

Repeat `--extension-id` on Unix, or pass a PowerShell string array, when store
and sideloaded builds use different IDs. `--browser` can be repeated with any
of `chrome`, `chromium`, `edge`, `brave`, `vivaldi`, and `opera`.

The Unix installer requires `certutil` on Linux (`libnss3-tools` on
Debian/Ubuntu or `nss-tools` on Fedora). It uses the current user's NSS
database. macOS uses the user's login keychain. Windows uses the current
user's Root store. No system-wide native-host registration is performed.

Installing a root CA is security-sensitive. This CA is generated independently
for each installation, its P-256 private key is stored only in the native
host's mode-0600 data bundle on Unix, and the Rust issuer creates only
exact-host, short-lived leaf certificates after HNS admission. The extension
will not activate its PAC until the platform trust command succeeds and the
installer writes the matching SHA-256 marker.

The browser registration locations follow the native-messaging host contracts
published by [Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging),
[Microsoft Edge](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging),
and [Opera](https://help.opera.com/en/extensions/message-passing/). Brave and
Vivaldi use their Chromium user-profile `NativeMessagingHosts` directories.

## Uninstall

Close all selected browsers, then run:

```sh
extension/install/uninstall.sh --browser all
```

or:

```powershell
extension\install\uninstall.ps1 -Browser all
```

The uninstaller removes only this host's per-browser registrations, its exact
per-install trust anchor, native executable, CA key material, marker, chain
state, cache, and other extension runtime data. The browser removes the
extension-owned proxy setting when the extension is disabled or uninstalled;
the service worker also clears it during orderly suspension.

## Security and recovery invariants

- Native messages use schema version 1, bounded request IDs, bounded
  native-endian frames, one active port, and monotonic event sequence numbers.
- Windows switches inherited standard streams to binary mode before reading a
  frame.
- The generated PAC contains no `dnsResolve`, socket, DoH, or fallback path.
- Proxy authentication is accepted only for the active `127.0.0.1` generation.
- CA-not-installed, host disconnect, malformed response, unsupported policy,
  PAC installation failure, and proxy restart all clear browser proxy state.
- Service-worker restart reconnects through `hello` and starts a fresh proxy
  generation with fresh credentials.
- A live health check preserves its current generation; stale or malformed
  status clears the PAC and credentials before reconnecting.
- Security UI and diagnostics consume only sanitized Rust results from the
  current session/runtime/policy tuple. JavaScript never infers cryptographic
  state from browser-visible headers.
- Historical public-HNS-DoH settings are removed without granting P2P relay
  consent.
- P2P DNS relay is opt-in. P2P ODoH, HNSR, and draft wire profiles are exposed
  as policy vocabulary but currently fail closed in Rust rather than silently
  downgrading.

## Qualification evidence

The 2026-07-25 portable checkpoint passed:

```sh
cargo +1.92.0 test --locked --offline \
  --manifest-path rust/Cargo.toml \
  -p hns-browser-runtime -p hns-chromium-native-host

cargo +1.92.0 clippy --locked --offline \
  --manifest-path rust/Cargo.toml \
  -p hns-browser-runtime -p hns-chromium-native-host \
  --all-targets -- -D warnings

npm run check:extension
```

The focused Rust gate passed 128 browser-runtime and 10 native-host unit tests.
The extension gate passed 11 Node tests, including isolated Linux
install/uninstall, Windows registration/removal coverage, PAC parity, native
messaging, stale-generation rejection, health-generation preservation, and
the unpacked MV3 build. Socket-backed Rust tests require permission to bind
loopback in a restricted sandbox; they passed when run with that local access.
The full Rust workspace test and strict-clippy gates also passed.

The `./scripts/check.sh` wrapper currently stops at its pre-existing
third-party-notice preflight: Cargo fingerprints are stale and the locked
Android `androidx.activity:activity-ktx:1.13.0` POM is not present in the local
Gradle cache, so the notice generator cannot refresh the checked-in asset
offline. No notice freshness success is claimed by this checkpoint.

## Remaining integration boundary

This clone still contains its historical `hns-browser-runtime` implementation.
The separately coordinated `hns-dane-engine` repository now defines the
canonical session-bound browser authority and bridge-authorization boundary.
This checkpoint aligns Chromium observability with its session, runtime
generation, policy generation, and event-sequence invariants, but does not
claim that the duplicate runtime has been replaced by a published canonical
engine dependency. That consolidation, P2P ODoH, HNSR, and non-stable
experimental wire profiles remain fail-closed work.

## Release gates still requiring target hardware

Linux unit and isolated installer tests run in this repository. Before a
signed release, run the installer, browsing, restart, upgrade, and uninstaller
matrix on supported Windows and macOS versions and on current stable releases
of all six browsers. Store signing, review, and published extension IDs are
distribution gates and are intentionally not fabricated by the source build.
