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
- Historical public-HNS-DoH settings are removed without granting P2P relay
  consent.
- P2P DNS relay is opt-in. P2P ODoH, HNSR, and draft wire profiles are exposed
  as policy vocabulary but currently fail closed in Rust rather than silently
  downgrading.

## Release gates still requiring target hardware

Linux unit and isolated installer tests run in this repository. Before a
signed release, run the installer, browsing, restart, upgrade, and uninstaller
matrix on supported Windows and macOS versions and on current stable releases
of all six browsers. Store signing, review, and published extension IDs are
distribution gates and are intentionally not fabricated by the source build.
