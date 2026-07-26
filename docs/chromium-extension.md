# Chromium Extension and Native Host

## Scope

The Manifest V3 extension routes every ordinary DNS hostname used by
HTTP/HTTPS/WS/WSS through an authenticated IPv4-loopback HTTP/CONNECT proxy.
Rust generates syntax-only PAC schema 3. It uses no IANA suffix list and does
no resolver work; special-use names, malformed names, non-web schemes, and IP
literals remain `DIRECT` and are independently rejected if they reach the
native DANE-browser admission mode.

The native request boundary resolves the complete hostname independently
through HNS and ICANN. It retains one complete plan per root, including
A/AAAA/CNAME, HTTPS/SVCB, the effective service port and transport, and TLSA:

- HNS only selects HNS;
- ICANN only selects ICANN;
- matching plans are convergent;
- different plans apply a persistent sticky binding when one exists, otherwise
  the first-use ICANN default;
- authenticated absence in both roots is a resolution failure;
- any timeout, bogus or indeterminate DNSSEC result, malformed response, or
  other root failure makes classification indeterminate and fails closed.

The IANA snapshot may remain an internal scheduling hint, but it is not an
authority boundary and cannot select or bypass a namespace.

Each root plan queries and validates both A and AAAA, requires their
alias/terminal-owner paths to agree, and retains the complete deterministic
endpoint set. A whole-name NXDOMAIN can terminate that root; NODATA for one
family cannot hide the other. The Gateway dials only the selected plan and
performs no later resolver lookup that could introduce an omitted address.
Consequently, roots with matching A but different AAAA results are divergent.

Persistent namespace selection treats HTTPS/WSS and HTTP/WS as paired security
origins for the same host and effective port, so a page and its WebSocket
cannot select different roots merely because their wire schemes differ. The
actual scheme remains in each plan and decision fingerprint.

The native host owns sync, HNS proof validation, delegated DNSSEC, TLSA/DANE,
origin transport, namespace bindings, proxy credentials, certificate issuance,
policy revisions, and monotonic runtime status. JavaScript owns only browser
APIs, native-message transport, bounded settings, and UI.

No production path sends an HNS lookup to a public recursive resolver or
accepts WebPKI for a selected HNS HTTPS plan. For a selected ICANN HTTPS/WSS
plan, Rust derives the TLSA owner from the effective origin port and transport,
queries through validating ICANN DoH, and applies one closed decision:

- a securely present supported TLSA RRset is enforced;
- authenticated TLSA absence uses WebPKI;
- an unsigned/insecure delegation ignores all unsigned TLSA bytes and uses
  WebPKI;
- bogus or indeterminate DNSSEC, resolver failure, and malformed responses
  fail closed and are never converted to absence.

HTTP/1.1, HTTP/2, and WSS use `_port._tcp.host`; HTTPS/SVCB-selected HTTP/3
uses `_port._udp.host`. Status calls this path `DANE via ICANN DoH`.

ICANN plan freshness is bounded by the earliest expiry across every retained
address, alias, HTTPS/SVCB, denial, and TLSA observation, including RRSIG
expiration. Because the legacy HNS delegated resolver does not yet expose
exact RR/RRSIG expiry, a plan that uses delegated HNS DNS is conservatively
reusable for at most one second; direct Urkel-only evidence retains its
anchor-bounded lifetime.

The old stateless-DANE parser/transport capability is not an active Chromium
feature in this checkpoint. The atomic dual-root plan requires live
DNSSEC-secure TLSA for selected HNS HTTPS and fails closed before certificate
evidence can authorize a TLS connection. Re-enabling stateless DANE requires a
typed trust policy in the shared plan contract and remains a release blocker
for that feature claim.

## Rust-owned security results

The loopback proxy observes typed internal response metadata before removing
the private `X-HNS-*` fields from the browser-visible response. The native
host converts that observation into security-result schema 2. Each result is
bound to the exact runtime session, runtime generation, policy generation, and
one monotonic event sequence. A proxy stop or policy restart clears all
retained results before revoking the old proxy generation.

The result reports the five-way namespace outcome, selected root and reason,
each root's state, network and chain-currentness anchor, actual selected DNS
transport, local HNS-proof state, local DNSSEC state, TLSA state, DANE state,
peer/proxy/target identities where applicable, privacy policy, registry
profile, and fallback/separation outcomes. Divergence is visible in the popup.
A relayed result continues to name the delegated nameserver as the authority
and identifies the relay only as an intermediary.

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
exact-host, short-lived leaf certificates after native DNS-name admission.
The extension will not activate its PAC until the platform trust command
succeeds and the installer writes the matching SHA-256 marker.

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
- PAC schema 3 sends every ordinary HTTP/HTTPS/WS/WSS DNS hostname to the
  native gateway, so main frames, redirects, subresources, Service Workers,
  downloads, and WebSockets share the same dual-root request-boundary policy.
- Namespace decision fingerprints partition connection pools, TLS verifier and
  resumption state, and Alt-Svc state. Records from different roots are never
  mixed into one plan.
- The live HNS delegated resolver follows the shared plan's direct-authority
  order: UDP, TCP fallback, authenticated authoritative DoH, then any enabled
  P2P DNS-relay fallback.
- HTTPS/WSS and HTTP/WS share their persistent namespace binding at equal host
  and effective port, while retaining distinct request-plan fingerprints.
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
- The existing P2P DNS-relay checkbox remains an independent requester opt-in
  in this extension schema. Rust maps it to the canonical shared policy's
  `Disabled` or direct-authority-first `Auto` requester mode. This browser
  product does not implement provider service: every opaque-relay,
  output-node, target, market, and HNSR provider role is explicitly disabled
  regardless of requester settings. P2P ODoH, HNSR, privacy downgrade, and
  draft wire profiles remain fail-closed rather than silently downgrading.
- A policy update is written to extension storage only after the native host
  has accepted it and returned an active proxy generation.

## Qualification evidence

The 2026-07-26 shared-policy checkpoint passed:

```sh
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml --workspace
cargo +1.92.0 clippy --locked --manifest-path rust/Cargo.toml \
  --workspace --all-targets -- -D warnings
cargo +1.92.0 fmt --manifest-path rust/Cargo.toml --all -- --check
python3 -m unittest tests.test_cargo_git_policy tests.test_ci_changed_targets
python3 scripts/verify_cargo_git_policy.py
python3 scripts/generate-third-party-notices.py --check
npm run check:extension
```

The final Chromium checkpoint passed 48 gateway, 152 loopback-proxy, 154
browser-runtime, 14 native-host, 65 resolver, and 51 transport tests. The
extension gate passed all 15 Node tests, including isolated Linux
install/uninstall, Windows registration/removal coverage, PAC parity, native
messaging, stale-generation rejection, health-generation preservation, and
the unpacked MV3 build. Socket-backed Rust tests require permission to bind
loopback in a restricted sandbox; they passed with that local access. The full
Chromium workspace also passed warning-denied Clippy and rustfmt.

The historical cross-platform `./scripts/check.sh` wrapper is not a release
gate for this extraction because it still contains mobile packaging and ABI
workflows. Its exact Cargo Git-source and notice checks are current, but the
Chromium-specific commands above remain the authoritative local checkpoint.
The active notice generator inventories the locked native-host closures for
Linux, macOS, and Windows. `extension/THIRD_PARTY_NOTICES.txt` is checksummed,
copied into the unpacked extension, and installed beside the native host.

## Remaining integration boundary

This clone still contains its historical `hns-browser-runtime`,
`hns-gateway`, and `hns-transport` implementations. TLSA owner derivation,
validating-DoH trust decisions, dual-root namespace selection, and the typed
requester/provider transport policy now consume the canonical
`hns-icann-dane`, `hns-namespace-resolution`, and `hns-resolution-policy`
crates through immutable Git dependencies on
`handshake-rs/hns-dane-engine` commit
`127b9ad55852df00b4df40826517715048dc3571`. The surrounding gateway,
resolver adapter, and transport integration remain historical clone code
pending broader engine consolidation.
The separately coordinated `hns-dane-engine` repository now defines the
canonical session-bound browser authority and bridge-authorization boundary.
This checkpoint aligns Chromium observability with its session, runtime
generation, policy generation, and event-sequence invariants, but does not
claim that the duplicate runtime has been replaced or that the canonical
contract is a registry-published dependency. That consolidation, P2P ODoH,
HNSR, and non-stable experimental wire profiles remain fail-closed work.

The retained Android/iOS source and FFI directories are historical and excluded
from the Cargo workspace/release graph. Mobile dual-root and ICANN-DANE
qualification belongs to the separate canonical mobile repository; this
Chromium checkpoint makes no all-browser coverage claim.

## Release gates still requiring target hardware

Linux unit and isolated installer tests run in this repository. Before a
signed release, run the installer, browsing, restart, upgrade, and uninstaller
matrix on supported Windows and macOS versions and on current stable releases
of all six browsers. Store signing, review, and published extension IDs are
distribution gates and are intentionally not fabricated by the source build.
