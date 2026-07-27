# Chromium Extension and Native Host

## Scope

The Manifest V3 extension and Rust native host support Chrome, Chromium, Edge,
Brave, Vivaldi, and Opera on Linux, macOS, and Windows.

Rust generates syntax-only PAC schema 3. Every ordinary DNS hostname used by
HTTP, HTTPS, WS, or WSS is sent to an authenticated IPv4-loopback proxy.
Because routing occurs at the browser proxy boundary, the same policy covers
initial pages, redirects, subresources, Service Workers, downloads, and
WebSockets.

The PAC does not classify namespaces and contains no IANA suffix decision,
resolver call, socket, DoH request, or fallback. Rust resolves the complete
hostname through HNS and ICANN, then records HNS-only, ICANN-only, convergent,
divergent, neither, or indeterminate. The IANA snapshot is a hint only. Bogus
or indeterminate DNSSEC fails closed and is never converted to absence.

For a selected ICANN HTTPS or WSS plan, Rust derives and validates the TLSA
owner for the effective port and transport. Secure supported TLSA is enforced;
authenticated denial or an unsigned delegation uses WebPKI; bogus DNSSEC,
malformed data, and resolver failure fail closed. TCP applications use
`_<port>._tcp.<host>` and HTTPS/SVCB-selected HTTP/3 uses
`_<port>._udp.<host>`. The UI describes this as `DANE via ICANN DoH`.

The five canonical browser contracts are pinned to
`handshake-rs/hns-dane-engine` revision
`7f7bb8fa100c2393f2cd5a64c64bf5e20a0f3ab5`.

## Header currentness and UI

The toolbar popup reports the latest page first and places the separate global
Handshake Header chain panel beneath it:

- **Validated header tip** is the highest locally proof-of-work-validated
  canonical header.
- **Corroborated target** is the outlier-resistant target derived from recent
  header-sync-owned observations in at least three independent peer address
  groups. Proof retrieval, relay use, and other transport liveness cannot
  refresh this evidence.
- **Highest peer claim** and **Schedule estimate** are diagnostic only. Neither
  can authorize a browser decision.
- **Page proof anchor** is the canonical header against which the latest
  page's HNS name proof was checked. It is not the global sync tip.

`Current` means that the validated tip is no more than two blocks behind the
corroborated target. The 144-block resource-proof cache window is retained for
reorganization-safe cache invalidation only; it is not a freshness allowance.
If fresh corroboration is unavailable, currentness is `Unknown` and HNS
resolution fails closed.

`Sync headers now` performs one explicit synchronization without rotating the
proxy generation or changing policy. A failed sync is reported in the header
section and does not disable an otherwise active proxy. Background sync is
stale-aware and limited to one attempt per ten-minute target interval; the
five-minute runtime health check reads local status only, and opening the popup
does not contact peers.

## Security-result boundary

The native host owns synchronization, Handshake proof validation, delegated
DNSSEC, ICANN validating DoH, TLSA/DANE, namespace bindings, proxy
credentials, certificate issuance, policy revisions, and monotonic runtime
status. JavaScript owns browser APIs, native-message framing, bounded settings,
and presentation.

Every request uses one admission stamp bound to its exact runtime session,
runtime generation, policy generation, and monotonic event. Response heads,
streamed and file-backed bodies, downloads, and tunnels must still hold that
authority at publication. Stop, policy update, readiness loss, and generation
rotation invalidate earlier work.

The proxy removes private internal metadata before sending a response to the
browser. The native host publishes only a sanitized, checked security result.
The extension requires an exact session/generation/policy/event match before
rendering it. A newer observation without exact canonical evidence clears the
older result and reports unavailable rather than synthesizing state.

The popup is scoped to the active tab's current Chromium `documentId`, not to
a process-global "last request." A bounded in-memory session map joins
`webRequest` main-frame completion to `webNavigation` document lifecycle.
Back/forward cache and History API changes may retain only the immutable
receipt already bound to that same document. A new document restored from the
HTTP cache may reuse a receipt only for the exact URL, runtime tuple, and
header-maintenance epoch that originally produced it. Missing, mismatched, or
concurrently ambiguous evidence is reported unavailable.

Header maintenance invalidates pending navigation correlation and exact-URL
cache reuse. It does not rewrite history: a document that was already
committed may continue to show its immutable receipt, explicitly labeled as
predating the latest header sync. A later document must obtain fresh
correlated evidence.

For an ICANN origin where Rust authenticates a defined WebPKI fallback, the
CONNECT tunnel remains end-to-end between Chromium and the origin. Rust emits
a bounded, sanitized decision with no HTTP status and no main-frame claim. The
extension can bind that decision to a document only after Chromium reports a
successful main-frame completion for the exact HTTPS host and port, runtime
tuple, and native security-maintenance epoch. A retained same-host decision
may describe Chromium reusing its existing tunnel; multiple non-equivalent
fingerprint/evidence matches fail unavailable. The popup labels this
provenance and states that Chromium, not the local Rust proxy, owns end-to-end
WebPKI.

That branch connects only to the explicit public IP and effective TCP port in
Rust's selected namespace plan; it never resolves the origin through system
DNS. The local CA is not prepared or presented, so Chromium's certificate
viewer shows the actual origin chain. Independent bounded upload/download
halves avoid throttling one direction behind an idle poll in the other.
Failure to open the selected socket, publish its checked status, or satisfy
the WebPKI-plan invariants returns a pre-TLS CONNECT failure and cannot fall
back to local certificate issuance. HNS DANE and secure ICANN TLSA remain on
the Rust TLS-termination path.

The native `securityMaintenanceEpoch` is authoritative. The extension never
predicts it: every header-sync attempt, successful or failed, is followed by a
native status read before cache or tunnel-decision reuse can resume. This
closes the interval where a sync may already have invalidated native evidence
but a browser cache completion arrives against older extension state.

When the verified HNS name proof itself contains all origin data, a successful
page has no delegated UDP/TCP/DoH/P2P DNS trace. Shared status records that
case as `LocalHnsProof`, an honest non-network provenance that is never a
transport-plan candidate. The popup renders it as `Local verified HNS proof`
instead of discarding the otherwise complete main-frame result.

## Browser policy

The options page has one experimental P2P DNS-relay requester checkbox:

- `false` maps to requester policy `Disabled`;
- `true` maps to direct-authority-first requester policy `Auto`.

It is explicit browser consent to consume an untrusted DNS transport. It does
not enable opaque relay serving, an output node, or any other provider
service. This Chromium product advertises no such service and all provider
roles are off.

HNSR is not offered in the UI. HNSR, P2P ODoH, unsupported privacy
downgrades, and draft wire profiles remain unimplemented and fail closed.
Historical public-HNS-DoH settings are removed without granting relay
requester consent.

The recursive HNS DoH recovery field is a new, independent opt-in. It is blank
by default and historical resolver values are never migrated into it. The
example `https://hnsdoh.com/dns-query` names the HNSDoH pool; Zorro is a
listed pool node, not a separate documented HTTPS URL. The example is not
prefilled or contacted automatically.

For each proof-backed HNS delegation, Rust uses this order:

1. direct authoritative UDP/TCP;
2. proof-anchored owner authoritative DoH on HTTPS 443 when published;
3. the requester-only P2P relay, if separately enabled;
4. the configured recursive HNS DoH endpoint, if separately enabled; then
5. fail closed.

The configured endpoint is eligible only for `DnsTransport` or a typed,
positively confirmed `Port53InterceptionDetected`. DNS response codes, invalid
or malformed responses, DNSSEC failure (including relay DNSSEC failure), and
missing or stale local chain/proof evidence never open it. Raw RFC 8484
responses enter the ordinary local HNS DNSSEC, HTTPS/SVCB, TLSA, and DANE
validation path; resolver AD is ignored.

The configured hostname is resolved only through the built-in fixed-bootstrap
validating ICANN DoH path, never system DNS. Rust connects to the resulting
explicit public IP while WebPKI validates the configured endpoint hostname.
When selected, its operator can observe HNS qnames and qtypes, request timing,
and the user's source IP. Nothing is sent to such an operator while the field
is blank.

Site owners can avoid either user recovery setting by publishing
proof-anchored authoritative DoH on HTTPS 443: an HNS `hnsdns=1` declaration
with proven glue and a TLSA pin, or the supported authenticated
`_dns.<NS>` SVCB form.

## Build

Install Rust 1.92.0 and Node.js 22 or later, then run:

```sh
cargo +1.92.0 build --release --locked \
  --manifest-path rust/Cargo.toml \
  -p hns-chromium-native-host
npm run check:extension
```

The unpacked extension is written to `dist/chromium-extension`. The extension
bundle does not contain the native executable, a CA private key, or a trust
anchor.

## Install

Load `dist/chromium-extension` through the target browser's extension
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

Repeat `--extension-id` on Unix, or provide a PowerShell string array, when
store and sideloaded builds use different IDs. `--browser` accepts `chrome`,
`chromium`, `edge`, `brave`, `vivaldi`, `opera`, or `all`.

Linux requires `certutil` from `libnss3-tools` or `nss-tools` and modifies only
the current user's NSS database. macOS uses the user's login keychain. Windows
uses the current user's Root store. Native-host registration is user-level.

The installer creates one P-256 CA per installation. Its private key remains
in the native host's protected data bundle. Rust issues only exact-host,
short-lived leaf certificates after native name admission on paths where Rust
must terminate TLS to enforce HNS or ICANN DANE. Defined ICANN WebPKI fallback
paths bypass this CA. The extension does not activate the PAC until platform
trust installation succeeds and the matching SHA-256 marker exists.

## Uninstall

Close all selected browsers, then run:

```sh
extension/install/uninstall.sh --browser all
```

or:

```powershell
extension\install\uninstall.ps1 -Browser all
```

The uninstaller removes this host's browser registrations, exact per-install
trust anchor, native executable, key material, marker, chain state, cache, and
runtime data. The browser removes extension-owned proxy settings when the
extension is disabled or uninstalled; orderly suspension also clears them.

## Recovery and security invariants

- Native messages use bounded schema-1 frames, request IDs, and one active
  port.
- The PAC contains no DNS or fallback logic.
- Proxy authentication is valid only for the active `127.0.0.1` generation.
- A healthy status check preserves the current generation; reconnect creates
  fresh credentials and reinstalls the PAC.
- CA-not-installed, host disconnect, malformed native response, rejected
  policy, PAC installation failure, or proxy restart clears proxy state.
- Namespace fingerprints partition pools, TLS verification and resumption, and
  Alt-Svc state.
- Selected HNS HTTPS never falls back to WebPKI. It never contacts a recursive
  HNS resolver automatically; a newly and explicitly configured recovery
  endpoint remains an untrusted transport whose bytes require local
  DNSSEC/TLSA/DANE validation.
- Selected ICANN HTTPS applies generic validating-DoH TLSA policy to every DNS
  host, not a hostname allowlist.
- JavaScript never infers DNSSEC, TLSA, DANE, or namespace state from
  browser-visible headers.
- Policy storage is updated only after native acceptance and an active proxy
  generation are returned.
- Header synchronization takes the runtime maintenance write lock, so a chain
  advance or reorganization cannot overlap request proof validation or
  publication. Native status exposes only page and CONNECT observations from
  the current maintenance epoch. Selective post-sync retention preserves a
  new-epoch observation published after maintenance releases while stale or
  late old-epoch observations remain unavailable.

## Qualification

Run the portable release gates:

```sh
git diff --check
python3 -m unittest -v tests/test_cargo_git_policy.py
python3 scripts/verify_cargo_git_policy.py
python3 scripts/generate-third-party-notices.py --check
./scripts/check-version-consistency.sh
./scripts/check-runtime-boundaries.sh
./scripts/verify-supply-chain.sh
cargo +1.92.0 fmt --manifest-path rust/Cargo.toml --all -- --check
cargo +1.92.0 clippy --locked --manifest-path rust/Cargo.toml \
  --workspace --all-targets -- -D warnings
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml --workspace
cargo +1.92.0 build --locked --release \
  --manifest-path rust/Cargo.toml -p hns-chromium-native-host
npm run check:extension
```

A signed release still requires native installation, browsing, restart,
upgrade, and complete-removal testing on supported Windows and macOS versions
and current stable builds of all six browsers. Store signing, review, and
published extension IDs are distribution gates, not source-build evidence.

Current mobile qualification and release instructions are maintained only in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).
