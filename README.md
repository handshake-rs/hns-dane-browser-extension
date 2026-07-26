# HNS DANE Browser

This worktree is the Chromium-extension extraction: a Manifest V3 package,
versioned Rust native-messaging host, syntax-only PAC and full-host dual-root
HNS/ICANN proxy boundary, per-install local CA lifecycle, generation-bound Rust
security results, and user-level installers for six Chromium browsers on Linux,
macOS, and Windows.

The retained `android/`, `ios/`, `android-ffi`, and `ios-ffi` trees are
historical source only. They are excluded from the Cargo workspace and from
this release checkpoint; they do not establish mobile dual-root or ICANN-DANE
coverage. The canonical mobile browser is maintained and qualified in the
separate `hns-dane-browser-mobile` repository.

## Layout

- `rust/`: active Cargo workspace for consensus primitives, header chain, Urkel proof interfaces, resolver, DNSSEC, DANE, transport, gateway, cache, the shared browser runtime, the platform-neutral loopback proxy, and the Chromium native host. The tree also retains excluded, historical Android JNI and Apple C ABI crate sources.
- `rust/crates/hns-chromium-native-host/`: bounded native messaging, persistent local CA, proxy lifecycle, policy, status, and installer utilities.
- `extension/`: Manifest V3 service worker, options/popup UI, packaging tests, and user-level native-host/CA installers.
- `rust/fuzz/`: `cargo-fuzz` parser harnesses for DNS, HNS resource values, P2P frames, Urkel proofs, TLSA records, and X.509 SPKI extraction.
- `android/`: historical, non-release Kotlin Android browser source retained pending cleanup.
- `ios/`: historical, non-release Swift/UIKit browser source retained pending cleanup.
- `fixtures/`: Header, Urkel, and DNS fixture slots for HSD/HNSD comparison data.
- `docs/`: Architecture, security model, version audit, and milestone notes.
- `docs/sync-audit.md`: first-run sync path, progress UI, and remaining sync-speed bottlenecks.
- `docs/supply-chain-audit.md`: pinned build inputs, CI/release gates, and residual reproducibility risks.
- `scripts/`: Local validation helpers.

## Current Scope

- Parses and serializes Handshake block headers.
- Computes Handshake mainnet genesis PoW hash using the HSD header algorithm.
- Validates Handshake TLD syntax and derives HSD-compatible SHA3-256 name hashes.
- Provides typed hash, height, target, and chainwork primitives.
- Stores headers behind an injectable trait with in-memory and SQLite implementations, persists a canonical `hash_by_height` index for reorg-aware best-chain lookups, appends canonical tip updates for normal chain growth, validates the exact mainnet genesis header, enforces HSD-compatible mainnet difficulty retarget bits, and rejects non-genesis headers that fail proof-of-work.
- Parses and synthesizes bounded DNS messages, questions, names, resource records, and RFC 9460 SVCB/HTTPS RDATA.
- Decodes HSD name resource values into DNS-style DS, NS, in-zone glue A/AAAA, synthetic glue A/AAAA, and TXT records; delegated nameserver DoH transport is bootstrapped from proof-anchored `hnsdns=1` metadata when present or discovered from RFC 9461 DNS-server SVCB records in authoritative DNS.
- Parses DNSSEC DNSKEY/DS/RRSIG/NSEC/NSEC3 records, computes RFC 4034 key tags, verifies SHA-1, SHA-256, and SHA-384 DS-to-DNSKEY delegation links, builds canonical RRSIG signed data including canonical RDATA names for CNAME, NS, SOA, SRV, and SVCB/HTTPS TargetName, verifies RSA/SHA-1 compatibility, RSA/SHA-256, RSA/SHA-512, ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, and Ed25519 RRset signatures, and composes those checks into fail-closed signed-RRset, delegated-chain, NSEC no-data, NSEC name-range, NSEC name-error, and RFC 5155 NSEC3 denial validators.
- Encodes and decodes the HSD packet subset needed for header sync and proof requests, including HSD-compatible 9-byte wire framing, 88-byte HSD network addresses in version and addr packets, version/verack ordering tolerance, advisory/unknown packet tolerance during sync waits, transient-failure peer recovery with bounded malformed-peer bans, and a blocking TCP peer connection for getaddr, getheaders, and getproof flows.
- Adds an experimental HNS P2P recursive-DNS requester transport after local proof validation and authoritative DNS attempts. Browser consumption is an independent opt-in, and relayed answers remain untrusted input to local DNSSEC, HTTPS/SVCB, TLSA, and DANE validation. The runtime prohibits public recursive HNS DoH and normalizes historical third-party HNS DoH settings to disabled without treating them as requester consent. Manual relay peers are accepted only as IP-literal `IPv4:port` or `[IPv6]:port` endpoints and persisted only after a live HSD handshake confirms the current relay capability. Operator-side opaque relay capacity is default-on with an explicit opt-out; serving as an output node is a separate explicit opt-in.
- Adds parser fuzz smoke targets for DNS messages/names/SVCB, HNS resource values, P2P frames/payloads, Urkel proofs, TLSA records, and bounded X.509 SPKI extraction.
- Provides sync coordinators for version/verack, getaddr/addr peer discovery, getheaders/headers ingestion with duplicate-header tolerance, locator construction, remote-height-aware no-op sync when peers are not ahead of the local best header, bounded multi-batch header sync across selected peers with persisted peer outcomes, same-run getaddr discovery rotation toward the peer-table target, Android first-run catch-up status that stays `syncing` while the known or estimated target is ahead of local best height, DNS seed refresh while the peer table is below target, tracked getproof/proof flow control, upstream-compatible Urkel proof verification, verified HSD `NameState.data` value handoff, and proof scheduling into the resolver resource-value store.
- Implements DANE TLSA matching, bounded X.509 certificate SPKI extraction, chain-aware EE/TA TLSA policy, and fail-closed HNS/WebPKI TLS decisions.
- Retains parser and transport support for experimental stateless DANE certificate evidence, but the new atomic dual-root browser plan deliberately requires live DNSSEC-secure HNS TLSA and fails closed before this fallback when TLSA is absent. The setting is therefore not a supported Chromium feature in this checkpoint. Restoring it requires a typed trust policy in the shared namespace-plan contract; this is a release blocker for any stateless-DANE claim.
- Provides peer scoring, banning, static peer seeding, HSD-compatible DNS seed discovery, bounded rotating getaddr peer discovery, SQLite peer-state persistence, address-group-aware outbound peer selection, LRU-bounded TTL resolver positive and verified-negative caching primitives, in-memory and SQLite verified resource-value providers, resource-cache byte accounting, chain-root/height anchoring, current-tip cache invalidation, active cap enforcement, clear-cache support, a proof-provider-backed HNS resolver boundary that can extract verified HSD resource values, distinguishes verified non-inclusion from existing names with no origin address, extracts final-label HNS roots for dotted HNS hosts, hydrates out-of-zone HNS nameserver addresses from their own verified root proofs, filters proven DNS-style records fail-closed, bootstraps RFC 8484 authoritative DoH from proof-anchored `hnsdns=1` transport metadata or RFC 9461 `_dns.<nameserver>` SVCB discovery, detects confirmed transparent port 53 interception with a bounded TEST-NET sentinel probe, and a DNSSEC-gated delegation boundary for HNS roots with NS/DS records backed by authoritative DoH or UDP DNS with TCP fallback, signed positive RRset validation, bounded CNAME-chain validation, signed child-referral validation with child CNAME-chain handling, parent/child NSEC/NSEC3 no-data validation, and delegated NXDOMAIN name-error validation.
- Provides bounded HTTP/1.1 origin transport over TCP or rustls TLS with same-origin keep-alive pooling, HTTPS rustls session resumption scoped to the active DANE/WebPKI policy, safe same-port Alt-Svc promotion to HTTP/2 or HTTP/3, HTTPS HTTP/2 origin transport over Tokio/Rustls, and HTTPS HTTP/3 origin transport over Quinn/h3 with DANE validation bound to the QUIC TLS handshake, with gateway routing only from owner-matching secure A/AAAA answers or validated CNAME-chain terminal A/AAAA answers to transport connect addresses, delegated origin A/AAAA lookup when Android starts from all root records, exact `_port._tcp.host` DNSSEC-secure TLSA lookup for DANE policy, strict and compatibility HNS HTTPS policy modes, HTTPS/SVCB ALPN and service-port policy selection constrained to implemented origin protocols, HTTP/1.1 default fallback when SVCB permits it, fail-closed origin response framing for unsupported transfer codings or ambiguous lengths, stream-to-writer decoded response bodies, and actionable fail-closed handling when HNS resolution lacks an origin address or delegated nameserver responses are invalid.
- Adds gateway-time live proof fetching on verified-resource cache miss from peers at or above the local anchor height, storing Urkel-verified values anchored to the current best header before origin routing, and native HNS WebSocket/HTTP Upgrade stream tunneling after HNS resolution, HTTPS/SVCB policy, and DANE validation. HNS resolution and HTTPS fail closed instead of falling back to a public recursive HNS resolver or HNS WebPKI; remaining DNSSEC algorithms and remaining gateway boundaries stay fail-closed or future work.
- Feeds the Chromium native host from that trusted proxy-status boundary before internal response metadata is stripped. Rust emits a sanitized, versioned main-frame result containing the live runtime/policy generation, chain anchor, actual DNS transport, HNS proof, DNSSEC, TLSA, DANE, and intermediary identities. The extension rejects stale results and only renders fixed labels; it does not parse DNS, certificates, proofs, or P2P state.

## Platform Scope

This checkpoint qualifies only the Chromium extension and native host. Mobile
source and scripts remain for history, but their FFI crates are not workspace
members and their former build/device claims are not release evidence here.

## Historical Mobile Implementation (Non-Release)

The following retained implementation describes the former mobile targets. It
is preserved as useful engineering history, but is excluded from the active
Cargo workspace and is not qualified by this checkpoint:

- Packaged the Rust FFI core into the APK for `arm64-v8a` and `x86_64`.
- Retains a historical Android WebView shell whose classifier and exact-scope proxy still use the legacy IANA-snapshot/HNS routing boundary. It is not built or released from this workspace and must not be cited as dual-root or automatic ICANN-DANE coverage.
- Gated every HNS main-frame navigation through `BrowserProxyCoordinator`. The latest load waited until the process-global AndroidX proxy override was owned and an immutable exact root/subdomain-scoped endpoint was started and applied; scope transitions, suspension, or ownership loss immediately withdrew routing, authentication, certificate trust, and typed status publication. Active in-scope WebView and Service Worker requests used the same proxy/compatibility/block routing snapshot; because Android WebView did not expose a Service Worker TLS challenge to the page client, admitted worker requests executed through the shared Rust runtime gateway instead of the local CONNECT certificate path.
- Selected the platform-neutral Rust proxy exclusively. It exposed a fresh authenticated loopback HTTP/CONNECT endpoint, routed HNS requests through the shared persistent runtime, terminated CONNECT with Rust-owned per-host local TLS identities, forwarded validated native WebSocket/HTTP Upgrade streams, and supplied bounded typed main-frame security status. Android proceeded past the expected local TLS error only when the full certificate DER matched the exact host and live proxy generation.
- Fell back only to the exact-scope compatibility interceptor if the Rust proxy could not start. A document-start policy left allowed WebSockets on Chromium's native implementation while rejecting cross-scope HNS targets; all HTTP parsing, CONNECT termination, certificate generation, and Upgrade tunneling remained in Rust.
- Provided a second, fail-closed whole-browser proxy mode for WebKit data stores that could not express Android's reverse-bypass scope. The Rust proxy routed the admitted HNS root through the shared HNS/DNSSEC/DANE backend, forwarded ICANN HTTP and opaque CONNECT only to explicit public addresses obtained through bounded WebPKI-authenticated DoH, blocked reserved/private destinations and unsafe ports before dialing, and never used the system resolver for a browser target.
- Exposed the shared runtime through a versioned `ios-ffi` C ABI with opaque monotonic handles, Rust-owned result buffers, bounded status mailboxes, one active proxy per runtime, immediate lifecycle revocation, and live generation/host/certificate matching. Apple device and simulator slices were packaged as `HnsBrowserRuntime.xcframework`.
- Added an iOS 17.0-or-later UIKit/WKWebView shell using one persistent website-data-store profile and an authenticated, no-failover whole-browser proxy configuration. Its deployment floor retained support for the iOS 17 and iOS 18 generations, while Apple builds used the stable iOS 26.5 SDK with Xcode 26.5 or 26.6. Swift owned navigation admission, WebView reconstruction, downloads, UI, and server-trust challenge integration; HNS classification, sync, resolution, DNSSEC, DANE, HTTP parsing, proxying, and TLS termination remained in Rust.

## Validate

```sh
cargo +1.92.0 fmt --manifest-path rust/Cargo.toml --all -- --check
cargo +1.92.0 clippy --locked --manifest-path rust/Cargo.toml \
  --workspace --all-targets -- -D warnings
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml --workspace
npm run check:extension
```

See `docs/chromium-extension.md` for the Chromium build, install, trust,
recovery, and complete-uninstall flow.

Historical Android/iOS build scripts are intentionally outside this
checkpoint. Use the canonical mobile repository for current mobile builds and
device qualification.

## Support

Donations are optional and do not unlock any app features.

- HNS donation address: `hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`

## License

This repository is source-available under the PolyForm Noncommercial License 1.0.0. Noncommercial use, study, modification, and redistribution are allowed under the license. Commercial use requires separate written permission from Denuo Web, LLC.

Source code: https://github.com/Denuo-Web/hns-dane-browser
