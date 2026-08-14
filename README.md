# HNS DANE Browser Extension

This repository contains the Chromium Manifest V3 extension, its Rust native
messaging host, and the cross-platform HNS DANE Browser Setup application.
Android and iOS are maintained separately in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

The extension installs a syntax-only PAC that sends every ordinary DNS
hostname used by HTTP, HTTPS, WebSocket, and secure WebSocket requests to an
authenticated loopback proxy. The PAC does not decide whether a name belongs
to Handshake or ICANN. Rust resolves the complete hostname through both roots
and classifies the result as:

- HNS only;
- ICANN only;
- convergent when both roots produce the same effective plan;
- divergent when both exist with different plans;
- neither when both roots securely establish absence; or
- indeterminate when either required result cannot be authenticated.

An IANA root-zone snapshot may be used as a scheduling hint, but never as the
namespace authority. Bogus or indeterminate DNSSEC is never treated as an
absent record or namespace.

For a selected ICANN HTTPS or WSS plan, Rust derives the TLSA owner from the
effective host, port, and transport and queries it through validating ICANN
DoH. A securely present supported TLSA RRset is enforced. Authenticated denial
or an unsigned delegation uses the defined WebPKI fallback. Bogus DNSSEC,
malformed data, and resolver failure fail closed.

On the defined WebPKI fallback, Rust opens only the exact public IP selected by
that decision and tunnels Chromium's TLS bytes unchanged. Chromium therefore
validates and displays the origin's real certificate chain. The per-install
local CA is used only where Rust must terminate TLS to enforce HNS or ICANN
DANE.

The native host integrates the five canonical browser contracts and the
consolidated private adapters from
[`handshake-rs/hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine)
through one exact reviewed Git revision recorded in `rust/Cargo.toml` and
`rust/Cargo.lock`:

- `hns-browser-runtime`;
- `hns-browser-observability`;
- `hns-icann-dane`;
- `hns-namespace-resolution`; and
- `hns-resolution-policy`.

Every admitted request is bound to the current runtime session, proxy
generation, policy generation, and monotonic admission event. The same
authority guard covers response-head publication, streamed or file-backed
bodies, downloads, and tunnels. Policy changes, readiness loss, or proxy
rotation invalidate older work rather than allowing stale bytes or status to
escape.

Header synchronization stages network I/O, quorum collection, snapshot
preparation, and peer merging in a private database. Only conditional,
generation-and-tip-bound publication briefly enters the live maintenance
gate, where headers, peers, and readiness become visible atomically. A
transient due-but-unexpired sync failure leaves the healthy proxy running; an
independent authenticated-evidence expiry still fails closed.

The extension retains proxy control across worker suspension and native-host
replacement. Mandatory transitions move through a confirmed fixed blocking
PAC and never expose system or direct routing while Rust security state is
unavailable.

## Requester and provider policy

The extension exposes one explicit opt-in for consuming the experimental HNS
P2P DNS-relay transport:

- unchecked maps to canonical requester policy `Disabled`;
- checked maps to direct-authority-first requester policy `Auto`.

This requester setting does not advertise or enable any service. The Chromium
product opts out of opaque relay serving and enables no output-node/provider
role. Ecosystem defaults for opaque relaying and explicit output-node consent
belong to the products that implement those services.

The options page also accepts an explicit recursive HNS DoH recovery URL. It
is blank and disabled by default, is never inherited from historical resolver
settings, and is generation-bound separately from P2P consent. The exact HNS
transport order is direct authoritative UDP/TCP, proof-anchored owner
authoritative DoH, an opted-in requester-only P2P relay, then the configured
recursive endpoint. The final endpoint is eligible only after a typed
transport failure or confirmed port-53 interception; invalid responses, DNS
failure codes, bogus DNSSEC, and missing or stale proof/chain evidence remain
terminal. Returned RFC 8484 bytes are locally DNSSEC- and DANE-validated; the
resolver's AD bit is not trusted.

The adopted canonical engine contains an HNSR requester lifecycle and HNSA
named-route admission, but this native host joins neither product path. It
constructs `HnsrPolicy::disabled()` instead of inheriting the engine default,
rejects every non-off HNSR input, persists no HNSR state, and presents no HNSR
control. P2P ODoH, privacy downgrade, and experimental wire-profile controls
remain visible as typed experimental policy inputs; unsupported selections
fail closed.

The popup can independently fetch the bounded public feed exposed by a
MeshMine operator, so viewing pool status does not require pool membership.
It omits credentials and referrer data, rejects redirects and oversized or
malformed objects, and labels every decoded value unverified. The feed endpoint
is not an identity authority: an authorization contains a name hash, not a
reversible HNS label.

The native Rust workspace now contains a schema-2 verifier core for MeshMine's
private `0xff00` `pool-stats` application profile under current HRM-backed
HNSA semantics. It accepts only an opaque broker-issued current named-service
authority bound to the exact network, name hash, HRM sequence/envelope hash,
authority revision and trusted operation time, service resource and delegation
IDs/generation, service key, intervals, capabilities, constraints, and fenced
lease generation. It then verifies the canonical service-signed HNSA endpoint
delegation and an endpoint-signed profile record that also binds an
independently selected route ID, endpoint-delegation ID/sequence, profile,
generation, and expiry. Commit-before-release state retains endpoint and
operator replacement history; minimized values contain no keys, signatures,
or raw authority objects. Counts, mode, tip, and production eligibility remain
authenticated operator claims, never consensus, wallet, or settlement facts.
The private profile defines a logical endpoint as its compressed endpoint key
and scopes snapshot replacement to `(service generation, operator ID)` across
endpoint keys. Core unsigned network/time and cryptographic digest/ID fields
are not treated as absence sentinels; the HNSA-required service generation and
endpoint sequence and the profile's record sequence remain nonzero.

This verifier is deliberately dormant. `CurrentHrmNamedService` has no public
constructor because the Chromium product does not yet have the sole trusted
subject-wide HRM/HNSA broker, authenticated aggregate store, external revision
floor, fenced operation lease, or current-HRM adapter required to issue it.
Native hello therefore reports schema 2, `meshmineHrmAuthorityAdapter: false`,
`meshmineLegacyHsa1Accepted: false`, and
`meshmineVerifiedPoolStats: false`. The popup parses only the new bounded
schema but still labels every value unverified; it advances no native state and
cannot turn an HTTP response into authority. The superseded `hsa1` and fixed
service-authorization path has been removed rather than retained as fallback.

## Optional wallet provider

The repository contains a Handshake-specific website provider schema v1 and a
strict private wallet ABI-v2 signed-artifact admission boundary. It consumes
the wallet-owned manifest schema v2 with provider schema 1 and approval schema
3, verifies deterministic JCS bytes and Ed25519 signatures against
verifier-owned roots, requires an exact qualified release pin and durable
anti-rollback high-water state, and on Linux can launch only a freshly rehashed
sealed executable image. No test key is production trust. The production
trust-root, release-pin, and release-floor tables are intentionally empty until
an independently released wallet service is qualified. Linux source contains a
dormant native-only composition for an explicitly trusted, pre-existing private
wallet database: it revalidates retained path identity, passes only the exact
`--database` argument pair, requires the live child to hold the retained
database inode, applies a non-value capability ceiling, negotiates the private
transport, and owns kill-and-wait restart generations. No extension command or
product configuration can construct that session.

This source composition is not an interoperability claim for the current
checked-in wallet executable. That executable still selects its locked
control-only runtime; synchronized HNS reads need a separately trusted unlock,
exact account, and authenticated node configuration. An exact launched-service
read fixture and single-process/no-descendant qualification remain release
requirements.

The provider code validates the approval-schema-v3 closed 12-variant typed
approval union. Permissions summaries require the minimized `hnsNames` list;
each disclosed name and its exact SHA3-256 hash is validated and rendered in the
trusted approval window. Events enter only through the service event channel,
and decisions stay bound to exact in-memory context. The released Chromium
product keeps the provider unavailable: no qualified standalone service,
private process transport, or released engine-authority adapter is joined.
Artifact authenticity, transport, runtime, engine authority, provider, and
value gates therefore remain false in production, and no staged artifact is
launched.

Focused offline verifier evidence at exact source
`a39f8759c0161b5e49cb93c0c5aea1f0298e3108` is 17 passed, 0 failed, and
24 filtered in the library target, plus 0 main-target tests. The first
invocation at `17d3efae6e0367e1f0ee2ef8cdafa67b5cdc20af` compiled
successfully but correctly rejected fixture directories inherited as mode
`0775`: 2 pure encoding tests passed and the other 15 failed at the shared
`walletArtifactDirectoryUnsafe` precondition. Commit `a39f8759` changed only
the fixtures to mode `0700`; the cached rerun passed. This is focused source
evidence, not the full gate, a release build/package, installed-browser
qualification, or product readiness.
See
[Handshake wallet provider](docs/wallet-provider.md) and
[wallet privacy](docs/wallet-privacy.md).

## Repository layout

- `extension/`: service worker, options and popup UI, tests, build tooling, and
  the release-time index for six embedded Setup archives.
- `rust/`: Chromium native host, platform adapter, loopback proxy, Handshake
  resolution stack, transport, and pinned canonical engine contracts.
- `rust/crates/hns-browser-setup/`: desktop GUI/CLI that installs, repairs,
  verifies, and completely removes the per-user native-host installation.
- `fixtures/`: bounded parser and experimental relay fixtures.
- `rust/fuzz/`: parser fuzz targets.
- `tests/experimental-dns-relay/`: isolated and four-node regtest relay
  acceptance harnesses.
- `docs/`: architecture, security, operations, and audit notes.
- `scripts/`: local policy, supply-chain, test, and qualification gates.

## Validate

Required development tools are Rust 1.92.0 and Node.js 22 or later.

```sh
cargo +1.92.0 fmt --manifest-path rust/Cargo.toml --all -- --check
cargo +1.92.0 clippy --locked --manifest-path rust/Cargo.toml \
  --workspace --all-targets -- -D warnings
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml --workspace
cargo +1.92.0 build --locked --release \
  --manifest-path rust/Cargo.toml -p hns-chromium-native-host
HNS_NATIVE_HOST_PATH="$PWD/rust/target/release/hns-chromium-native-host" \
HNS_HEADER_SNAPSHOT_PATH="$PWD/release/hns_headers_300000.snapshot.gzip" \
  cargo +1.92.0 build --locked --release \
    --manifest-path rust/Cargo.toml -p hns-browser-setup \
    --features embedded-host
python3 scripts/verify_cargo_git_policy.py
python3 scripts/generate-third-party-notices.py --check
npm run check:extension
```

Required CI also publishes a read-only, exact-SHA Linux arm64 bundle containing
the static native host and canonical extension package for qualification in a
disposable Chromium profile. See
[installed-browser qualification](docs/installed-browser-qualification.md);
artifact creation is not itself qualification.

See [HNS DANE Browser Setup](docs/setup-application.md) for the primary desktop
installation flow and [Chromium Extension and Native Host](docs/chromium-extension.md)
for build, trust, recovery, and manual-installation details.
The extension detects an exact native-component version mismatch before
activation, retains its blocking gate, and offers the newly embedded Setup
package. Its dropdown also exposes a safe **Complete Uninstall…** handoff; the
user still closes browsers and confirms removal inside Setup.

Store submission copy, reviewer disclosures, permission justifications, and
shared Chrome/Edge/Opera artwork are maintained in [`store/`](store/README.md).
Tagged GitHub Releases provide the browser-neutral extension ZIP, with all six
final platform-matched Setup applications embedded, plus matching manual
native-host bundles. Setup embeds the validated mainnet header bootstrap
through height 300,000. Store packaging occurs only after Windows signing,
macOS signing/notarization, and Linux provenance finalization.
The Linux Setup ABI ceiling remains glibc 2.39 (for example Ubuntu 24.04 or
Debian 13).
Chrome Web Store distribution also serves Brave and Vivaldi, while Edge and
Opera can use their own catalog listings.
See the [Chromium release process](docs/release.md) for the immutable-tag,
multi-platform build, checksum, signing-status, and catalog-ID boundaries.
Windows release builds enforce a complete system-DLL allowlist and carry the
project's pinned self-signed Authenticode signature plus an RFC 3161 SHA-256
timestamp. That certificate is not publicly trusted, so SmartScreen or an
**Unknown Publisher** warning can still appear; users should verify both the
archive SHA-256 and the published certificate fingerprint. macOS jobs require
Developer ID signatures, Apple notarization, stapled Setup tickets, and the
verified 11.0 deployment floor. Linux release archives receive keyless GitHub
build-provenance attestations. A missing credential or failed platform check
blocks the extension artifact instead of publishing an unsigned store bundle.

## Support and license

Donations are optional and do not unlock features.

- [GitHub Sponsors](https://github.com/sponsors/denuoweb)
- [Donate HNS](handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh?label=Denuo%20Web%20Handshake%20Browser&message=Handshake%20Browser%20donation):
  `hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`

This repository is source-available under the PolyForm Noncommercial License
1.0.0. Noncommercial use, study, modification, and redistribution are allowed
under that license. Commercial use requires separate written permission from
Denuo Web, LLC.

Source: https://github.com/handshake-rs/hns-dane-browser-extension
