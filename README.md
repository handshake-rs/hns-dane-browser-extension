# HNS DANE Browser Extension

This repository contains the Chromium Manifest V3 extension and its Rust native
messaging host. Android and iOS are maintained separately in
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

The native host integrates the five canonical browser contracts from
[`handshake-rs/hns-dane-engine`](https://github.com/handshake-rs/hns-dane-engine)
at immutable revision
`fe38e805ba9d8ba26d486c5c7aa67c87c8cf9159`:

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

## Requester and provider policy

The extension exposes one explicit opt-in for consuming the experimental HNS
P2P DNS-relay transport:

- unchecked maps to canonical requester policy `Disabled`;
- checked maps to direct-authority-first requester policy `Auto`.

This requester setting does not advertise or enable any service. The Chromium
product opts out of opaque relay serving and enables no output-node/provider
role. Ecosystem defaults for opaque relaying and explicit output-node consent
belong to the products that implement those services.

HNSR is not implemented by this native host. Requests for that role fail
closed, and the extension does not present an HNSR control. P2P ODoH, privacy
downgrade, and experimental wire-profile controls remain visible as typed
experimental policy inputs; unsupported selections fail closed.

## Repository layout

- `extension/`: service worker, options and popup UI, tests, build tooling, and
  user-level native-host installers.
- `rust/`: Chromium native host, platform adapter, loopback proxy, Handshake
  resolution stack, transport, and pinned canonical engine contracts.
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
python3 scripts/verify_cargo_git_policy.py
python3 scripts/generate-third-party-notices.py --check
npm run check:extension
```

See [Chromium Extension and Native Host](docs/chromium-extension.md) for build,
installation, trust, recovery, and removal instructions.

## Support and license

Donations are optional and do not unlock features.

- HNS donation address:
  `hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`

This repository is source-available under the PolyForm Noncommercial License
1.0.0. Noncommercial use, study, modification, and redistribution are allowed
under that license. Commercial use requires separate written permission from
Denuo Web, LLC.

Source: https://github.com/handshake-rs/hns-dane-browser-extension
