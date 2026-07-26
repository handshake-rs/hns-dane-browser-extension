# Milestones

## Completed source milestones

### Chromium product split

- Current Android and iOS work moved to
  [`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).
- This repository's active product boundary is the Manifest V3 extension,
  native messaging host, authenticated loopback proxy, and Chromium Rust
  adapter.
- Cargo, CI, notices, version policy, and documentation are scoped to that
  boundary.

### Canonical browser contracts

The Chromium adapter consumes these contracts from
`handshake-rs/hns-dane-engine` at immutable revision
`fe38e805ba9d8ba26d486c5c7aa67c87c8cf9159`:

- runtime request authority;
- checked browser observability;
- generic ICANN DANE policy;
- dual-root namespace resolution; and
- requester/provider resolution policy.

Each request is stamped before DNS and retains the exact authority through
response-head, body/download, and tunnel publication. Stale work and stale
status are rejected after a generation, policy, readiness, or lifecycle
change.

### Generic ICANN DANE and dual-root classification

- The syntax-only PAC routes every ordinary DNS HTTP(S)/WS(S) hostname to
  Rust.
- Rust resolves the complete hostname through HNS and ICANN and retains
  HNS-only, ICANN-only, convergent, divergent, neither, or indeterminate.
- The IANA list is a non-authoritative hint only.
- ICANN TLSA owner derivation uses the effective port and transport for every
  selected HTTPS/WSS host.
- Secure TLSA is enforced; authenticated denial or an unsigned zone uses
  WebPKI; bogus/indeterminate DNSSEC fails closed.
- Redirects, subresources, Service Workers, downloads, and WebSockets share
  the same proxy/admission boundary.

### Consent boundary

- The browser DNS-relay requester is explicit opt-in:
  `false → Disabled`, `true → Auto`.
- The Chromium product opts out of opaque relay serving and enables no output
  or provider role.
- HNSR and P2P ODoH remain unimplemented and fail closed.

## Release qualification still required

- exact-current-main hosted CI;
- native install, browsing, restart, upgrade, and complete removal on supported
  Windows and macOS versions;
- current stable matrix for Chrome, Chromium, Edge, Brave, Vivaldi, and Opera;
- store signing, review, and published extension IDs; and
- release artifact provenance tied to the reviewed commit/tag.

Passing portable source gates is not a substitute for those release gates.

## Next engineering milestone

Move the remaining platform-neutral loopback admission and publication
mechanics into the canonical engine while retaining browser-specific listener,
native-messaging, CA/TLS integration, lifecycle, and installer code here.
Preserve the current request stamp, full-host namespace plan, typed DANE
failure, and checked status invariants during that extraction.
