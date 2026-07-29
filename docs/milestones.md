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
`7f7bb8fa100c2393f2cd5a64c64bf5e20a0f3ab5`:

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

### Desktop Setup and signed macOS distribution

- Version-matched graphical Setup packages install, repair, inspect, and
  completely remove the user-level native host and exact local CA on Linux,
  macOS, and Windows for x64 and arm64.
- The published v0.5.5 macOS native-host and Setup packages completed
  Developer ID signing and Apple notarization on 2026-07-29. Credentialed jobs
  used the protected `macos-signing` environment; the separate write-enabled
  `release` environment still needs protection rules. Setup tickets are
  stapled; standalone native hosts use Apple's online ticket.
- Windows release packages remain accurately labeled unsigned.

### Staged header maintenance and mandatory proxy lifecycle

- Header network work, quorum collection, snapshot preparation, and peer
  merging occur in a private staged database outside the live maintenance
  gate.
- Generation-and-tip-bound delta publication atomically updates headers,
  peers, and readiness; incomplete, stale, or superseded stages fail closed.
- Manifest V3 suspension preserves the live proxy, and every native-host
  replacement enters a confirmed fixed blocking PAC before disconnecting the
  captured process. Runtime failure and retry paths never expose direct or
  system routing.

## Current qualification evidence and remaining release work

- Exact-current-main hosted CI passed for release commit
  `86b18497285753944ec1b9196ec05ee359c6db11` in
  [run 30435346299](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/30435346299).
  The tag workflow published 29 verified `v0.5.5` assets in
  [run 30435936597](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/30435936597),
  and the macOS replacement completed in
  [run 30436887463](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/30436887463).
  Repeat and retain these gates for each future release commit.
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
