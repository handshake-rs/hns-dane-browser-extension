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

The Chromium adapter now consumes the consolidated engine source through exact
reviewed Git revisions: private browser adapters at `b8bdfbf7e234e64166886ade6f79d698e23056af`
and five compatibility patches at `1ab4ab626f945712b0f960945986cb52efefef7c`.
The split is temporary and must converge before the next feature release:

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
- Wallet admission source now consumes the wallet-owned manifest schema v2,
  verifies JCS/Ed25519/exact pins, retains durable per-line high-water state,
  and provides a Linux sealed-executable primitive. At exact source
  `a39f8759c0161b5e49cb93c0c5aea1f0298e3108`, the focused offline command
  below passed 17 tests with 0 failures and 24 filtered in the library target;
  the main target contained 0 tests:

  ```sh
  CARGO_TARGET_DIR=/home/den/.codex/targets/hns-extension-wallet-abi-verifier-aug3 \
  TMPDIR=/home/den/.codex/tmp/hns-extension-wallet-abi-verifier-aug3 \
  cargo test --locked --offline -p hns-chromium-native-host wallet_abi::tests -- --test-threads=1
  ```

  The first invocation at
  `17d3efae6e0367e1f0ee2ef8cdafa67b5cdc20af` compiled successfully. Two
  pure encoding tests passed, while the other 15 reached the same
  `walletArtifactDirectoryUnsafe` fixture precondition because the environment
  created test roots and ABI directories as mode `0775`. That production
  rejection was correct. `a39f8759` changed only the fixture helpers to force
  both directories to `0700`; the cached rerun above then passed.
  This did not run the full repository gate, a release build or package,
  installed-browser coverage, or product qualification. Production trust
  roots, release pins, and floors remain empty, and macOS/Windows execution,
  private transport, opaque engine authority, provider projection, and product
  qualification remain release blockers.

Passing portable source gates is not a substitute for those release gates.

## Next engineering milestone

Adopt one current engine revision and join its HNSA admission, HNSR requester,
and opaque provider-authority lifecycles to the native host. Retain only the
browser-specific listener, native-messaging, CA/TLS, lifecycle, installer, and
approval UI here. The first wallet product slice remains non-value status,
lock, and capability controls; private transport, production wallet trust
roots, native approval rendering, and installed-browser qualification must land
before provider installation. Value movement and P2P marketplace controls are
separate later gates and remain disabled.
