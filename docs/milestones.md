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

The Chromium adapter now consumes the consolidated engine source through one
exact reviewed Git revision,
`65c397e8347f37085ea67d2c9c745ce896328e64`, for both private browser adapters
and the five canonical `0.2.1` contracts:

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
- The adopted engine contains HNSR and HNSA named-route lifecycles, but the
  Chromium product joins neither route lifecycle. It explicitly constructs
  disabled HNSR policy; P2P ODoH also remains unimplemented and fails closed.

### MeshMine public-feed verifier core

- `hns-meshmine-pool-stats` implements the private `0xff00` read-only profile
  over the canonical non-forgeable `VerifiedHnsResource` and exact
  `hns-service-authority` types.
- The independently supplied HNS name and configured network, current
  single-string `hsa1` authority, name hash, current height/time, zero flags, zero detached
  constraints, exact read-statistics capability, authorization ID, delegation
  ID, endpoint sequence, endpoint key, snapshot signature, and lifetime are
  all bound before a minimized value exists.
- Its bounded canonical state retains authorization, delegation, global
  per-operator snapshot, resource/policy generation, trusted-time, and
  terminal conflict/capacity history. The public
  entry returns a verified value only after a caller-provided atomic
  compare-generation commit accepts every mutation, including mutations made
  on a failing verification.
- This is an enabling core, not product availability. The existing Chromium
  proof/cache authority cannot manufacture the required private
  `VerifiedHnsResource`, and no authenticated rollback-resistant native store
  or message/UI join exists. Native capabilities keep
  `meshmineVerifiedPoolStats` false, JavaScript remains display-only, and HNSR
  stays disabled.

### Desktop Setup and signed macOS distribution

- Version-matched graphical Setup packages install, repair, inspect, and
  completely remove the user-level native host and exact local CA on Linux,
  macOS, and Windows for x64 and arm64.
- The published v0.5.5 macOS native-host and Setup packages completed
  Developer ID signing and Apple notarization on 2026-07-29. Credentialed jobs
  used the protected `macos-signing` environment; the separate write-enabled
  `release` environment now permits only `main` and `v*` tags. Setup tickets
  are stapled; standalone native hosts use Apple's online ticket.
- The 0.6.0 release path signs Windows packages with the persistent project
  self-signed Authenticode certificate and RFC 3161 SHA-256 timestamps. The
  certificate remains outside Windows public trust, so release and Setup copy
  must preserve the SmartScreen/**Unknown Publisher** warning and publish both
  archive and certificate fingerprints.

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
- Consolidated source
  `ae702ebdea59050dd9395636f549ff9c2b8f2e4b` passed
  [CI run 31394858244](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31394858244)
  and
  [CodeQL run 31394857474](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31394857474).
  Its exact JavaScript was loaded in an isolated Chromium 149 profile and
  stayed fail-closed against an incompatible older native host. The old host
  reported approval schema 2 while the browser source required schema 3, so
  that evidence is historical browser-code/negative-compatibility evidence,
  not exact-native-host qualification. Full hashes and observations are in
  [installed-browser qualification](installed-browser-qualification.md#historical-mixed-version-evidence).
- The `0.5.6` candidate repins every engine dependency to
  `2b23bd55d14d36fe60073606869d75b4796c54f7` and adds a required
  `installed-browser-qualification-<commit>-linux-arm64` CI artifact. Exact
  code source `5a7683e70162220c8bfbdae9e8a7d4c3c37acf02` passed CI
  [31404782077](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31404782077),
  CodeQL
  [31404781059](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31404781059),
  and the available exact-artifact isolated Chromium checks. Current
  documentation-only main `d091bcf3ecd72ed36acdf17ce54dad80c3003bd0`
  passed CI
  [31409759063](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31409759063)
  and CodeQL
  [31409753614](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31409753614).
  A positive navigation with a preflighted DNSSEC/TLSA-qualified HNS origin
  remains required; `welcome` was only a synthetic routing hostname and failed
  closed against unavailable authority. Exact hashes and observations are in
  [installed-browser qualification](installed-browser-qualification.md#current-056-exact-artifact-evidence-partial).
- Local `0.6.1` and the current Unreleased source changes are not covered by
  those historical runs. They require fresh exact-head CI and CodeQL, an
  exact-artifact installed-browser rerun, and the release/signing gates below
  before they can be described as qualified or published.
- Native install, browsing, restart, upgrade, and complete removal on supported
  Windows and macOS versions;
- a current stable matrix for Chrome, Chromium, Edge, Brave, Vivaldi, and Opera;
- store signing, review, and published extension IDs; and
- release artifact provenance tied to the selected reviewed commit/tag.
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
  private-transport product integration, opaque engine authority, provider
  projection, and product qualification remain release blockers.
- The Chromium popup now renders a strictly sanitized, display-only projection
  of native wallet artifact admission. It accepts the exact ABI-v2 status
  contract and internally consistent stage/reason/metadata combinations, while
  any malformed status or asserted transport/runtime/provider availability
  becomes unavailable. This adds no native request or process launch: lock
  state, active wallet, and modules remain unavailable, and provider, value,
  and settlement remain disabled.
- The dormant Linux child-pipe controller now implements the ABI-v2 HNS read
  classes behind an exact singleton account selected from `listAccounts`:
  balance, receive target, bounded transaction history, and exact-ready module
  status. Request/response classes and session sequences remain correlated,
  malformed or non-HNS data poisons the private session, and independent value
  calls do not claim a coherent snapshot. A native-only aggregate executes the
  exact six operations in their fixed order and returns one minimized view
  while explicitly retaining those per-operation synchronization semantics.
- A dormant native-only Linux composition now joins signed-artifact launch,
  one generation-bound single-use `WalletBootstrapLease`, one explicit retained
  owner-private database identity, exact `--database <path>` arguments, a
  manifest-derived non-value capability ceiling requiring both
  `walletOperations` and the exact-six-operation `hnsReadOperationsV1` marker,
  ABI negotiation, and a monotonic kill-and-wait generation slot. The opaque
  bootstrap packet is neither read nor parsed by the browser; its read-only
  close-on-exec pipe is collision-safely installed only at child descriptor 3,
  while stdin/stdout stay ABI-only and the child environment stays empty.
  Database/path identity is rechecked around launch, negotiation, and every
  read, and the live child must retain that exact database inode. Poisoned
  reads remove their killed/reaped generation. The production source supplies
  no lease. No extension request, product configuration, provider, approval,
  unlock, mutation, or value path invokes the session; all public gates stay
  false. This first lease is launch authorization only, not ongoing broker
  revocation or wallet-database exclusivity.
- A Linux-only native fixture now demonstrates the complete dormant browser
  boundary: test-signed exact release admission, sealed launch, the expected
  opaque FD3 bootstrap, exact database argv and retained inode, ABI negotiation
  with `hnsReadOperationsV1`, and the fixed six HNS reads. The same test proves
  synchronous kill/reap on restart, stale-generation rejection without
  invalidating the replacement, and fail-closed kill/reap/removal after a
  database-inode replacement. It leaves the production lease source and all
  provider/value/public gates false.
- Exact interoperability with the checked-in wallet executable is still not
  demonstrated. It selects its locked control runtime; the HNS read runtime
  needs trusted unlock/account/authenticated-node inputs and does not advertise
  `hnsReadOperationsV1`. Broad `walletOperations` alone therefore still fails
  read-session admission. The source fixture is browser-boundary evidence, not
  a qualified wallet-service release or installed-product result.

Passing portable source gates is not a substitute for those release gates.

## Next engineering milestone

The popup now obtains the expected exact lowercase HNS label through a
separate explicit field, validates and hashes it before network I/O, and never
derives an endpoint from the active tab. That local selection is not yet a
native authority input and does not authenticate a feed.

Join the existing Chromium proof/sync runtime to the verifier without
fabricating `hns-light-chain::VerifiedHnsResource`. This requires either one
canonical proof authority shared by browsing and HNSA or a new engine-reviewed
adapter that preserves the private chainwork, current-anchor, exact-name, and
resource guarantees. The product must bind the independently selected name to
that native authority, add a serialized atomic and authenticated
rollback-resistant state store for the verifier's canonical blob, and expose
one native request that returns only the minimized committed snapshot. The
configured HTTP endpoint and proof objects served by it remain untrusted
transport input, never identity or state authority.

Installed-browser qualification must cover valid admission, malformed and
expired objects, identity mismatch, clock rollback, serial/sequence rollback,
sticky equal-sequence conflict across native-host restart, commit failure, and
authority rotation under a greater resource generation. Until that adapter,
store, request, UI, and qualification land, `meshmineVerifiedPoolStats` remains
false and the popup remains unverified.

Retain only the browser-specific listener, native-messaging, CA/TLS, lifecycle,
installer, and approval UI here. The first wallet product slice remains
non-value status, lock, and capability controls; private-transport product
integration, production wallet trust roots, native approval rendering, and
installed-browser qualification must land before provider installation. HNSR
transport,
discovery and persistence, value movement, settlement, and P2P marketplace
controls are separate later gates and remain disabled.

The current wallet-readiness panel completes only artifact-status presentation.
Source-level native launch/read composition now exists, but actual lock and
module presentation still requires a qualified production wallet release, an
explicit trusted configuration source, lifecycle ownership in the native host,
a new reviewed native/UI projection, and installed-browser qualification. It
remains a separate gated tranche.
