# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Changed

- Switched the five canonical `hns-dane-engine` contracts from the reviewed
  Git revision to exact, checksum-verified crates.io `0.1.0` packages and
  marked every desktop Rust application package non-publishable.
- Activate the authenticated native proxy before a potentially long initial
  header catch-up. ICANN browsing can continue through Rust while HNS requests
  remain fail-closed until current corroborated header evidence is available.
- Reuse exact insecure ICANN origin RRset evidence for the defined WebPKI
  fallback without issuing an unauthenticatable TLSA lookup, while retaining
  mandatory TLSA discovery for signed origins that alias into unsigned targets.
- Migrate exact legacy native-messaging manifests and clean up
  ownership-checked external-extension registrations and Chromium launch
  wrappers so removing the extension remains persistent across browser
  restarts.
- Align the source-only Chromium wallet boundary to private ABI v2 while
  retaining website provider schema v1: stage only from `wallet-abi-v2`,
  validate all 12 typed approval-summary variants, reject inline result events,
  accept events only through the service channel, and bind approval-window
  rejection or closure to its exact in-memory dispatch context.
- Adopt wallet approval schema v3, including the required bounded `hnsNames`
  disclosure, exact canonical HNS name and SHA3-256 hash validation, and trusted
  rendering of every disclosed name/hash pair.
- Accept permission generation zero in a private native capability snapshot
  for a never-authorized origin without relaxing native event or exact
  wallet-session binding.
- Consume the wallet-owned signed-artifact manifest schema v2 at the Chromium
  boundary, including exact JCS bytes, signature-omitted payload hashing,
  Ed25519 verification, verifier-owned release pins/floors, stable atomic
  per-release-line anti-rollback state with interprocess serialization,
  launch-time signed-window revalidation, retained path binding, and a
  Linux-only sealed-executable launch primitive.

### Security

- Keep wallet injection fail-closed while the browser engine lacks a consumable
  opaque provider-authority context and no signed canonical wallet service
  executable/transport exists. Caller-supplied authority-shaped fields are not
  authentication, and stale page requests are never retried automatically.
- Admit optional Unix wallet adapter staging through current-user-owned,
  no-follow opened handles with bounded schema-v2 manifests, closed/unique
  capability validation, single-link immutable-file checks, same-handle
  hashing, pinned Ed25519 authenticity, and exact release qualification. Linux
  execution is copied and rehashed into a sealed memfd; Windows and macOS
  execution remain unavailable pending reviewed platform equivalents.
- Invalidate wallet document and approval authority before header maintenance,
  and re-derive exact browser authority after awaited native capability,
  request, and approval results before publishing any completion or event.
- Keep the production wallet trust-root, exact release-pin, and release-floor
  tables empty. Private transport, runtime negotiation, engine authority,
  provider availability, and value movement remain false; the controller does
  not invoke the admission-only launcher.

## 0.5.5 - 2026-07-29

### Changed

- Added an OIDC-backed Azure Artifact Signing workflow that Authenticode-signs
  and RFC 3161 SHA-256 timestamps Windows x64 and arm64 native hosts before
  embedding them, signs the Setup executables, verifies signer and timestamp
  policy, and transactionally replaces only the nine affected release assets.
- Enumerate every Windows PE import in release builds, reject dynamic Microsoft
  CRT linkage, and require every concrete DLL or driver to be an explicitly
  allowlisted Windows `System32` component.
- Pin both macOS release architectures to
  `MACOSX_DEPLOYMENT_TARGET=11.0`, record the floor in each Setup app, and
  require every release Mach-O binary's `LC_BUILD_VERSION` to match it.
- Added bounded real-window startup smoke tests for Windows and macOS Setup
  builds, including signed-asset compatibility for immutable older tags.
- Added a manual, default-branch macOS release-signing workflow that rebuilds
  an existing tag without changing its version, signs and notarizes x64 and arm64
  native hosts and Setup apps, staples Setup tickets, verifies the final
  archives with Gatekeeper, and replaces only the nine affected release assets
  after retaining and validating the published release.
- Added explicit release metadata and installation guidance for Developer ID
  signed native hosts using Apple's online ticket and signed Setup apps carrying
  a stapled ticket.
- Normalize modern OpenSSL 3 PKCS#12 bundles into a legacy-compatible,
  ephemeral copy before macOS keychain import, avoiding Security.framework's
  misleading bad-password rejection without weakening the stored credential.
- Resolve `codesign` against the one exact imported certificate hash after
  matching both its SHA-256 fingerprint and SHA-1 keychain identity.
- Queue native-host and Setup notarization submissions together, tolerate
  transient Apple status-network failures with conservative polling, and
  retain notarization evidence from failed signing jobs.

### Security

- Authenticate Windows signing through a protected, default-branch-scoped
  `windows-signing` environment and GitHub OIDC, with no exportable signing key
  or Azure client secret in GitHub. Pin the expected certificate subject and
  verify the resulting signature and RFC 3161 timestamp with Windows trust
  policy and SignTool.
- Pin the allowed Developer ID certificate name, SHA-256 fingerprint, and Team
  ID before signing; import it only into an ephemeral CI keychain.
- Keep the certificate bundle, import password, and App Store Connect Team key
  in the protected, default-branch-scoped `macos-signing` environment. Verify
  temporary and final GitHub asset names, sizes, and SHA-256 digests around
  replacement. Protect the separate write-enabled `release` environment before
  claiming environment-enforced publisher approval.

## 0.5.4 - 2026-07-27

### Changed

- Moved bounded header synchronization into a private staged database so
  network I/O, quorum collection, snapshot preparation, and peer merging no
  longer hold the live proxy's maintenance gate.
- Added a generation- and tip-bound SQLite delta journal. Normal one-block
  publication now validates and commits only the new header and canonical
  suffix instead of rescanning the complete chain database.
- Refresh authenticated target evidence ten minutes before its hard expiry,
  while retaining the independently enforced two-block currentness limit.

### Fixed

- Removed the Manifest V3 suspend teardown that could leave Chromium's PAC
  pointing at a native listener the extension had just disconnected.
- Made every native-host replacement transition from the live mandatory PAC
  to a confirmed fixed blocking PAC before disconnecting the captured process,
  then to the replacement PAC. No startup, failure, or retry path clears proxy
  control to system or direct routing.
- Bound PAC writes, native callbacks, status adoption, header maintenance, and
  alarm mutations to explicit control and connection generations. Late work
  from an old runtime can no longer disconnect a replacement or overwrite its
  PAC, refresh deadline, or hard-expiry alarm.
- Kept a live proxy active through transient, due-but-unexpired sync and status
  failures. Authenticated evidence expiry remains an independent fail-closed
  transition even while a native synchronization request is hung.
- Added process-wide header and peer publication locks, fixed-size crash-state
  tokens, conditional publication, exact three-way peer merging, stale-stage
  reclamation, and recovery from interrupted `UPDATING` state.
- Avoided holding the peer database lock across network probes and added
  bounded SQLite busy handling for concurrent runtime access.
- Reported CONNECT backend failures with their actual status and observability
  classification instead of mislabeling them as malformed browser requests.

### Security

- Reject conditional header publication when its baseline marker, delta
  coverage, parent linkage, proof of work, chainwork, or canonical suffix is
  missing, conflicting, or tampered.
- Validate native refresh envelopes, including exact zero-work coalesced
  responses, before treating a synchronization attempt as successful.
- Added executable lifecycle race tests for dropped PAC callbacks, late
  mutations, native generation replacement, alarm ordering, evidence expiry,
  and stale status isolation.

## 0.5.3 - 2026-07-27

### Added

- Added HNS DANE Browser Setup as a version-matched Rust desktop application
  for Linux, macOS, and Windows on x64 and arm64. Each target embeds the exact
  native host built for that target and the release publishes a separately
  labeled Setup archive for every supported operating-system/CPU pair.
- Added graphical Install or Repair, Status, and Complete Uninstall flows for
  Chrome, Chromium, Edge, Brave, Vivaldi, and Opera, together with equivalent
  command-line automation. Setup accepts multiple explicit store-specific
  extension IDs and never scans browser profiles to infer them.
- Added first-run copy-ID and exact-version Setup download guidance. Manual
  native-host archives and shell/PowerShell installers remain available for
  managed deployment and troubleshooting.

### Changed

- Bundled the matching NSS `certutil` executable and its required non-system
  libraries in Linux Setup packages. Windows uses a self-contained Rust
  executable with the static CRT where supported, while macOS uses standard
  system frameworks. Linux Setup retains the base operating-system ABI and
  requires glibc 2.39 or newer (Ubuntu 24.04 / Debian 13 generation).
- Extended deterministic release manifests, checksums, dependency notices,
  CI, privacy disclosures, store-review notes, and platform documentation to
  cover the Setup application.
- Normalized generated PNG metadata so repeated store-artwork builds are
  byte-for-byte deterministic.

### Security

- Kept installation per-user and limited it to explicitly selected browser
  registrations and exact validated 32-character extension IDs. Setup writes
  manifests and its ownership records atomically, installs only its exact
  generated CA, verifies effective platform trust, and retains a pre-trust
  ownership history across repeated interrupted repairs so uninstall can still
  remove older exact CA and registration hashes.
- Hardened the expert Linux manual fallback to compare the complete exported
  certificate digest and inspect both permitted Chromium NSS database
  locations during uninstall.
- Kept the native executable, CA key material, runtime state, and browser
  registration inside the existing Rust security boundary; the extension
  package still contains no executable or private key.

## 0.5.2 - 2026-07-26

### Changed

- Pinned the canonical browser-runtime, observability, ICANN-DANE,
  namespace-resolution, and resolution-policy contracts to
  `handshake-rs/hns-dane-engine` revision
  `7f7bb8fa100c2393f2cd5a64c64bf5e20a0f3ab5`.
- Added a new blank-by-default `recursiveHnsDohUrl` consent boundary. A
  user-configured endpoint is generation-bound and is attempted only after
  direct authoritative UDP/TCP, proof-anchored owner authoritative DoH, and
  any separately opted-in requester-only P2P relay are unavailable.
- Bootstrapped configured resolver hostnames only through fixed-address
  validating ICANN DoH, then connected to an explicit public address while
  retaining WebPKI validation for the configured hostname. No configured
  endpoint is prefilled or contacted while the setting is blank.
- Added the shared HNS DANE icon, first-install native-host setup, exact
  source/license/privacy/support/donation links, store listing copy and
  artwork for Chrome/Brave/Vivaldi, Edge, Opera, and Chromium, and tagged
  GitHub Release packaging for browser-neutral and native-host artifacts.

### Fixed

- Preserved each complete hostname's bounded HNS and ICANN
  present/absent/failed dispositions when dual-root classification fails,
  without retaining or reconstructing successful origin plans.
- Reported a typed HNS port-53 interception failure when the HNS root has a
  transport failure and the same request contains a positive TEST-NET canary;
  missing or inconclusive probes remain generic and fail closed.
- Limited configured-recursive and P2P recovery to typed transport
  unavailability or confirmed interception. DNS response codes, malformed
  replies, bogus DNSSEC, relay DNSSEC failure, and missing or stale proof/chain
  state remain terminal and cannot be masked by a later transport.
- Preserved successful proof-contained HNS main-frame results with the honest
  non-network `LocalHnsProof` provenance instead of dropping their details for
  lack of a delegated-DNS trace. The popup now shows the latest main frame
  before the complete Header chain panel.
- Rendered confirmed port-53 interception failures as hardened, paragraph-
  separated HTML with a per-name HNS DANE generator link. The handoff includes
  a nameserver only when it came from the authenticated HNS delegation, and
  unrelated gateway failures remain plain text.
- Bound popup security receipts to the active Chromium tab and document.
  Back/forward-cache and same-document history keep only that document's
  immutable Rust receipt; disk-cache reuse requires an exact URL receipt from
  the same runtime and header-maintenance epoch. Header sync keeps the receipt
  for an already committed document but cannot authorize a new cached page.
- Correlated Rust's decision-only ICANN WebPKI CONNECT observations with
  successful Chromium main-frame completion without fabricating a Rust HTTP
  status or main-frame claim. The popup now labels Chromium's end-to-end
  WebPKI ownership, retained-tunnel and cache provenance, while the
  authoritative native maintenance epoch revokes new reuse after every header
  sync attempt. Native status filters both HTTP and CONNECT observations by
  their stored epoch, preserving new-epoch results that race sync completion
  while rejecting late old-epoch callbacks.
- Bypassed local certificate issuance for selected ICANN WebPKI fallback.
  Chromium now carries its TLS handshake through an exact-IP, independently
  pumped raw CONNECT tunnel and displays the origin certificate. Socket-open,
  invariant, canonical-status, registry, cancellation, and unexpected backend
  failures are pre-TLS denials and cannot downgrade back to the local CA.
- Retried selected ICANN WebPKI CONNECTs across bounded, rotating batches of
  authenticated public A/AAAA endpoints under one aggregate timeout. Each
  socket's actual peer must match the retained endpoint set, and canonical
  authority is rechecked before every dial.
- Advanced WebPKI endpoint rotation by one when the complete endpoint plan
  fits in a single batch, so repeated tunnels do not retry the same failed
  first address.
- Retried internally constructed RFC 8484 POSTs once on a fresh exact-IP
  connection when an idle pooled ICANN or configured-recursive DoH socket is
  stale. Generic POST requests remain non-replayable.
- Scheduled header synchronization from the native quorum-evidence deadline,
  two minutes before the last three independent peer groups can expire.
  The existing health alarm remains the safety check. Routine stale or unknown
  state retains the ten-minute attempt floor, while a failed or manual attempt
  near a known deadline gets bounded one-minute retries through two minutes
  after expiry so it cannot suppress the only pre-expiry refresh opportunity.
- Prevented a retained urgent window from postponing an already-due routine
  refresh after a wall-clock rollback; retained deadline context can now only
  accelerate maintenance.

### Security

- Kept configured recursive RFC 8484 responses inside the local HNS
  DNSSEC/TLSA/DANE validation path and ignored resolver AD as trust evidence.
  Historical public-recursive values are tombstoned rather than migrated.
- Added explicit UI disclosure that a configured operator can observe qnames,
  qtypes, timing, and source IP. P2P requester consent remains independent
  from every relay/output-provider role.

## 0.5.1 - 2026-07-26

### Added

- Added full-host dual-root resolution for every ordinary DNS HTTP(S)/WS(S)
  request routed by syntax-only PAC, with HNS-only, ICANN-only, convergent,
  divergent, neither, and indeterminate outcomes.
- Added generic ICANN DANE through validating ICANN DoH. TLSA owners are
  derived from the effective host, port, and transport; secure TLSA is
  enforced, authenticated denial or an unsigned delegation uses WebPKI, and
  bogus DNSSEC fails closed.
- Added checked, versioned Chromium security results sourced from the Rust
  response-publication boundary, including namespace choice, chain
  currentness, actual DNS transport, HNS proof, DNSSEC, TLSA/DANE,
  intermediary identity, policy, and monotonic runtime authority.
- Added a Chromium header-chain panel that separates the globally validated
  tip, corroborated target, raw highest peer claim, schedule estimate, lag,
  and page-specific proof anchor, plus an explicit `Sync headers now` action.

### Changed

- Split current Android and iOS development into
  `handshake-rs/hns-dane-browser-mobile`; this repository now contains only
  the Chromium extension, native host, and their Rust support.
- Pinned the canonical browser-runtime, observability, ICANN-DANE,
  namespace-resolution, and resolution-policy contracts to
  `handshake-rs/hns-dane-engine` revision
  `fe38e805ba9d8ba26d486c5c7aa67c87c8cf9159`.
- Kept the browser's P2P DNS-relay requester behind explicit consent:
  unchecked maps to `Disabled` and checked maps to direct-authority-first
  `Auto`. The browser advertises no provider service.
- Made Chromium health checks preserve a healthy proxy generation instead of
  rotating credentials and reinstalling the PAC on every alarm.
- Decoupled live chain freshness from the 144-block proof-cache/reorganization
  retention window. Browser HNS decisions now require the validated tip to be
  within two blocks of a recent multi-address-group peer target; an unavailable
  target is unknown and fails closed rather than being treated as current.
- Isolated persisted header-height observation time from general peer
  liveness, so proof retrieval, relay traffic, and unvalidated version claims
  cannot refresh or promote currentness evidence.
- Added stale-aware background header synchronization with a bounded
  ten-minute attempt cadence. Status refreshes and popup opens remain local and
  do not themselves poll Handshake peers.

### Fixed

- Bound normal and upgraded response-head publication to the exact header
  maintenance epoch used during validation. Header sync, cache clearing,
  snapshot installation, or header reset now invalidates any prepared response
  that has not yet been published.
- Kept direct authoritative UDP/TCP 53 first when usable. A positive matching
  TEST-NET interception canary now stops futile TCP and remaining port-53
  attempts, classifies that path as unavailable, and continues through
  independently authenticated proof-pinned authoritative DoH. A timeout or
  inconclusive probe does not classify interception or authenticated absence.
- Made HNS HTTPS/SVCB evaluate supported protocols in the effective RFC 9460
  ALPN set in `h3` → `h2` → `http/1.1` order, including the HTTPS default
  unless `no-default-alpn` is present, with transport-scoped TLSA owners. Only
  securely authenticated TLSA absence may advance to the next protocol;
  bogus DNSSEC remains terminal, and valid UDP TLSA retains HTTP/3.

### Security

- Bound each request and every output boundary to one canonical runtime
  session, runtime generation, policy generation, and monotonic admission
  event. Stale response heads, bodies, downloads, tunnels, and status are
  rejected after authority changes.
- Partitioned connection pools, TLS/resumption state, and Alt-Svc state by the
  exact namespace-decision fingerprint.
- Removed IANA suffix membership as an authoritative namespace classifier.
  The list is a performance hint only and cannot bypass full-host HNS/ICANN
  resolution.
- Kept HNSR, P2P ODoH, unsupported privacy downgrades, and provider roles
  unimplemented and fail-closed.

## 0.5.0 - 2026-07-16

### Added

- Added an opt-in Handshake P2P DNS relay protocol, bounded `hsd` responder integration, Rust requester, Android and iOS runtime controls, deterministic cross-language fixtures, and fast and full four-node regtest acceptance tiers.
- Added manual Android relay-peer configuration with live capability verification and persisted peer state.

### Changed

- Enabled the P2P DNS relay by default for new Android installs while retaining the independent legacy HNS DoH compatibility fallback for networks whose peers have not upgraded.
- Bumped the Android app, shared Rust core, Apple shell, Play upload defaults, and store metadata package to 0.5.0 (build 40).

### Security

- Kept relay peers untrusted: validated headers and Urkel proofs, delegated DNSSEC, negative proofs, HTTPS/SVCB policy, TLSA, and DANE certificate matching remain local to the browser.
- Added proof-gated admission, public-authority filtering, bounded rate and concurrency controls, strict response correlation, query-minimizing diagnostics, and failover away from unavailable or malformed relay peers.

## 0.4.1 - 2026-07-15

### Changed

- Updated the repository and in-app source-code links to the renamed cross-platform GitHub repository.
- Bumped the Android app and Play release package to 0.4.1 (build 39) while retaining the unchanged Rust engine and Apple shell at 0.4.0.
- Made CI select Rust, Android, and Apple gates from the changed paths, with shared Rust changes still validating both platform packages.

## 0.4.0 - 2026-07-15

### Added

- Added a stable versioned Apple C ABI, deterministic device/simulator Rust builds, XCFramework packaging, C/C++ header/export checks, and a macOS build and simulator gate using the stable iOS 26.5 SDK with Xcode 26.5 or 26.6.
- Added an iOS 17.0-or-later UIKit/WKWebView shell using the same Rust runtime, resolver, HNS/DNSSEC/DANE policy, proxy parser, TLS terminator, and persistent state as Android.
- Added a fail-closed whole-browser Rust proxy mode for WebKit, with authenticated admission, optional immutable HNS scope, bounded explicit-bootstrap WebPKI DoH for ICANN addresses, public-address and unsafe-port enforcement, opaque CONNECT, streamed HTTP forwarding, and WebSocket Upgrade tunneling without system target DNS.

### Changed

- Centralized browser special-use hostname policy in `hns-core` and shared it across classification, HNS resolution, and proxy admission.
- Kept Android on its exact HNS-scoped proxy mode while exposing platform-neutral classifier, root extraction, live challenge matching, and typed status APIs to both native shells.
- Kept the iOS deployment floor at 17.0 to support the iOS 17 and iOS 18 generations independently of the iOS 26.5 build SDK; Xcode 26.5 and 26.6 are accepted for that Apple build gate.
- Bumped the Android app, Rust core, Apple shell, Play upload defaults, and store metadata package to 0.4.0 (build 38).

### Security

- Added monotonic opaque Apple handles, bounded Rust-owned buffers and mailboxes, panic-contained C exports, one active proxy per runtime, policy/start race protection, immediate stop revocation, and joined runtime-owned teardown.
- Added an optional signed physical-device validation matrix for extra confidence in WebKit proxy isolation, server-trust challenges, Service Workers, WebSockets, lifecycle changes, and renderer/network-process restarts. Simulator validation does not satisfy this matrix, and no physical-device pass is claimed.

## 0.3.16 - 2026-07-14

### Added

- Added generic HNS-proof-pinned RFC 8484 authoritative DoH so an owner can use an HNS hostname such as `https://denuoweb:8443/dns-query`, connect through verified HNS nameserver GLUE, and authenticate a self-signed endpoint without an ICANN domain or WebPKI.
- Added exact toolbar provenance for `DANE via ADoH`, `DANE via DNS53`, `DANE via 3rd DoH`, `Stateless DANE`, `DANE via ICANN DoH`, and the corresponding non-TLS HNS paths.

### Changed

- Ordered HNS delegated resolution for availability: owner ADoH first, authoritative UDP/TCP 53 second, and the configured third-party HNS DoH resolver last in Compatibility mode; Strict mode omits only that final third-party fallback.
- Bumped the Android app, Rust core, Play upload defaults, and Play metadata package for the 0.3.16 release.

### Fixed

- Distinguished certificate-carried stateless DANE from DNS-fetched TLSA and made resolver traces follow the exact A/AAAA and TLSA transports, including IPv6-only origins and HTTPS/SVCB-selected ports.
- Rejected spoofed internal provenance headers and prevented them from being exposed to Chromium or page content.

## 0.3.15 - 2026-07-14

### Fixed

- Added exact transport-owned `Content-Length` metadata to non-empty HTTP/2 and HTTP/3 request bodies, restoring proof-bootstrapped authoritative DoH interoperability with servers that require it while preventing caller-supplied length mismatches.

### Changed

- Bumped the Android app, Rust core, Play upload defaults, and Play metadata package for the 0.3.15 release.

## 0.3.14 - 2026-07-14

### Changed

- Changed the default compatibility DoH resolver from the failing global HNSDoH pool to the working Zorro node while keeping the resolver user-configurable.
- Bumped the Android app, Rust core, Play upload defaults, and Play metadata package for the 0.3.14 release.

## 0.3.13 - 2026-07-14

### Added

- Added in-app third-party software notices generated deterministically from the locked Android release runtime and shipping Rust dependency closure, with complete license text and integrity checking.
- Added a release-bundle gate for exact native ABI inventory, 16 KiB bundle/ELF alignment, ELF hardening and bounds, stripped shipping libraries, matching FULL native debug symbols and Build IDs, path sanitization, R8 mapping, notices, and upload-certificate signing.

### Security

- Hardened the native release build against caller-supplied compiler, linker, and Cargo profile overrides; pinned NDK r28c; remapped local checkout, tool-home, and NDK paths; and made AGP responsible for stripping while retaining Play Console symbols.

### Fixed

- Added proof-anchored `hnsdns=1` authoritative DoH bootstrap metadata so delegated HNS names can reach their RFC 8484 endpoint without first relying on interceptable UDP/TCP port 53; origin answers still require delegated DNSSEC validation against the HNS-proven DS.
- Added a bounded TEST-NET DNS sentinel probe and resolver-trace field that can positively identify transparent port 53 interception without treating a timeout as proof that the network is clean.
- Allowed RFC 9461 DNS-server SVCB records to use a distinct WebPKI-authenticated target name while retaining the HNS-proven nameserver glue address for the connection.
- Expanded the deletion controls to clear WebView origin storage with cookies and to clear the persisted gateway diagnostic log, with updated in-app privacy disclosure.
- Replaced the automatically loaded remote default homepage with a bundled start page that contains no network resources; user-configured homepages remain supported.
- Moved adaptive launcher icons to the API-compatible resource directory and removed obsolete notification, service, privacy, resolver-trace, and cookie-only localized strings.

### Changed

- Bumped the Android app, Rust core, Play upload defaults, and Play metadata package for the 0.3.13 release.

## 0.3.12 - 2026-07-13

### Fixed

- Retried delegated authoritative DNS over TCP when UDP answers fail DNSSEC validation, preserving fail-closed DNSSEC behavior while recovering from UDP-only DNS path corruption.
- Bumped the Android app, Rust core, Play upload defaults, and Play metadata package for the 0.3.12 release.

## 0.3.11 - 2026-07-12

### Fixed

- Kept automatic HNS header sync alive while navigating between browser, settings, diagnostics, and sync screens; it now stops only when the whole app leaves the foreground, and the HNS Sync screen follows automatic status updates live.
- Added the missing localized cleartext-HTTP warning in every declared app language so the warning bar no longer fails Android lint or falls back to English.

### Changed

- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.11 release.

## 0.3.10 - 2026-07-12

### Security

- Removed the insecure HNS DNS result opt-in. HNS gateway resolution requires verified HNS/DNSSEC data again; cleartext `http://` remains a transport choice only after secure name resolution.
- Added a persistent yellow warning bar for `http://` pages to make cleartext transport visible separately from HNS resolution status.

### Fixed

- Stabilized HNS gateway page loads by falling back from failed Alt-Svc promotion, avoiding unsafe DoH POST promotion, preserving identity-encoded WebView gateway assets, and normalizing root main-frame URL status matching.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.10 release.

## 0.3.9 - 2026-07-12

### Fixed

- Restricted insecure HNS resolution opt-in to cleartext HNS origins; HTTPS and WSS HNS origins still fail closed on unsigned HNS address, HTTPS/SVCB, or TLSA/DANE resolution.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.9 release.

## 0.3.8 - 2026-07-12

### Security

- Blocked native origin, authoritative DNS/DoH, and advertised P2P connections to non-public endpoints on mainnet/testnet, enforced the browser unsafe-port policy, and kept explicit regtest-only development exceptions.
- Authenticated the randomized loopback proxy, limited it to the active HNS origin, blocked alternate loopback literals, made exported launcher input extra-blind, and required a user gesture before external-scheme intents.
- Enforced same-origin redirect following, strict WebSocket handshake/frame/close validation, bounded WebSocket sessions and queues, bounded response/download/cache stores, and fail-closed Service Worker behavior when proxy authentication is unavailable.
- Pinned and verified Rust, Gradle, Android, CI Action, dependency, and release-signing inputs; added read-only CI, Dependabot coverage, secret checks, strict lockfiles, and cryptographic AAB signer verification.

### Fixed

- Fixed native WebSocket upgrade headers and clean-close handling, HTTP/1 informational/framing/trailer parsing, HTTP/2 and HTTP/3 body/header limits and timeouts, unsafe pooled-request replay, and caller header normalization.
- Fixed unchecked header-height arithmetic, JNI request/read length validation, stale or unbounded transport state, delegated DNS source validation, and complete current IANA/special-use name classification including `.internal`.
- Fixed Android lifecycle leaks and sync/cache races, unbounded browser history/download fields, staged-file cleanup, oversized header-snapshot extraction, and release lint failures for experimental API opt-in and locale plural resources.

### Changed

- Removed the ICANN DANE TXT-shadow compatibility fallback. The hardcoded ICANN DANE test host now uses native DNSSEC TLSA only, while delegated HNS authoritative DoH continues to use RFC 9461 `_dns.<nameserver>` SVCB discovery.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.8 release.

## 0.3.7 - 2026-07-08

### Changed

- Disabled spellcheck, suggestions, and personalized learning for the browser omnibar so Android keyboards treat it as a URI/search field instead of prose.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.7 release.

## 0.3.6 - 2026-07-08

### Changed

- Kept HNS sync active only while the app is open, removed the persistent phone sync notification, hid completed sync progress until header resync, enlarged the browser menu, aligned the main toolbar with the top of the app, and moved header resync into HNS Sync settings.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.6 release.

## 0.3.5 - 2026-07-08

### Added

- Added Android locale resources for English, Spanish, French, German, Portuguese, Japanese, Arabic, Persian, and Hebrew.
- Added Android per-app language configuration and a Settings entry for Android's system app-language picker.

### Changed

- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.5 release.

## 0.3.4 - 2026-07-07

### Added

- Added an off-by-default experimental Settings flag for stateless HNS DANE certificate evidence using certificate-carried Urkel proof and RFC 9102 DNSSEC-chain extensions against recent local tree roots.

## 0.3.1 - 2026-07-06

### Changed

- Set the default Android homepage to `https://denuoweb/homepage` and removed the bundled static homepage asset.
- Bumped the Android app, Rust core, network user-agent strings, Play upload defaults, and Play metadata package for the 0.3.1 release.

## 0.3.0 - 2026-07-06

### Changed

- Bumped the Android app, Rust core, network user-agent strings, and Play upload defaults for the 0.3.0 release.

## 0.2.9 - 2026-07-06

### Added

- Replaced `hnsdns=1` HNS TXT discovery with RFC 9461 `_dns.<nameserver>` SVCB discovery for RFC 8484 authoritative DoH endpoints on delegated nameservers, used after direct UDP/TCP 53 and validated against the HNS-proven DS chain.
- Added resolver trace and Android diagnostics labels for authoritative DoH attempts and malformed RFC 9461 DoH discovery records.

### Changed

- Rebranded the unreleased Android app to HNS DANE Browser with launcher label HNS DANE, package ID `com.denuoweb.hnsdane`, and GitHub package references under `Denuo-Web/hns-dane-browser-android`.
- Replaced the launcher, Play icon, feature graphic, and in-app brand assets with the centered HNS DANE mark.

## 0.2.8 - 2026-07-04

### Added

- Added a configurable compatibility DoH resolver setting for portable HNS resolution across arbitrary networks.

### Fixed

- Validated delegated HNS DNSSEC over DoH transport locally against HNS DS records instead of relying on resolver AD bits.
- Accepted DoH responses with compressed RRSIG signer names.
- Validated inline child-zone signed answers and no-data proofs for delegated HNS zones.
- Kept optional HTTPS/SVCB policy lookup failures from blocking secure A/TLSA/DANE validation.

## 0.2.7 - 2026-06-30

### Changed

- Updated the bundled HNS directory homepage organization and footer copy.

## 0.2.6 - 2026-06-30

### Fixed

- Kept refreshed HNS WebSocket pages from receiving stale native events from the previous page instance.

## 0.2.5 - 2026-06-30

### Fixed

- Bridged HNS WebSockets through the native HNS gateway so single-label HNS pages can open `wss://` connections with resolver, HTTPS service, and DANE validation instead of relying on Android WebView's WebSocket TLS stack.

## 0.2.4 - 2026-06-30

### Changed

- Audited the bundled HNS homepage with resolver trace, HNS proof, TLSA, and DANE checks; removed non-working entries and added Denuo Web as a core direct-authoritative HNS site.
- Updated Denuo Web infrastructure to advertise HTTP/3 through DNS HTTPS records and showcase HTTP/3 plus WebSocket echo support.

### Fixed

- Kept regular origin HTTP reads on the normal response timeout instead of the shorter tunnel idle timeout.
- Avoided stale DoH transport promotion state across Android resolver fallback queries.
- Submitted omnibox Enter on key-down and forced focus back to WebView so the keyboard closes reliably.

## 0.2.3 - 2026-06-30

### Security

- Hardened Android WebView startup, optional WebKit feature usage, Service Worker interception, renderer recovery, and non-HTTP(S) navigation handling.
- Hardened the Android loopback gateway so it refuses broad WebView proxy fallback when host-scoped reverse-bypass support is unavailable.
- Restricted loopback gateway handling to active HNS host/subdomain scope and rejected non-HNS proxy traffic with fail-closed responses.
- Removed release stack-trace printing from the loopback accept path and kept diagnostics bounded through the gateway event log.

### Changed

- Updated `androidx.activity:activity-ktx` from `1.12.0-alpha05` to stable `1.13.0`.
- Updated production-readiness and security-model documentation for the stricter loopback proxy posture.

### Fixed

- Made the Android FFI live-proof cache-miss test deterministic by persisting the synthetic peer height before selection.
- Addressed the current Rust clippy warning in the Android FFI fallback marker.
