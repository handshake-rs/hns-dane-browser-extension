# Build and Supply-Chain Audit

Last audited: 2026-07-26

> Most mobile evidence below is historical. The active workflow in this
> extraction is Chromium-only: it always runs repository/supply-chain policy,
> the Rust workspace and release native-host build, the Node extension
> lint/tests/build, and a required aggregate gate. Android, Apple, TestFlight,
> and screenshot jobs were removed from this repository's workflow graph.

## Configured and Local Gates

- The checked-in GitHub Actions workflow always runs the Chromium policy, Rust/native-host, and extension gates. Its permissions are read-only, release secrets are not provided, every non-local `uses:` reference is pinned to a full commit SHA, checkout credentials are not persisted, and concurrent runs on the same ref are cancelled. Historical evidence: the earlier `0.4.1` cross-platform tree passed every selected job in [run 29477163745](https://github.com/Denuo-Web/hns-dane-browser/actions/runs/29477163745); that run does not validate this checkpoint.
- Dependabot watches GitHub Actions and the active Cargo workspace weekly.
- Rust uses toolchain `1.92.0`; metadata, build, test, Clippy, and cargo-deny commands use the committed root lock with `--locked`. Registry packages carry Cargo checksums.
- The root workspace lock contains exactly three reviewed Cargo Git packages: `hns-icann-dane`, `hns-namespace-resolution`, and `hns-resolution-policy`, all from one immutable `handshake-rs/hns-dane-engine` revision. The dedicated verifier and nine negative/positive policy tests reject another package, URL, declaration location, alias, moving selector, or lock revision.
- cargo-deny permits only the canonical engine Git URL and reviews the active workspace's licenses, advisories, bans, and sources.
- The Chromium notice generator takes the union of the locked non-development `hns-chromium-native-host` dependency closures for Linux, macOS, and Windows. It reproduces registry and canonical engine license text, fingerprints the active manifests and lock, and commits a full-asset SHA-256.
- `extension/THIRD_PARTY_NOTICES.txt` is copied into the unpacked extension build and beside the installed native host on Linux, macOS, and Windows. CI verifies it without requiring a dependency cache.
- The active workflow runs the exact-source policy tests/verifier, notice integrity, cargo-deny, workspace formatting/Clippy/tests, a release native-host build, all extension tests, and the unpacked MV3 build. Its required aggregate job fails unless every gate succeeds.
- Historical mobile supply-chain scripts and inputs remain in this clone pending the reviewed repository trim. They are not Chromium release authority.

## Audit Results

### Current Chromium `0.5.0` Candidate

- The extension, native host, and Rust workspace declare `0.5.0`.
- The active native-host graph consumes the three exact-pinned engine contracts above. Direct authoritative UDP/TCP precedes authenticated authoritative DoH and policy-admitted relay fallback.
- The generated desktop notice inventories 163 external Cargo components for Linux and macOS and 168 for Windows; its committed SHA-256 is recorded in `scripts/third-party-notices.sha256`.
- Focused qualification results for the final source checkpoint are retained in `docs/chromium-extension.md` and the ecosystem evidence repository. Hosted current-main CI remains required before release.

### Historical mobile `0.5.0` evidence

- Android declares `0.5.0` / code 40 and the shared Rust workspace declares `0.5.0`. This is not a metadata-only release: it changes the shared resolver/P2P runtime and Android behavior.
- The complete local `scripts/check.sh` gate passed on 2026-07-16, including supply-chain and version checks, warning-denied Clippy, all three cargo-deny scopes, the full Rust workspace tests, fuzz smoke, iOS C ABI tests, and the header-snapshot exporter. The final requester review and focused P2P suite also passed after closing query-profile, handshake-bound, forward-status, and peer-height issues.
- Android passed 192 unit tests plus debug and release lint with no errors. A clean committed-tree build using Gradle 9.6.1, AGP 9.2.1, compile/target SDK 37, build-tools AAPT2 36.1.0, and NDK `28.2.13676358` passed R8/resource shrinking and the unsigned and upload-signed bundle gates.
- The scripted isolated topology and bounded load tier passed, followed by the real four-`hsd` regtest tier at height 91 with a registered `relaytest` name, four matching chain/tree states, verified Urkel inclusion, local DNSSEC and DANE, HTTPS 200, bad-to-good relay failover, and no legacy DoH sentinel contact. The focused `hsd` responder suite passed 47 tests with ESLint clean.
- Hosted path-policy, Rust, cold-cache Android, Apple, and required-result jobs are pending for the exact candidate commit.
- The final upload-signed code 40 APK verifies with APK Signature Scheme v2 and the established single RSA-4096 certificate SHA-256 `D2:2F:F3:25:17:53:11:EB:E6:D6:E9:3D:A3:FD:F5:1D:84:89:22:A1:B8:1A:CB:B3:2F:22:39:CC:F9:4A:51:14`; it passes 16 KiB ZIP alignment. Its SHA-256 is `bff5ba468b0c5ad2d134603127f089ad6fdc9e9b5ceab921825e570cfefd60fb`.
- The final upload-signed AAB passed content-signature, exact ABI inventory, 16 KiB ELF alignment, hardening, stripping, matching Build ID/debug-symbol, local-path, mapping, and notices gates. Its SHA-256 is `96c5926c559881ba74e380eea062dce3de6cefaf91d3753882e528cccc96e1d0`.
- The separate debug test APK uses package `com.denuoweb.hnsdane.relaytest`, version `0.5.0-relay-test` / code 40, and SHA-256 `019aeb82b84de878716637fd053321a4590e0c384de3010e885af7e154803990`.
- The exact signed release could not be installed because the previously attached Pixel 9 physically disconnected from USB before the install step. Device acceptance remains pending and is not inferred from build or host-side tests.
- Third-party notices and their committed fingerprint were regenerated for the `0.5.0` Rust/dependency graph and passed the checked-in integrity gate.
- Release signing and Play upload remain intentional secret-dependent gates. CI should build and structurally verify the release variant without signing credentials and must not publish.

### Historical `0.4.1` Evidence

- `scripts/check.sh` passed locally on 2026-07-15 for Android `0.4.1` with shared Rust engine `0.4.0`, including supply-chain/version checks, formatting, clippy with warnings denied, all three cargo-deny scopes, the complete Rust test matrix, fuzz-target compilation, and the header-snapshot exporter.
- The final `0.4.1` Android build passed 187 unit tests, debug and release lint with zero errors, R8/resource shrinking, upload signing, APK signature and 16 KiB ZIP-alignment verification, and both release-bundle gates. It used Gradle 9.6.1 / AGP 9.2.1, compile/target SDK 37, NDK `28.2.13676358`, and build-tools AAPT2 36.1.0. The signed AAB SHA-256 was `4b2cc8b1da7700675eedb1ed2319ccafd9541acc7114abff9bd60eb6399b4267`; the signed APK SHA-256 was `a5a9d50d5b19302af488f7f5e6c68281364070edc7edcb14e16dbb1e1a5d61a2`.
- Independent artifact inspection confirmed both installed JNI libraries were NDK r28c API 34 ET_DYN files, stripped, 16 KiB-aligned, RELRO, non-executable-stack, immediate-binding, text-relocation-free, and paired with unstripped `.dbg` files carrying the same Build IDs. No checkout/home/NDK path was found; the signed release APK passed 16 KiB ZIP alignment.
- The shared-runtime tree passed 5/5 connected Pixel instrumentation tests plus live `https://denuoweb/` and `https://aboutlife/` DNSSEC/DANE acceptance. The exact signed `0.4.1` APK subsequently upgraded the Pixel 9 from code 38 to code 39 and cold-launched its main activity successfully.
- cargo-deny reported no known advisory, source, or license-policy failures for the shipping workspace, fuzz workspace, or exporter. Duplicate transitive versions and unused allow-list entries remained warnings.
- No high-confidence secret or secret-bearing filename was found among tracked files.
- The locally configured upload certificate SHA-256 matched the retained and published `0.4.0` APK signer and the `0.4.1` APK. It still needs an out-of-band comparison with the upload certificate shown by Play Console for the next release.
- GitHub Actions [run 29477163745](https://github.com/Denuo-Web/hns-dane-browser/actions/runs/29477163745) passed the `0.4.1` code and build-policy tree before the evidence-only documentation update. Actions is disabled and `main` has neither branch protection nor a ruleset, so this is historical execution evidence rather than a continuously enforced control.

## Residual Risks

- This audit pins inputs but does not establish bit-for-bit reproducible APK/AAB output. Runner images, the JDK 21 patch release selected by setup-java, Android SDK packaging, archive timestamps, and signing can still vary. A future release process should compare independently built unsigned artifacts before signing.
- Gradle verification metadata was generated from artifacts already obtained over the configured HTTPS repositories. Future checksum changes require a deliberate review; the metadata is an integrity pin, not independent provenance proof.
- cargo-deny relies on the current RustSec advisory database at check time. CI availability or an upstream advisory-database outage can affect results.
- The local JNI script defaults to and enforces NDK `28.2.13676358`; `HNS_ANDROID_NDK_VERSION` may override that expectation only for an intentional, reviewed toolchain change.
- The upload certificate fingerprint is public configuration, but its approved value still needs an out-of-band comparison with the Play Console upload certificate before the next release.
