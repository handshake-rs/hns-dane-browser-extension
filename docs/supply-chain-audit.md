# Build and Supply-Chain Audit

Last audited: 2026-08-10

## Scope

This audit covers the Chromium extension, Rust native host, Rust desktop Setup
application, active Cargo workspace, user-level installers, and generated
desktop notices. Mobile build and release evidence is maintained in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

## Locked inputs and policy

- Rust is pinned to toolchain 1.92.0.
- Cargo metadata, build, test, Clippy, cargo-deny, and notice generation use
  the committed `rust/Cargo.lock` with `--locked`.
- Cargo Git dependencies are denied except for the exact reviewed
  `handshake-rs/hns-dane-engine` revision and its exact reviewed
  `handshake-rs/hns-rs` authority dependency revision; other dependencies
  resolve only from checksum-verified registries.
- Exactly five canonical engine packages are required:
  `hns-browser-runtime`, `hns-browser-observability`, `hns-icann-dane`,
  `hns-namespace-resolution`, and `hns-resolution-policy`.
- Every canonical package and private Chromium adapter is pinned and locked to
  engine version `0.2.0` at that same revision.
- The source-policy verifier and its negative tests reject unreviewed Git
  inputs, moving engine or HNSA-authority revisions, canonical registry
  fallbacks, and different locked versions.
- cargo-deny reviews active licenses, advisories, bans, and sources.
- Node.js 22 or later is required for extension lint, tests, and the unpacked
  Manifest V3 build.
- External GitHub Actions are pinned to full commit SHAs. Normal policy,
  build, test, and packaging jobs have read-only permissions; only the
  final release publishers receive the narrowly required release-write
  permission. The macOS signing jobs themselves run behind the
  default-branch-restricted `macos-signing` environment; the final asset
  replacement job uses the separate `release` environment described below.
- Dependabot watches GitHub Actions and Cargo.

The default-branch-only macOS replacement workflow normalizes a modern OpenSSL
3 PKCS#12 credential into an ephemeral legacy-compatible import bundle with a
one-time password, then selects the one keychain identity matching the pinned
SHA-256 certificate and its exact SHA-1 signing identity. Native-host and
Setup notarization submissions are queued together and conservatively polled
through transient Apple status-network failures. Submission IDs, status, and
logs are retained even when a signing job fails.

The `macos-signing` environment is branch-restricted. The final `replace` job
has `contents: write` and uses the `release` environment, which currently has
no environment protection rules or branch policy. Workflow validation still
requires an explicit replacement confirmation, the canonical repository,
current default branch, exact tag/source/version identity, and bounded asset
replacement. Protect and default-branch-restrict the `release` environment to
make publisher approval enforcement match the signing-job boundary.

## Notices

The notice generator inventories the locked non-development dependency
closures of `hns-chromium-native-host` and `hns-browser-setup` for Linux,
macOS, and Windows. It records license text for registry dependencies,
canonical engine dependencies, and exact HNSA authority dependencies; includes
fingerprinted reviewed standard-license texts when a published crate omits its
workspace-level copy, fingerprints active manifests
and the lock, and checks the committed notice digest. The license policy also
explicitly permits the Setup GUI's Boost, CC0, Open Font, and Ubuntu Font
licenses.

`extension/THIRD_PARTY_NOTICES.txt` is copied into the unpacked extension and
installed beside the native host and Setup application. A notice mismatch is
a release failure.

## Required portable gates

```sh
python3 -m unittest -v \
  tests/test_cargo_git_policy.py \
  tests/test_browser_qualification_provenance.py
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
HNS_NATIVE_HOST_PATH="$PWD/rust/target/release/hns-chromium-native-host" \
  cargo +1.92.0 build --locked --release \
    --manifest-path rust/Cargo.toml -p hns-browser-setup \
    --features embedded-host
npm run check:extension
```

CI has separate policy, Rust/native-host, extension, and Linux arm64
installed-browser-input jobs plus a required aggregate result. The latter
packages the exact static host and canonical extension, verifies their inner
source/platform identity and secret-free boundary, and uploads the SHA-keyed
artifact described in
[installed-browser qualification](installed-browser-qualification.md). A
release must record the exact commit and exact-current-main CI run; historical
runs or artifact creation do not qualify later source.

Exact-current-main release commit
`86b18497285753944ec1b9196ec05ee359c6db11` passed
[CI run 30435346299](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/30435346299).
The tag workflow published all 29 verified `v0.5.5` assets in
[run 30435936597](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/30435936597).
The default-branch macOS replacement, including its protected credentialed
signing jobs, then passed in
[run 30436887463](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/30436887463).
Future releases must repeat rather than inherit these dated results.

Consolidated browser source
`ae702ebdea59050dd9395636f549ff9c2b8f2e4b` later passed
[CI run 31394858244](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31394858244)
and
[CodeQL run 31394857474](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31394857474).
Its isolated Chromium run used an older incompatible host and is preserved
only as browser-code/fail-closed evidence. Final `0.5.6` code source
`5a7683e70162220c8bfbdae9e8a7d4c3c37acf02` subsequently passed exact CI
[31404782077](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31404782077),
CodeQL
[31404781059](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31404781059),
and the available exact-artifact isolated-profile checks. The positive
HNS/DANE origin remained open because the synthetic `welcome` origin was not a
reachable DNSSEC/TLSA-qualified service. Documentation-only main
`d091bcf3ecd72ed36acdf17ce54dad80c3003bd0` then passed exact CI
[31409759063](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31409759063)
and CodeQL
[31409753614](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31409753614).
See the exact hashes and retained boundary in
[installed-browser qualification](installed-browser-qualification.md#current-056-exact-artifact-evidence-partial).

## Residual risks

- Release archives and their inventory are deterministic for identical staged
  inputs. Cross-run bit-for-bit reproducibility of compiled native-host and
  Setup binaries is not yet established.
- Hosted runner images, host C toolchains, operating-system certificate tools,
  archive metadata, and signing can vary.
- cargo-deny depends on the RustSec advisory database available at check time.
- Installer unit tests and package-structure gates do not replace real
  user-level registration, trust, restart, upgrade, and removal tests on every
  Windows and macOS target.
- The exact-SHA Linux arm64 CI bundle removes local-build ambiguity but still
  depends on a hosted runner and does not prove installation, browser behavior,
  x64, Windows, macOS, or store distribution until the corresponding target
  gates are run.
- Store signing and review require external credentials and policy decisions;
  source CI must not fabricate their completion. The published v0.5.5 macOS
  native-host and Setup assets completed Developer ID signing and Apple
  notarization on 2026-07-29; Windows artifacts remain unsigned.
- An immutable Git revision is stronger than a branch selector but still
  requires deliberate review before changing either pinned HNS source commit.
