# Release administration

The tag-triggered workflow accepts only `v<manifest-version>` tags that point to
the exact current default-branch tip. It packages a keyless browser-neutral
Manifest V3 ZIP for first store submissions, a canonical-ID ZIP for GitHub and
unpacked use, and both native-host and graphical setup packages for Linux,
Windows, and macOS on x64 and arm64. The 14 deterministic archives have 14
checksum sidecars; `SHA256SUMS` is the twenty-ninth release asset. Before
publication, the publisher checks every remote name, nonzero size, and GitHub
SHA-256 digest against the locally verified file. It publishes only after all
portable, extension, and platform matrix jobs succeed.

Before delegating release authority or granting additional write access,
repository administrators should:

1. protect the default branch and require the `Required CI` check;
2. restrict creation and updates of `v*` tags to release maintainers;
3. configure the `release` GitHub Actions environment with required maintainer
   approval; and
4. enable immutable releases only after any required signing replacement has
   completed; then
5. review the tag commit, workflow changes, store identity, and release notes
   before approving that environment.

The canonical release/default extension ID and the public key from which it is
derived are recorded in `release/extension-identity.json`. Store catalogs can
assign different IDs. Set the public `CHROMIUM_EXTENSION_ID` repository variable
to an exact catalog ID before tagging when one is known. Native bundles register
both the canonical ID and that catalog ID; the installers also accept additional
exact IDs. The `-mv3.zip` GitHub/unpacked package injects the public key into its
packaged manifest so unpacked installations derive the canonical ID. The
`-mv3-store.zip` first-submission package remains keyless so each catalog can
assign its own ID. No private key is distributed in either package.

Required source CI separately retains a 14-day, exact-commit Linux arm64
installed-browser-input artifact containing the static raw host, its canonical
archive, the canonical-ID extension ZIP, checksum sidecars, and
machine-readable provenance. It receives no credentials, is not a published
release asset, and must be exercised only in a disposable profile as documented
in
[`docs/installed-browser-qualification.md`](../docs/installed-browser-qualification.md).

The tag workflow contains no signing authority and initially creates unsigned
Windows and macOS archives. Two manual, default-branch-only replacement
workflows can rebuild the same tagged source on x64 and arm64. The Windows flow
uses GitHub OIDC and Azure Artifact Signing to Authenticode-sign and RFC 3161
SHA-256 timestamp each native host before embedding it and each Setup
executable afterward. The macOS flow uses the approved Developer ID Application
identity, notarizes both products, and staples the Setup apps. Each publisher
replaces only its four platform archives, four checksum sidecars, and
`SHA256SUMS`, preserving the release tag, source commit, title, version, and all
other assets.

The published v0.5.5 macOS assets completed that default-branch workflow on
2026-07-29. Its credentialed signing jobs used the protected
`macos-signing` environment. Setup apps contain stapled tickets and standalone
native hosts use Apple's online notarization ticket. Windows v0.5.5 artifacts
remain unsigned until the Windows replacement workflow is configured and
completed.

Windows signing uses the protected `windows-signing` environment, an Entra
federated identity, and the narrowly scoped Artifact Signing Certificate
Profile Signer role; no exportable key or client secret is stored in GitHub.
The approved exact certificate subject is pinned and every signed executable is
checked with PowerShell trust policy and SignTool, including its timestamp.

The macOS credentialed signing jobs use the protected `macos-signing`
environment.
Store the certificate bundle, its password, and App Store Connect private key
only as the environment secrets documented in `docs/release.md`. Store the
approved certificate identity, fingerprint, Team ID, API key ID, and Team API
issuer ID as environment variables. It imports the certificate into an
ephemeral keychain after normalizing modern OpenSSL 3 PKCS#12 input into an
ephemeral legacy-compatible bundle with a one-time password. It verifies the
pinned SHA-256 fingerprint and Team ID, selects the exact corresponding SHA-1
keychain identity for `codesign`, queues native-host and Setup notarization
submissions together, and tolerates transient Apple status-network failures
during bounded polling. It destroys the keychain after each job and retains
submission IDs, status, and logs as workflow artifacts, including after
failure. The `.p8` key is unencrypted API key material; no `.p8` password is
used.

The final write-enabled `replace` job uses the separate `release` environment;
that environment currently has no approval or branch rules and must be
protected before the asset publisher can be described as
environment-protected.

Each setup executable embeds the exact version-matched native host. Windows
setup executables and their embedded native hosts statically link the Microsoft
CRT where supported. Every concrete imported DLL is explicitly allowlisted as
a `System32` component, while Windows API-set contracts are recognized
separately. The macOS setup is a launchable `.app` with an `Info.plist`,
executable, license, and notices; both macOS binaries rely only on system
frameworks, target macOS 11.0, and are inspected for an exact
`LC_BUILD_VERSION` floor. Native Windows and macOS release jobs launch the real
Setup window under a 30-second bound. On Linux, the embedded native
host remains statically linked with musl while the eframe setup uses the native
GNU target in a runnable AppDir. That AppDir carries NSS `certutil`, all NSS/NSPR
modules and integrity files shipped by its package, an isolated helper
loader/shared-library closure, package versions, hashes, and licenses. The setup
process uses the host's complete Wayland/X11/OpenGL stack and does not prepend an
AppDir library directory. This keeps Mesa, NVIDIA, GLVND, libdecor, X11/XCB,
Wayland, and the compiler runtime from resolving against a mixed-version
userspace stack. Linux Setup requires glibc 2.39 or newer and common
desktop GUI libraries (Ubuntu 24.04 / Debian 13 generation). The release gate
rejects setup shared libraries, a launcher-level `LD_LIBRARY_PATH`, and any
packaged ELF object requiring a later glibc version. Its clean-environment
release smoke test creates a temporary NSS database and exercises certificate
add/list/delete, so users do not need to install `libnss3-tools`.
