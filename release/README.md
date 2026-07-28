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

The tag workflow contains no signing secrets. Automated Windows archives remain
unsigned. The tag workflow initially creates unsigned macOS archives; the
manual, default-branch-only `Replace macOS release assets with signed builds`
workflow can rebuild the same tagged source on x64 and arm64, sign it with the
approved Developer ID Application identity, submit both native hosts and setup
apps to Apple, staple the setup apps, and replace only the four macOS archives,
their four checksum sidecars, and `SHA256SUMS`. The workflow preserves the
release tag, source commit, title, version, and all non-macOS assets.

The published v0.5.4 macOS assets completed that default-branch workflow on
2026-07-28. Its credentialed signing jobs used the protected
`macos-signing` environment. Setup apps contain stapled tickets and standalone
native hosts use Apple's online notarization ticket. Windows v0.5.4 artifacts
remain unsigned.

The credentialed signing jobs use the protected `macos-signing` environment.
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
CRT where supported and otherwise use Windows components. The macOS setup is a
launchable `.app` with an `Info.plist`, executable, license, and notices; both
macOS binaries rely only on system frameworks. On Linux, the embedded native
host remains statically linked with musl while the eframe setup uses the native
GNU target in a runnable AppDir. That AppDir carries NSS `certutil`, all NSS/NSPR
modules and integrity files shipped by its package, an isolated helper
loader/shared-library closure, common X11/Wayland GUI client libraries, package
versions, hashes, and licenses. It never preloads bundled glibc into the setup
process, so the v0.5.4 Linux Setup requires the build baseline of glibc 2.39 or
newer (Ubuntu 24.04 / Debian 13 generation). The release gate rejects any
packaged ELF object requiring a later glibc version. Its clean-environment
release smoke test creates a temporary NSS
database and exercises certificate add/list/delete, so users do not need to
install `libnss3-tools`.
