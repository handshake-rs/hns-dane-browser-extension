# Release administration

The tag-triggered workflow accepts only `v<manifest-version>` tags that point to
the exact current default-branch tip. It packages a keyless browser-neutral
Manifest V3 ZIP for first store submissions, a canonical-ID ZIP for GitHub and
unpacked use, and both native-host and graphical setup packages for Linux,
Windows, and macOS on x64 and arm64. Both extension ZIPs contain those same six
final Setup archives and a platform-selection index. The 14 deterministic archives have 14
checksum sidecars; `SHA256SUMS` is the twenty-ninth release asset. Before
publication, the publisher checks every remote name, nonzero size, and GitHub
SHA-256 digest against the locally verified file. It publishes only after all
portable, extension, and platform matrix jobs succeed.

Before delegating release authority or granting additional write access,
repository administrators should:

1. protect the default branch and require the `Required CI` check;
2. restrict creation and updates of `v*` tags to release maintainers;
3. configure the `release`, `macos-signing`, and `windows-signing` GitHub
   Actions environments with the documented protection and credentials;
4. review the tag commit, workflow changes, store identity, and release notes
   before approving that environment.

The canonical release/default extension ID and the public key from which it is
derived are recorded in `release/extension-identity.json`. Store catalogs can
assign different IDs. Set the public `CHROME_EXTENSION_ID`,
`EDGE_EXTENSION_ID`, and `OPERA_EXTENSION_ID` repository variables before
tagging when those IDs are known. The legacy `CHROMIUM_EXTENSION_ID` remains a
single-catalog compatibility input. Native bundles and Setup receive the
validated, deduplicated set with the canonical ID. The `-mv3.zip`
GitHub/unpacked package injects the public key into its
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

The tag workflow itself now contains protected, environment-scoped platform
jobs. Windows uses the project's persistent, pinned self-signed certificate to
Authenticode-sign and RFC 3161 SHA-256 timestamp each native host before
embedding it and each Setup executable afterward. macOS uses the approved
Developer ID Application identity, notarizes both products, and staples Setup.
Linux uses GitHub keyless artifact attestations. Only after all six Setup
archives are finalized does the read-only extension job embed them; only after
that does the `release` environment publish.

The manual replacement workflows remain for historical releases, including
v0.5.5. Current store packages cannot be finalized by replacing separate assets
after publication because their installer bytes are already inside the ZIP.

Windows signing uses the protected `windows-signing` environment. The encrypted
PFX and its password are environment secrets; only the public DER certificate
and its metadata are committed. The runner imports the key non-exportably into
its current-user store, signs by exact thumbprint, and deletes the key and
temporary PFX on every exit path. Verification temporarily trusts only the
committed public certificate, checks the exact certificate bytes, subject,
RSA-3072 key, code-signing EKU, embedded signature, timestamp, and SignTool
policy, then removes that temporary trust and confirms the files return to an
intact-but-untrusted state. Users' systems never install the publisher
certificate. It is not publicly trusted, so SmartScreen or **Unknown Publisher**
warnings remain expected; verify each archive SHA-256 and the published
certificate fingerprint.

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

The final write-enabled publisher and historical `replace` jobs use the
separate `release` environment. Its deployment policy permits only `main` and
`v*` tags. It currently has no required reviewer, so repository administrators
can add one if releases should pause for a second explicit approval.

Each Setup executable embeds the exact version-matched native host and the
hash-pinned height-300,000 mainnet header snapshot. Windows
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
