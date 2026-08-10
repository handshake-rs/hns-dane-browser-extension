# Chromium Release Process

Tagged releases contain a keyless Manifest V3 package for first catalog
submissions, a canonical-ID package for GitHub/unpacked use, and six native
host bundles plus six graphical setup bundles for Linux, macOS, and Windows on
x64 and arm64. Each of the 14 archives includes immutable source metadata, the
product license, third-party notices, installation guidance, and a per-asset
checksum. The workflow publishes an aggregate `SHA256SUMS` as the twenty-ninth
asset only after every build and release gate succeeds.

The canonical GitHub-release extension ID is
`idejjnoplngbhpnpjekblpalblbianio`. Chrome Web Store, Microsoft Edge Add-ons,
and Opera Add-ons can assign different IDs. Always copy the exact ID shown by
the installed browser. The native-host installers accept multiple exact IDs
so one host can serve verified installations from more than one catalog.

## Publish

1. Make the manifest, package, Rust workspace, changelog, and documentation
   versions agree.
2. Run `bash scripts/check.sh`.
3. Commit and push the release source to the default branch, then require its
   exact CI and CodeQL runs to pass.
4. Download the exact SHA-keyed installed-browser artifact and complete the
   isolated-profile gate in
   [installed-browser qualification](installed-browser-qualification.md).
5. Create and push an annotated `v<version>` tag at that unchanged default
   branch tip.
6. Follow the tag-triggered `Release` workflow. It creates or reuses a draft,
   reruns the portable gate, builds all 14 required archives, verifies all 14
   checksum sidecars, generates the twenty-ninth asset (`SHA256SUMS`), checks
   GitHub's remote name, size, and SHA-256 digest for every asset against the
   local file, and publishes the release with the GitHub CLI.

For the version selected in the release commit:

```sh
release_version=X.Y.Z
git tag -a "v${release_version}" -m "HNS DANE Browser ${release_version}"
git push origin "v${release_version}"
gh run watch --repo handshake-rs/hns-dane-browser-extension
gh release view "v${release_version}" \
  --repo handshake-rs/hns-dane-browser-extension \
  --json isDraft,isPrerelease,url,assets
```

If any quality or platform job fails, the release remains a draft. Fix the
source in a new version; do not move a published version tag. A safe rerun of
the same failed workflow can replace draft assets only while the default
branch still points at that tagged commit; once `main` advances, fix and tag a
new version. A rerun cannot silently replace the source recorded by an already
published release.

Organization administrators should protect the default branch and `v*` tags,
restrict release-tag creation, and place the publisher job behind an approved
release environment before granting additional write access. Enable immutable
releases after all required platform-signing replacement is complete. Build and
packaging jobs remain read-only; only the final publisher receives repository
write permission.

The qualification CI artifact has no signing credentials and is not a release
asset. It exists to avoid a second local Rust build while preserving exact
source/native/extension identity. The current `0.5.6` code artifact has partial
exact-artifact observations recorded in
[installed-browser qualification](installed-browser-qualification.md#current-056-exact-artifact-evidence-partial),
but the positive known-good HNS/DANE navigation remains open. A later release
checkout must be qualified under its own SHA. None of the artifact's disabled
HNSA, HNSR, wallet-provider, value, or marketplace fields may be promoted by
the packaging job.

## Wallet service artifact qualification

The browser release and an independently released wallet service have separate
signing authorities. Do not add a production wallet key from a test fixture,
developer checkout, environment variable, manifest field, or owner-writable
configuration. A wallet-service release can be considered for admission only
after all of the following are reviewed from immutable release evidence:

1. The complete manifest matches the wallet repository's
   `signedArtifactManifestV2` contract and is emitted as RFC 8785 JCS. Its
   signature-omitted JCS payload hash and Ed25519 signature verify.
2. Source repository, clean commit/tree, source-archive digest, target triple,
   executable format, exact artifact size/digest, version, publication window,
   closed capabilities, release line, sequence, and predecessor manifest are
   independently reproduced. Qualification must also demonstrate a sane
   installation wall clock for not-before/expiry enforcement and either a
   self-contained service binary or a pinned, audited dynamic-loader and
   shared-library closure; sealing the main executable does not seal those
   runtime dependencies.
3. The signer root is added only to the verifier-owned production table with a
   bounded release-line sequence interval. The exact manifest/artifact release
   is separately pinned, and the compiled release-line floor is advanced
   monotonically. A trusted signer alone never qualifies an artifact.
4. The focused verifier suite covers canonical bytes, signature/root failure,
   mutable files, wrong native format, restart, state tamper, downgrade after
   complete ABI-directory replacement, concurrent sequence admission,
   path/root replacement, cached expiry/clock rollback, and sealed execution.
   The complete repository gate and Linux target qualification then pass at
   the exact browser commit.

The focused verifier filter passed at exact source
`a39f8759c0161b5e49cb93c0c5aea1f0298e3108`: 17 passed, 0 failed, and
24 filtered in the library target, with 0 main-target tests. Its first
invocation at `17d3efae6e0367e1f0ee2ef8cdafa67b5cdc20af` compiled
successfully but had 15 fixture-only
`walletArtifactDirectoryUnsafe` failures because the environment created the
test directories as `0775`; the 2 pure encoding tests passed. Production
correctly rejects that mode. `a39f8759` forced only test fixture directories
to `0700`, and the cached rerun passed. The exact command and target/temp paths
are recorded in [milestones](milestones.md#current-qualification-evidence-and-remaining-release-work).

The current tables are empty. Linux is the only implemented sealed-execution
boundary; macOS and Windows must stay unavailable until equivalent reviewed
ownership and immutable-execution mechanisms land. Even a launch-admitted
artifact must not make provider or value gates true until the private
child-pipe transport, exact runtime negotiation, browser-engine opaque
authority, public approval projection, restart lifecycle, and installed-browser
qualification all pass.
The focused filter is not the full repository gate, a release build/package,
installed-browser testing, or wallet product qualification and does not
authorize populating the production trust-root, release-pin, or floor tables.

## Setup application packages

Every setup application embeds the exact native-host binary built earlier in
the same target job. Packaging rejects a setup executable with the wrong file
format, architecture, Rust target, or embedded host bytes.

- Linux uses `HNS-DANE-Browser-Setup.AppDir/AppRun`. The embedded native host
  remains statically linked with musl, while the eframe setup uses the native
  GNU target. The AppDir includes a package-local `certutil`, NSS/NSPR modules
  and integrity files, an isolated helper loader/shared-library closure,
  package versions, hashes, and dependency licenses. The setup process uses the
  host's complete Wayland/X11/OpenGL stack; the AppDir contains no setup shared
  libraries and its launcher does not set `LD_LIBRARY_PATH`. This prevents host
  Mesa, NVIDIA, GLVND, or libdecor modules from binding to a mixed-version GUI
  dependency. The workflow rejects either packaging regression, tests every
  packaged ELF object against the current glibc 2.39 ABI ceiling, and tests the
  layout in a clean environment by creating an NSS database and adding, listing,
  and deleting a temporary certificate. A system `libnss3-tools` installation
  is not required, but Linux Setup requires glibc 2.39 or newer and common
  desktop GUI libraries (Ubuntu 24.04 / Debian 13 generation).
- Windows contains one self-contained GUI `.exe`. The build requests static
  Microsoft CRT linkage. The release gate enumerates every direct PE import,
  rejects dynamic CRT imports, permits Windows API-set contracts, and requires
  every concrete DLL or driver name to be explicitly allowlisted and present
  in `System32`.
- macOS contains a launchable `HNS DANE Browser Setup.app` with `Info.plist`,
  `Contents/MacOS/hns-dane-browser-setup`, license, and notices. Its linked
  dependencies, and those of the embedded native host, must be Apple system
  frameworks or `/usr/lib` libraries. Both architectures are built with
  `MACOSX_DEPLOYMENT_TARGET=11.0`; packaging records the same
  `LSMinimumSystemVersion`, and the release gate requires every Mach-O
  executable's `LC_BUILD_VERSION minos` to equal `11.0`.

The Windows and macOS target jobs also launch a real Setup window under a
30-second bound. Windows closes after its visible native window receives the
first operating-system redraw event, avoiding a hosted-runner dependency on a
hardware OpenGL context; normal Setup launches still use the complete eframe
renderer. macOS closes after the first rendered eframe GUI frame. The
credentialed replacement workflows retain a bounded normal-window fallback
solely for immutable tags that predate that smoke-test mode.

## Signing and store submission

The tag workflow creates unsigned Windows and macOS files first so ordinary
builds never receive signing authority. Two manual, default-branch-only
workflows can replace an existing published release's Windows or macOS x64 and
arm64 native-host and Setup archives without changing its tag, version, source
commit, title, or other platform assets.

The published v0.5.5 macOS x64 and arm64 assets completed this
default-branch-only flow on 2026-07-29. Its credential-bearing signing jobs
used the protected `macos-signing` environment. Their Setup apps carry stapled
tickets; their standalone native hosts use Apple's online notarization ticket.
Windows v0.5.5 assets remain unsigned until the Windows replacement workflow is
configured and completed.

### Windows Authenticode

The `Replace Windows release assets with Authenticode-signed builds` workflow
uses Azure Artifact Signing on an x64 Windows 2025 runner. It cross-builds the
ARM64 target because the signing action does not support Windows ARM runners.
The workflow signs and RFC 3161 SHA-256 timestamps each native host before
embedding it, then signs the Setup executable. It verifies the exact approved
certificate subject, timestamp certificate, Windows trust policy, SignTool
policy, and complete DLL allowlist before packaging. No exportable certificate
or private key enters GitHub.

Create a protected `windows-signing` GitHub environment restricted to `main`.
Configure a Microsoft Entra application with a GitHub Actions federated
credential for that environment, and assign its service principal the
`Artifact Signing Certificate Profile Signer` role at the narrow certificate
profile scope. Configure these non-secret environment variables:

- `AZURE_ARTIFACT_SIGNING_CLIENT_ID`
- `AZURE_ARTIFACT_SIGNING_TENANT_ID`
- `AZURE_ARTIFACT_SIGNING_SUBSCRIPTION_ID`
- `AZURE_ARTIFACT_SIGNING_ENDPOINT`
- `AZURE_ARTIFACT_SIGNING_ACCOUNT_NAME`
- `AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE`
- `WINDOWS_AUTHENTICODE_PUBLISHER`

`WINDOWS_AUTHENTICODE_PUBLISHER` must be the complete certificate subject
reported by `Get-AuthenticodeSignature`, including its exact ordering and
punctuation. The workflow authenticates through GitHub OIDC and Azure CLI only;
it does not accept an Azure client secret.

Run and follow the manual workflow with:

```sh
release_tag=vX.Y.Z
gh workflow run resign-windows-release.yml \
  --repo handshake-rs/hns-dane-browser-extension \
  --ref main \
  -f release_tag="$release_tag" \
  -f confirm_replacement=true
gh run watch \
  --repo handshake-rs/hns-dane-browser-extension \
  --exit-status
```

The Windows publisher downloads and verifies all 29 current release assets
before any write, retains a workflow-artifact backup, uploads nine replacements
under temporary names, verifies their GitHub SHA-256 digests, then swaps only
the four Windows archives, their sidecars, and `SHA256SUMS`. It verifies all 29
final names, sizes, and digests and updates the release signing disclosure.

### macOS Developer ID

The workflow normalizes the stored modern OpenSSL 3 PKCS#12 certificate into
an ephemeral legacy-compatible import bundle protected by a one-time password.
It verifies the pinned certificate name, SHA-256 fingerprint, and Team ID,
then resolves `codesign` to the one imported SHA-1 keychain identity that
matches that certificate. It signs each native host before embedding it,
signs each Setup app with hardened runtime and a trusted timestamp, queues the
two notarization submissions together, and polls for up to 19,800 seconds
while tolerating transient Apple status-network failures. It requires
`Accepted`, staples and validates the Setup app, extracts the final tarball
again, and repeats code-signing, stapler, and Gatekeeper checks. Submission
IDs, status, and logs remain workflow evidence even after a failed job. Apple
does not support stapling a ticket directly to a standalone executable.

Create a protected `macos-signing` GitHub environment restricted to `main`, and
configure these environment secrets:

- `APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64`
- `APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD`
- `APPLE_NOTARY_API_PRIVATE_KEY_P8_BASE64`

Configure these non-secret environment variables:

- `APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_NAME`
- `APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_SHA256`
- `APPLE_TEAM_ID`
- `APPLE_NOTARY_API_KEY_ID`
- `APPLE_NOTARY_API_ISSUER_ID`

The final `replace` jobs use a separate `release` environment and
`contents: write`. Protect that environment, restrict it to `main`, and require
maintainer approval before treating asset publication as
environment-protected. Both workflows reject a non-default-branch dispatch and
require explicit confirmation, exact tag/source/version identity, and
post-replacement digest verification.

The issuer ID must be copied from App Store Connect under **Users and Access >
Integrations > App Store Connect API > Team Keys** for the Team key matching
the configured API key ID. It cannot be derived from a certificate, Team ID,
or `.p8` file. The Developer ID certificate bundle's password is needed only
for the `.p12` import. App Store Connect `.p8` Team keys are unencrypted; do not
create or configure a second password for that file.

Set the binary credential secrets without placing their values in shell
history:

```sh
base64 -w0 developerID_application.p12 |
  gh secret set APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64 \
    --env macos-signing \
    --repo handshake-rs/hns-dane-browser-extension
base64 -w0 AuthKey_9944D8P9RY.p8 |
  gh secret set APPLE_NOTARY_API_PRIVATE_KEY_P8_BASE64 \
    --env macos-signing \
    --repo handshake-rs/hns-dane-browser-extension
read -rsp 'Developer ID .p12 password: ' HNS_P12_PASSWORD
printf '\n'
printf %s "$HNS_P12_PASSWORD" |
  gh secret set APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD \
    --env macos-signing \
    --repo handshake-rs/hns-dane-browser-extension
unset HNS_P12_PASSWORD
```

After configuring the issuer ID, run and follow the manual workflow with:

```sh
release_tag=vX.Y.Z
gh workflow run resign-macos-release.yml \
  --repo handshake-rs/hns-dane-browser-extension \
  --ref main \
  -f release_tag="$release_tag" \
  -f confirm_replacement=true
gh run watch \
  --repo handshake-rs/hns-dane-browser-extension \
  --exit-status
```

The macOS publisher follows the same backup, temporary-upload, digest-check,
and exact-swap process for only the four macOS archives, their sidecars, and
`SHA256SUMS`.

Repository automation does not submit store dashboards. Publisher accounts,
domain verification, final catalog IDs, privacy declarations, review, and
store signing remain credentialed release steps. Submission copy and artwork
are maintained in [`store/`](../store/README.md).

Donations are optional and do not unlock features:

- GitHub Sponsors: <https://github.com/sponsors/denuoweb>
- HNS:
  `handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`
