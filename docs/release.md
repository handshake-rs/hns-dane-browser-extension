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
   exact CI run to pass.
4. Create and push an annotated `v<version>` tag at that unchanged default
   branch tip.
5. Follow the tag-triggered `Release` workflow. It creates or reuses a draft,
   reruns the portable gate, builds all 14 required archives, verifies all 14
   checksum sidecars, generates the twenty-ninth asset (`SHA256SUMS`), checks
   GitHub's remote name, size, and SHA-256 digest for every asset against the
   local file, and publishes the release with the GitHub CLI.

For example:

```sh
git tag -a v0.5.4 -m "HNS DANE Browser 0.5.4"
git push origin v0.5.4
gh run watch --repo handshake-rs/hns-dane-browser-extension
gh release view v0.5.4 \
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

## Setup application packages

Every setup application embeds the exact native-host binary built earlier in
the same target job. Packaging rejects a setup executable with the wrong file
format, architecture, Rust target, or embedded host bytes.

- Linux uses `HNS-DANE-Browser-Setup.AppDir/AppRun`. The embedded native host
  remains statically linked with musl, while the eframe setup uses the native
  GNU target. The AppDir includes a package-local `certutil`, NSS/NSPR modules
  and integrity files, an isolated helper loader/shared-library closure,
  common GUI client libraries, package versions, hashes, and dependency
  licenses. The AppDir does not bundle `libwayland-client.so.0`; it uses the
  host copy so host Mesa graphics backends cannot resolve against an older,
  incompatible Wayland client. It does not preload bundled glibc into setup.
  The workflow tests every packaged ELF object against the v0.5.4 glibc 2.39
  ABI ceiling and tests the layout in a clean environment by creating an NSS
  database and adding, listing, and deleting a temporary certificate. A system
  `libnss3-tools` installation is not required, but Linux Setup requires glibc
  2.39 or newer (Ubuntu 24.04 / Debian 13 generation).
- Windows contains one self-contained GUI `.exe`. The build requests static
  Microsoft CRT linkage and rejects dynamic CRT imports; only Windows
  components may remain.
- macOS contains a launchable `HNS DANE Browser Setup.app` with `Info.plist`,
  `Contents/MacOS/hns-dane-browser-setup`, license, and notices. Its linked
  dependencies, and those of the embedded native host, must be Apple system
  frameworks or `/usr/lib` libraries.

## Signing and store submission

The automated Windows executables are currently unsigned. The tag workflow also
creates unsigned macOS files first so ordinary builds never receive Apple
credentials. Run the manual `Replace macOS release assets with signed builds`
workflow from the default branch to replace an existing published release's
macOS x64 and arm64 native-host and Setup archives without changing its tag,
version, source commit, title, or non-macOS assets.

The published v0.5.4 macOS x64 and arm64 assets completed this
default-branch-only flow on 2026-07-28. Its credential-bearing signing jobs
used the protected `macos-signing` environment. Their Setup apps carry stapled
tickets; their standalone native hosts use Apple's online notarization ticket.
Windows v0.5.4 assets remain unsigned.

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

The final `replace` job uses a separate `release` environment and
`contents: write`. That environment currently has no approval rules or branch
policy, so protect it and restrict it to `main` before treating asset
publication as environment-protected. The workflow itself already rejects a
non-default-branch dispatch and requires explicit confirmation, exact
tag/source/version identity, and post-replacement digest verification.

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
gh workflow run resign-macos-release.yml \
  --repo handshake-rs/hns-dane-browser-extension \
  --ref main \
  -f release_tag=v0.5.4 \
  -f confirm_replacement=true
gh run watch \
  --repo handshake-rs/hns-dane-browser-extension \
  --exit-status
```

The publisher downloads and verifies the current 29 release assets before any
write, retains a workflow-artifact backup, uploads all nine replacements under
temporary names, verifies their GitHub SHA-256 digests, then swaps only the four
macOS archives, their sidecars, and `SHA256SUMS`. It finally verifies all 29
published names, sizes, and digests.

Repository automation does not submit store dashboards. Publisher accounts,
domain verification, final catalog IDs, privacy declarations, review, and
store signing remain credentialed release steps. Submission copy and artwork
are maintained in [`store/`](../store/README.md).

Donations are optional and do not unlock features:

- GitHub Sponsors: <https://github.com/sponsors/denuoweb>
- HNS:
  `handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`
