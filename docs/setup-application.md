# HNS DANE Browser Setup

HNS DANE Browser Setup is the user-facing installer, repair tool, status
viewer, and complete uninstaller for the Chromium extension's Rust native
host. It is built from this repository and shares the extension/native-host
version.

The setup program does not choose an operating system or CPU at runtime.
Releases provide six explicit targets:

- Linux x64 and arm64;
- Windows x64 and arm64; and
- macOS x64 and arm64.

Each target embeds the native-host executable produced for that same target,
the canonical mainnet header snapshot through height 300,000, and the exact
known catalog extension IDs supplied to the release build. Release setup
builds do not accept a runtime native-host or snapshot override, and the setup
application never downloads or substitutes executable code during
installation. Local payload overrides exist only in non-embedded development
builds.

## User flow

1. Install HNS DANE Browser in the intended Chromium catalog or load the
   canonical GitHub package.
2. On the extension's Setup page, choose **Save Setup**. The page selects the
   signed package embedded in the installed extension for the current
   operating system and CPU; it does not fetch an executable from the web.
3. Close the selected Chromium browsers and run the saved Setup application.
4. Confirm the detected browser selections and the release-baked extension
   IDs, then choose **Install or Repair**. The advanced ID field remains
   available for an explicitly reviewed catalog or managed-deployment ID.
5. Reopen the browser and verify **Rust security path active** and
   **DANE local CA: Installed** in the toolbar popup.

Different catalogs can assign different extension IDs. The release gate bakes
the canonical ID and every configured Chrome, Edge, and Opera catalog ID into
all six Setup applications. Setup accepts multiple exact IDs and registers
only those values. It does not infer identity by scanning browser profiles.
Unknown IDs are never discovered or silently authorized.

Browser selection expresses the Chromium-family compatibility the user
intends; it is not a promise that every flavor has a private registration
location. Chromium native-messaging contracts share some locations:

- Opera uses the Google Chrome compatibility location on Windows, and Setup
  writes both Opera's own location and the Chrome compatibility location on
  Linux and macOS.
- Brave and Vivaldi use their own locations on Linux and macOS. On Windows,
  Setup also writes their published Google Chrome fallback location.

Setup deduplicates concrete paths when multiple selected flavors share one.
Selecting one of these flavors can therefore create a registration where
Chrome also looks, even when Chrome was not selected. The manifest still
allows only the exact extension IDs supplied by the user. Browser selection
controls intended compatibility, while exact manifest ownership and content
control replacement and removal.

## Installation boundary

Setup performs a per-user installation:

- writes the version-matched native host to the product's private application
  data directory;
- verifies and imports the embedded mainnet header snapshot through height
  300,000 before reporting installation success;
- obtains the Native Messaging manifest from that installed executable;
- writes the native-messaging compatibility locations required by the
  selected Chrome, Chromium, Edge, Brave, Vivaldi, and Opera flavors, including
  the shared fallback locations described above;
- asks the native host to create or load the per-install P-256 CA;
- commits a bounded ownership transaction before changing the user trust
  store;
- installs that exact CA in the current user's Chromium-compatible trust
  store; and
- records the completed trust marker and atomic installation receipt only
  after the platform trust operation succeeds.

Failed trust installation therefore leaves the extension fail-closed. Setup
does not install an administrator-wide CA, alter system DNS, or grant a relay
or output-provider role.

Repair repeats the same bounded operation with the embedded native-host
version. Complete Uninstall removes only registrations owned by this
installation, the exact CA identified by its fingerprint, the native host,
private key material, runtime data, and setup receipt. Unsafe or ambiguous
removal roots are rejected. If installation was interrupted after trust
mutation but before the final receipt, Complete Uninstall uses the pre-trust
transaction to identify and remove only the recorded CA and registration.

The toolbar dropdown exposes **Complete Uninstall…** as a handoff to the
extension Setup page. That page saves the same platform-matched embedded Setup
package and instructs the user to close all supported browsers, run it, and
choose **Complete Uninstall**. Browser JavaScript never invokes the destructive
operation directly.

## Header bootstrap snapshot

The bundled `HNSHDRSNAP1` snapshot contains 300,001 mainnet headers from
genesis through height 300,000. It is not a full-block archive, transaction
archive, wallet, or precomputed name-state database. The compressed and raw
SHA-256 digests are pinned in `release/header-snapshot-300000.json`.

Setup verifies the compressed payload, streams it through a strict
70,800,287-byte output bound, verifies the raw digest, and gives the temporary
file only to the installed version-matched native host. The host then applies
its normal genesis, linkage, proof-of-work, difficulty, checkpoint, trailing
data, count, and exact-tip checks before committing header batches. The
temporary file is removed on success or failure. The operation is idempotent
when the local validated chain is already at or beyond height 300,000; peers
provide later headers and live proof-backed name state.

## Optional wallet service staging

The current Setup package does not contain or install a wallet service. The
native host recognizes `data/wallet-abi-v2` only as a fail-closed staging
location for a future independently released signed manifest-v2 adapter and
executable. The private host/service contract is ABI 2 while the website-facing
provider schema remains 1. The native host does not search for a wallet
elsewhere. Admission requires verifier-owned signer, exact release, and
anti-rollback floor configuration; all production tables are currently empty,
and the controller does not invoke the Linux sealed-execution primitive.

That version directory may contain only the staged adapter manifest and
artifact. Wallet databases, seeds, encryption keys, backups, logs, approvals,
and migration state must live in an independent wallet-owned location. A future
wallet installer must verify its signer and target, stage the artifact
transactionally with the manifest written last, and perform explicit
version-to-version migration. Setup repair must not copy, reinterpret, or
overwrite external wallet state.

Complete Uninstall removes the owned browser installation root, so it also
removes any manifest/artifact staged under `data/wallet-abi-v2` and its
browser-owned admission high-water record and empty coordination lock. That is
adapter cleanup, not wallet deletion. Setup must neither locate nor remove the
independent service's database, keys, backups, or other wallet-owned state.
Damaged, partial, unsigned, unsupported-platform, or ABI-incompatible staging
remains unavailable and cannot weaken browser/DANE operation. Artifact
authenticity, transport, runtime negotiation, engine authority, provider
availability, and value movement all remain false regardless of local staging.

## Bundling and operating-system dependencies

Rust application dependencies are linked into the setup executable. The
matching native host and canonical compressed header snapshot are embedded in
that executable, so they are covered by Windows Authenticode or macOS code
signing. The product license and third-party notices are part of each setup
package.

Windows uses current-user registry and certificate-store facilities supplied
by Windows. macOS uses the current user's login keychain and system security
facilities. Linux packages include the NSS certificate utility and its
non-system runtime libraries so users are not required to install
`libnss3-tools` or `nss-tools` separately. Kernel interfaces, graphics
drivers, and base operating-system libraries remain platform components. The
Linux Setup is built against glibc 2.39 and therefore requires glibc
2.39 or newer, such as Ubuntu 24.04 or Debian 13. The release gate inspects
every packaged ELF object so this ABI floor cannot drift above 2.39 unnoticed.

The manual shell and PowerShell installers remain in release native-host
archives as an expert, auditable offline fallback. They use fixed per-user
roots and bounded ownership checks, but have less transactional recovery than
Setup and may require expert cleanup after damaged metadata or a partial
failure. The Linux fallback requires system `certutil`, `base64`, and
`sha256sum`; uninstall checks the full exported certificate digest in both
permitted Chromium NSS database locations.

## Distribution limits

Chromium requires the user to approve installation of a catalog extension.
Setup neither opens catalog listings nor silently installs an extension. The
user must install the extension first through the intended catalog or
developer-mode workflow. Enterprise administrators can use browser policy for
a managed deployment.

ChromeOS and mobile Chromium do not support this desktop native-host
installation. Android and iOS are maintained in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

Store packages must never contain an unsigned Windows Setup executable or an
unnotarized macOS Setup application. The release graph finalizes and verifies
the project's pinned self-signed Windows Authenticode signatures and RFC 3161
SHA-256 timestamps, macOS Developer ID signatures/notarization/stapling, and
Linux build-provenance attestations before it assembles the extension ZIP. The
Windows publisher certificate is not publicly trusted and is never installed
on a user's machine, so SmartScreen or **Unknown Publisher** may still warn.
Verify the downloaded archive SHA-256 and the published certificate
fingerprint before running it. Missing signing authority blocks the release.
