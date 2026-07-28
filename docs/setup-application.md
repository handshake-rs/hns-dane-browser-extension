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

Each target embeds the native-host executable produced for that same target.
Release setup builds do not accept a runtime native-host override, and the
setup application never downloads or substitutes executable code during
installation. A local payload override exists only in non-embedded development
builds.

## User flow

1. Install HNS DANE Browser in the intended Chromium catalog or load the
   canonical GitHub package.
2. Open the extension's Setup page and copy the exact 32-character extension
   ID shown there.
3. Download the setup package matching the operating system and CPU.
4. Close the selected Chromium browsers.
5. Paste one or more exact extension IDs, select the installed Chromium
   flavors, and choose **Install or Repair**.
6. Reopen the browser and verify **Rust security path active** and
   **DANE local CA: Installed** in the toolbar popup.

Different catalogs can assign different extension IDs. Setup accepts multiple
exact IDs and registers only those values. It does not infer identity by
scanning browser profiles.

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

## Bundling and operating-system dependencies

Rust application dependencies are linked into the setup executable. The
matching native host, product license, and third-party notices are part of
each setup package.

Windows uses current-user registry and certificate-store facilities supplied
by Windows. macOS uses the current user's login keychain and system security
facilities. Linux packages include the NSS certificate utility and its
non-system runtime libraries so users are not required to install
`libnss3-tools` or `nss-tools` separately. Kernel interfaces, graphics
drivers, and base operating-system libraries remain platform components. The
v0.5.4 Linux Setup is built against glibc 2.39 and therefore requires glibc
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

Automated Windows and macOS setup artifacts must be described as unsigned
until project-controlled Authenticode and Apple Developer signing and
notarization are configured.
