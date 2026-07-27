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
4. enable immutable releases so published tags and assets cannot be replaced;
   and
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

The workflow contains no signing secrets. Automated Windows archives are
unsigned, and automated macOS archives are unsigned and not notarized. Configure
and independently audit platform signing before describing those artifacts as
signed or notarized.

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
process, so the v0.5.3 Linux Setup requires the build baseline of glibc 2.39 or
newer (Ubuntu 24.04 / Debian 13 generation). The release gate rejects any
packaged ELF object requiring a later glibc version. Its clean-environment
release smoke test creates a temporary NSS
database and exercises certificate add/list/delete, so users do not need to
install `libnss3-tools`.
