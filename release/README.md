# Release administration

The tag-triggered workflow accepts only `v<manifest-version>` tags that point to
the exact current default-branch tip. It packages a keyless browser-neutral
Manifest V3 ZIP for first store submissions, a canonical-ID ZIP for GitHub and
unpacked use, and native hosts for Linux, Windows, and macOS on x64 and arm64.
Linux artifacts are statically linked with musl. The publisher verifies every
archive sidecar, creates `SHA256SUMS`, rejects missing or unexpected assets, and
publishes only after all portable, extension, and native matrix jobs succeed.

Before delegating release authority or granting additional write access,
repository administrators should:

1. protect the default branch and require the `Required CI` check;
2. restrict creation and updates of `v*` tags to release maintainers;
3. configure the `release` GitHub Actions environment with required maintainer
   approval; and
4. review the tag commit, workflow changes, store identity, and release notes
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
