# Chromium Release Process

Tagged releases contain a keyless Manifest V3 package for first catalog
submissions, a canonical-ID package for GitHub/unpacked use, and six native
host bundles for Linux, macOS, and Windows on x64 and arm64. Each archive
includes immutable source metadata, the product license, third-party notices,
installation guidance, and a per-asset checksum. The workflow publishes an
aggregate `SHA256SUMS` only after every build and release gate succeeds.

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
   reruns the portable gate, builds all eight required archives, verifies all
   eight checksum sidecars, generates the seventeenth asset (`SHA256SUMS`), and
   publishes the release with the GitHub CLI.

For example:

```sh
git tag -a v0.5.2 -m "HNS DANE Browser 0.5.2"
git push origin v0.5.2
gh run watch --repo handshake-rs/hns-dane-browser-extension
gh release view v0.5.2 \
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
release environment before granting additional write access. Build and
packaging jobs remain read-only; only the final publisher receives repository
write permission.

## Signing and store submission

The automated Windows bundles are currently unsigned. The automated macOS
bundles are unsigned and not notarized. Configure project-controlled
Authenticode and Apple Developer credentials before representing those
artifacts as signed.

Repository automation does not submit store dashboards. Publisher accounts,
domain verification, final catalog IDs, privacy declarations, review, and
store signing remain credentialed release steps. Submission copy and artwork
are maintained in [`store/`](../store/README.md).

Donations are optional and do not unlock features:

- GitHub Sponsors: <https://github.com/sponsors/denuoweb>
- HNS:
  `handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`
