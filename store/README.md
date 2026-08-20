# Chromium Store Submission Package

This directory is the copy-and-asset source of truth for Shakescape
Extension store submissions.

## Distribution map

- **Google Chrome:** submit the keyless
  `hns-dane-browser-extension-v<version>-mv3-store.zip` release asset to
  Chrome Web Store.
- **Brave and Vivaldi:** use the Chrome Web Store listing. Both browsers
  install Chrome Web Store extensions.
- **Microsoft Edge:** submit the same keyless `-mv3-store.zip` asset to
  Microsoft Edge Add-ons with the Edge-specific listing copy.
- **Opera:** submit the same keyless `-mv3-store.zip` asset and Opera-sized
  screenshots to Opera Add-ons, or install the Chrome Web Store edition where
  Opera supports it.
- **Chromium:** use the canonical-ID `-mv3.zip` GitHub Release asset in
  developer/managed deployment together with the matching native-host bundle.

Both ZIPs contain the same JavaScript and all six finalized Setup archives.
The first-submission `-mv3-store.zip`
omits the manifest `key` so each catalog can assign its own extension ID. The
GitHub/unpacked `-mv3.zip` includes only the committed public key—never the
private key—so it derives the canonical development ID. The user must pass
no ID in the normal flow: the release build bakes the canonical and configured
Chrome, Edge, and Opera IDs into Setup so its `allowed_origins` list stays
exact. A dashboard-assigned ID must be configured and a new release candidate
built before submission or review; it is never inferred from browser profiles.

## Files

- `chrome/en-US.md`: Chrome Web Store copy and fields.
- `edge/en-US.md`: Microsoft Edge Add-ons copy and fields.
- `opera/en-US.md`: Opera Add-ons copy and fields.
- `permission-justifications.md`: single purpose, remote-code declaration, and
  exact permission reasons.
- `privacy-declarations.md`: conservative store privacy answers.
- `review-notes.md`: native-host and local-CA setup for reviewers.
- `assets/chrome-edge/`: 300-pixel logo, 440×280 small tile, 1400×560 marquee,
  and 1280×800 screenshots.
- `assets/opera/screenshots/`: 612×408 screenshots.
- `assets/source/`: canonical Denuo Web-owned brand sources.

Run `scripts/generate-chromium-store-assets.sh` to regenerate every derivative.
Run the release packaging script to create both ZIPs with `manifest.json` at
their root. Packaging accepts only the six final platform archives, verifies
their hashes/signing state and snapshot metadata, writes
`installers/index.json`, and embeds them below `installers/`. Never use the
canonical-ID `-mv3.zip` for a first catalog submission; use the explicitly
keyless `-mv3-store.zip`.

## Public URLs

- Homepage: <https://denuoweb.com/work/hns-dane-browser-extension>
- Source: <https://github.com/handshake-rs/hns-dane-browser-extension>
- Privacy policy:
  <https://denuoweb.com/work/hns-dane-browser-extension/privacy>
- License and user agreement:
  <https://denuoweb.com/work/hns-dane-browser-extension/legal>
- Support: <https://github.com/handshake-rs/hns-dane-browser-extension/issues>
- License:
  <https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/LICENSE>
- Native downloads:
  <https://github.com/handshake-rs/hns-dane-browser-extension/releases/latest>
- GitHub Sponsors: <https://github.com/sponsors/denuoweb>
- HNS donation:
  `handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`

The desktop extension and mobile applications have separate product-specific
privacy and legal pages. Use the extension URLs above for every desktop store.

## Dashboard-only blockers

Repository preparation does not submit or approve a store item. Chrome,
Microsoft, and Opera developer accounts, final catalog IDs, publisher/domain
verification, dashboard privacy declarations, and store review remain
credentialed external steps. Chrome's current listing checklist also calls for
a YouTube feature-video URL; recording approval, upload, and the final URL
remain a Denuo Web account step and are intentionally not fabricated here.
Store submission is blocked until the exact Windows installers embedded in the
ZIP carry the pinned project self-signed Authenticode identity and RFC 3161
SHA-256 timestamp, the exact macOS installers are Developer ID-signed,
notarized, and stapled, and the exact Linux archives have GitHub
build-provenance attestations. The Windows certificate is not publicly trusted,
so listing and Setup copy must disclose possible SmartScreen/**Unknown
Publisher** warnings and provide both the archive SHA-256 and publisher
certificate fingerprint. The final extension ZIP is assembled only after
those platform jobs; later asset replacement cannot create a different
installer than the one reviewers and users receive.
