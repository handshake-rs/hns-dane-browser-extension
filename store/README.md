# Chromium Store Submission Package

This directory is the copy-and-asset source of truth for HNS DANE Browser
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

Both ZIPs contain the same JavaScript. The first-submission `-mv3-store.zip`
omits the manifest `key` so each catalog can assign its own extension ID. The
GitHub/unpacked `-mv3.zip` includes only the committed public key—never the
private key—so it derives the canonical development ID. The user must pass
every exact installed catalog ID to the native-host installer so its
`allowed_origins` list stays exact.

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
their root. Never use the canonical-ID `-mv3.zip` for a first catalog
submission; use the explicitly keyless `-mv3-store.zip`.

## Public URLs

- Homepage/source: <https://github.com/handshake-rs/hns-dane-browser-extension>
- Privacy policy:
  <https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/docs/privacy-policy.md>
- Support: <https://github.com/handshake-rs/hns-dane-browser-extension/issues>
- License:
  <https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/LICENSE>
- Native downloads:
  <https://github.com/handshake-rs/hns-dane-browser-extension/releases/latest>
- GitHub Sponsors: <https://github.com/sponsors/denuoweb>
- HNS donation:
  `handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh`

The older hosted Denuo Web privacy page describes the mobile applications and
must not be used for the desktop listing until it is replaced with the current
desktop policy.

## Dashboard-only blockers

Repository preparation does not submit or approve a store item. Chrome,
Microsoft, and Opera developer accounts, final catalog IDs, publisher/domain
verification, dashboard privacy declarations, and store review remain
credentialed external steps. Chrome's current listing checklist also calls for
a YouTube feature-video URL; recording approval, upload, and the final URL
remain a Denuo Web account step and are intentionally not fabricated here.
The published v0.5.4 macOS native-host and Setup assets are Developer ID
signed and Apple-notarized (Setup tickets are stapled; standalone native hosts
use Apple's online ticket). Windows v0.5.4 assets remain unsigned because
Authenticode credentials are not configured. A future tag's initial macOS
output is unsigned until its credentialed replacement workflow completes, so
each release must retain its own accurate signing labels. The signing jobs use
the protected `macos-signing` environment; the write-enabled `release`
environment still needs protection rules.
