# Chrome Web Store — en-US

- Name: `Shakescape`
- Manifest summary: `Routes web DNS names through a local Rust dual-root DNSSEC and DANE runtime.`
- Category: `Productivity`
- Language: `English (United States)`
- Homepage: `https://denuoweb.com/work/hns-dane-browser-extension`
- Support: `https://github.com/handshake-rs/hns-dane-browser-extension/issues`
- Privacy policy: `https://denuoweb.com/work/hns-dane-browser-extension/privacy`
- License and user agreement: `https://denuoweb.com/work/hns-dane-browser-extension/legal`
- Official URL: `https://denuoweb.com/work/hns-dane-browser-extension`
- Mature content: `No`
- First-submission package:
  `hns-dane-browser-extension-v<version>-mv3-store.zip` (keyless)
- Localized promo video: upload a current feature walkthrough to the official
  Denuo Web YouTube account and enter its URL before submission; no URL is
  invented in source.

## Detailed description

Shakescape adds Handshake-aware, fail-closed browsing to desktop
Chromium. A local Rust native host resolves each complete web hostname through
both the Handshake and ICANN roots, validates the available evidence, and
shows the selected namespace and security path in the toolbar popup.

Key capabilities:

- full-host HNS/ICANN classification: HNS only, ICANN only, convergent,
  divergent, neither, or indeterminate;
- local Handshake header and proof validation;
- DNSSEC and TLSA/DANE enforcement for selected HNS and securely published
  ICANN TLSA records;
- Chromium-owned end-to-end WebPKI only after authenticated ICANN TLSA denial
  or an unsigned ICANN delegation;
- exact-IP origin connections from authenticated DNS plans, without system
  DNS fallback;
- the same decision path for redirects, subresources, Service Workers,
  downloads, WebSockets, and the initial document;
- clear security receipts, proof anchors, header-chain state, and a manual
  header-sync control;
- optional requester-only P2P DNS relay and user-configured recursive HNS DoH
  recovery. Both are off/blank by default and returned answers remain subject
  to local proof, DNSSEC, TLSA, and DANE verification.

The extension requires the source-available Shakescape Setup application.
The submitted extension ZIP contains signed/attested, version-matched Linux,
macOS, and Windows Setup packages. The first-install page selects the one for
the current computer and lets the user save it; the extension cannot launch
it. Setup contains the matching Rust native host, a validated Handshake header
bootstrap through height 300,000, required non-system dependencies, and the
release-baked catalog IDs, and installs one per-user local CA. Its Complete
Uninstall action is also reachable from the extension dropdown. ChromeOS and
mobile Chromium cannot use this native host. Android and iOS are separate
products.

Windows executables use a project self-signed Authenticode certificate and an
RFC 3161 SHA-256 timestamp. That publisher is not publicly trusted, so Windows
SmartScreen or **Unknown Publisher** may warn; Setup displays the archive
SHA-256 and published certificate fingerprint for verification.

The project runs no advertising, analytics, telemetry, developer account, or
browsing-history service. See the linked privacy policy for the DNS operators
and local/session data needed to provide the feature.

Source:
https://github.com/handshake-rs/hns-dane-browser-extension

License:
https://denuoweb.com/work/hns-dane-browser-extension/legal

Optional donation:
https://github.com/sponsors/denuoweb

HNS donation address:
hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh

Donations do not unlock features.
