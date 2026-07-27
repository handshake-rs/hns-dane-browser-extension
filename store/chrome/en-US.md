# Chrome Web Store — en-US

- Name: `HNS DANE Browser`
- Manifest summary: `Routes web DNS names through a local Rust dual-root DNSSEC and DANE runtime.`
- Category: `Productivity`
- Language: `English (United States)`
- Homepage: `https://github.com/handshake-rs/hns-dane-browser-extension`
- Support: `https://github.com/handshake-rs/hns-dane-browser-extension/issues`
- Privacy policy: `https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/docs/privacy-policy.md`
- Official URL: leave unset until a current desktop product page is published
  on a verified Denuo Web domain.
- Mature content: `No`
- First-submission package:
  `hns-dane-browser-extension-v<version>-mv3-store.zip` (keyless)
- Localized promo video: upload a current feature walkthrough to the official
  Denuo Web YouTube account and enter its URL before submission; no URL is
  invented in source.

## Detailed description

HNS DANE Browser adds Handshake-aware, fail-closed browsing to desktop
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

The extension requires the source-available HNS DANE Browser Setup application.
Its version-matched Linux, macOS, and Windows packages contain the matching
Rust native host, required non-system dependencies, and install one per-user
local CA. The extension's first-install page links to the matching setup
release and shows the exact catalog-specific extension ID that Setup must
register. ChromeOS and mobile Chromium cannot use this native host. Android
and iOS are separate products.

The project runs no advertising, analytics, telemetry, developer account, or
browsing-history service. See the linked privacy policy for the DNS operators
and local/session data needed to provide the feature.

Source:
https://github.com/handshake-rs/hns-dane-browser-extension

License:
https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/LICENSE

Optional donation:
https://github.com/sponsors/denuoweb

HNS donation address:
hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh

Donations do not unlock features.
