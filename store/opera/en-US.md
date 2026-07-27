# Opera Add-ons — en-US

- Name: `HNS DANE Browser`
- Summary: `Browse HNS and ICANN names through a local Rust DNSSEC and DANE security path.`
- Category: `Web Development`
- Support page: `https://github.com/handshake-rs/hns-dane-browser-extension/issues`
- License: `PolyForm Noncommercial License 1.0.0`
- Privacy policy: `https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/docs/privacy-policy.md`
- First-submission package:
  `hns-dane-browser-extension-v<version>-mv3-store.zip` (keyless)

## Description

HNS DANE Browser adds a local Rust dual-root resolver and authenticated
loopback proxy to desktop Opera. It resolves complete hostnames through
Handshake and ICANN, validates HNS proofs and DNSSEC, enforces secure
TLSA/DANE records, and shows the exact namespace and certificate policy chosen
for the active page.

The same decision covers redirects, page resources, Service Workers,
downloads, and WebSockets. Optional P2P DNS use is requester-only and requires
explicit consent. A user-configured recursive HNS DoH recovery URL is blank by
default. Bogus or indeterminate evidence fails closed.

Install the matching Linux, macOS, or Windows native-host bundle from the
GitHub Release linked by the setup page. Pass the exact Opera extension ID to
the installer and select `opera`. The extension runs no ads, analytics,
telemetry, or developer-operated browsing-history service.

Source and downloads:
https://github.com/handshake-rs/hns-dane-browser-extension

Optional donation:
https://github.com/sponsors/denuoweb

HNS donation address:
hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh
