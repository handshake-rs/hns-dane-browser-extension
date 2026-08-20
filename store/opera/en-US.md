# Opera Add-ons — en-US

- Name: `Shakescape`
- Summary: `Browse HNS and ICANN names through a local Rust DNSSEC and DANE security path.`
- Category: `Web Development`
- Website: `https://denuoweb.com/work/hns-dane-browser-extension`
- Support page: `https://github.com/handshake-rs/hns-dane-browser-extension/issues`
- License: `PolyForm Noncommercial License 1.0.0`
- Privacy policy: `https://denuoweb.com/work/hns-dane-browser-extension/privacy`
- License and user agreement: `https://denuoweb.com/work/hns-dane-browser-extension/legal`
- First-submission package:
  `hns-dane-browser-extension-v<version>-mv3-store.zip` (keyless)

## Description

Shakescape adds a local Rust dual-root resolver and authenticated
loopback proxy to desktop Opera. It resolves complete hostnames through
Handshake and ICANN, validates HNS proofs and DNSSEC, enforces secure
TLSA/DANE records, and shows the exact namespace and certificate policy chosen
for the active page.

The same decision covers redirects, page resources, Service Workers,
downloads, and WebSockets. Optional P2P DNS use is requester-only and requires
explicit consent. A user-configured recursive HNS DoH recovery URL is blank by
default. Bogus or indeterminate evidence fails closed.

The submitted extension ZIP contains the finalized Linux, macOS, and Windows
Shakescape Setup packages. Its Setup page selects the current computer's
package for a user-initiated save. Each package contains the matching Rust
native host, validated Handshake headers through height 300,000, required non-system
dependencies, and release-baked catalog IDs. Select Opera and choose Install
or Repair; Complete Uninstall is available from both Setup and the extension
dropdown. The extension runs no ads, analytics, telemetry, or
developer-operated browsing-history service.

Windows executables carry a project self-signed Authenticode signature and an
RFC 3161 SHA-256 timestamp. The certificate is not publicly trusted, so
SmartScreen or **Unknown Publisher** may warn; verify the archive SHA-256 and
publisher certificate fingerprint shown by Setup before running it.

Source and downloads:
https://github.com/handshake-rs/hns-dane-browser-extension

Optional donation:
https://github.com/sponsors/denuoweb

HNS donation address:
hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh
