# Microsoft Edge Add-ons — en-US

- Name: `Shakescape`
- Short description: `Routes web DNS names through a local Rust dual-root DNSSEC and DANE runtime.`
- Category: `Developer tools`
- Website: `https://denuoweb.com/work/hns-dane-browser-extension`
- Support: `https://github.com/handshake-rs/hns-dane-browser-extension/issues`
- Privacy policy: `https://denuoweb.com/work/hns-dane-browser-extension/privacy`
- License and user agreement: `https://denuoweb.com/work/hns-dane-browser-extension/legal`
- Mature content: `No`
- First-submission package:
  `hns-dane-browser-extension-v<version>-mv3-store.zip` (keyless)
- Search terms: `Handshake`, `HNS`, `DNSSEC`, `DANE`, `TLSA`,
  `dual-root DNS`, `secure browsing`

## Description

Shakescape gives Microsoft Edge a local, Rust-verified security path for
Handshake and ICANN web names. The native host resolves every complete
hostname through both roots, validates Handshake proofs and DNSSEC, derives
the correct TLSA owner from the effective HTTPS or WebSocket endpoint, and
enforces securely present DANE policy.

The toolbar popup shows whether a host is HNS-only, ICANN-only, convergent,
divergent, absent from both roots, or indeterminate. Bogus DNSSEC is never
treated as absence. For ordinary ICANN sites, Edge retains end-to-end WebPKI
only after the Rust decision authenticates TLSA denial or an unsigned
delegation; the origin's real certificate remains visible.

The extension applies the same namespace decision to main frames, redirects,
subresources, Service Workers, downloads, and WebSockets. It exposes local
header/proof anchors and explicit recovery controls for port-53 interception.
P2P DNS is requester-only and opt-in. A custom recursive HNS DoH URL is blank
by default. Both recovery paths still require local proof, DNSSEC, TLSA, and
DANE verification.

The matching source-available Shakescape Setup application must be run on
Linux, macOS, or Windows. The submitted extension ZIP contains the finalized
packages and its Setup page selects the current computer's package for a
user-initiated save. Setup contains the matching Rust native host, validated
Handshake headers through height 300,000, required non-system dependencies,
and release-baked catalog IDs. The dropdown also provides a Complete Uninstall
handoff. ChromeOS and mobile Chromium are unsupported.

Windows executables carry the project's self-signed Authenticode signature and
an RFC 3161 SHA-256 timestamp. The certificate is not publicly trusted, so
SmartScreen or **Unknown Publisher** may warn; compare the archive SHA-256 and
publisher certificate fingerprint shown by Setup with the release metadata.

There are no ads, analytics, telemetry, developer accounts, paid feature
unlocks, or developer-operated browsing-history service. Source, license,
privacy, support, native downloads, and an optional donation link are
available from the setup page and project repository.

Optional donation:
https://github.com/sponsors/denuoweb
