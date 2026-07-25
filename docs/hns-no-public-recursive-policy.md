# HNS resolver and TLS trust boundary

The Chromium-extension runtime must not send Handshake names to a public
recursive resolver and must not authenticate an HNS origin through WebPKI.
These are runtime invariants, not UI defaults.

| Path | Policy |
| --- | --- |
| Local header and Urkel-proof resolution | Required HNS authority path |
| Proof-declared authoritative HNS DoH | Allowed only with proof-anchored address and TLS authentication |
| Direct authoritative DNS | Allowed; DNSSEC and DANE remain local and fail closed |
| Experimental HNS P2P DNS relay | Opt-in; relay answers remain untrusted until local DNSSEC/DANE validation |
| Public recursive HNS DoH | Prohibited |
| HNS WebPKI origin fallback | Prohibited |
| ICANN DoH and WebPKI | Preserved outside the HNS authority path |

## Migration

`RuntimePolicy` temporarily retains `hns_doh_resolver` and
`legacy_hns_doh_compatibility` so old mobile settings and ABI callers can be
read during the extraction. `BrowserRuntime::open` and every policy update
normalize the endpoint to `None` and the legacy switch to `false`. No legacy
setting is reinterpreted as consent to enable the experimental P2P relay.

Raw gateway requests reject both an HNS recursive-resolver header and an
enabled legacy-compatibility header. Generated requests emit neither. All
runtime `GatewayConfig` instances use strict HNS HTTPS mode.

## Verification

The `hns-browser-runtime` tests cover policy normalization, request-header
rejection, proof-anchored authoritative DoH, strict origin TLS behavior, and
separate ICANN resolution. Production builds do not construct either of the
retired public-recursive HNS resolver types.

The mobile UI still present in this transitional clone is not a supported
extension surface. It will be removed after the Rust native host and Manifest
V3 package replace mobile packaging.
