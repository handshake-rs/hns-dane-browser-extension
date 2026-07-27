# No Automatic Public Recursive HNS Resolver Policy

The Chromium browser path must not send Handshake names to a public recursive
DNS or DoH service automatically. A user may separately and explicitly
configure a recursive HNS DoH recovery endpoint. The field is blank by
default, no endpoint is prefilled or contacted while blank, and historical
resolver values are never migrated into this new consent.

## Allowed HNS authority order

After current local Handshake header and Urkel proof validation, delegated HNS
DNS may use:

1. direct authoritative UDP with TCP fallback;
2. proof-anchored owner authoritative DoH after direct authority is
   unavailable or fails, including when a positive matching TEST-NET canary
   classifies port 53 as intercepted;
3. the experimental HNS P2P DNS-relay requester, only after explicit browser
   opt-in and only as untrusted input to local DNSSEC/DANE validation; and
4. the user-configured recursive HNS DoH endpoint, only after its independent
   explicit opt-in and only as untrusted input to the same local validation.

Failure of these paths is an actionable fail-closed result. It is not
permission to discover or select any other public HNS resolver.

A positive interception probe stops futile TCP and remaining direct-server
attempts. A timeout or inconclusive probe does not classify interception or
authenticated DNS absence. Every alternate answer is independently validated;
bogus DNSSEC never becomes “no TLSA.”

The configured endpoint is eligible only when earlier delegated transports
produce `DnsTransport` or positively confirmed
`Port53InterceptionDetected`. It is prohibited after a DNS response code,
invalid response, DNSSEC failure, relay DNSSEC failure, stale/missing local
chain or proof, or proof-name mismatch. These are security/evidence outcomes,
not transport availability.

Rust resolves the configured endpoint hostname only through the existing
fixed-address validating ICANN DoH path, filters to public addresses, connects
to an explicit address, and uses WebPKI for the configured hostname. System
DNS is never used for bootstrap. RFC 8484 replies then enter local HNS DNSSEC,
HTTPS/SVCB, TLSA, and DANE validation. Resolver AD is not trusted.

For HNS HTTPS/SVCB, supported protocols in the effective RFC 9460 ALPN set are
evaluated in `h3` → `h2` → `http/1.1` order; the HTTP/1.1 HTTPS default applies
unless `no-default-alpn` is present. Each candidate derives its own UDP or TCP
TLSA owner. Only securely authenticated TLSA absence may advance to the next
candidate; other validation failures remain terminal.

The extension requester setting maps `false` to `Disabled` and `true` to
direct-authority-first `Auto`. It does not enable opaque relay serving or any
output/provider role. This Chromium product advertises no provider service.
The recursive URL is a second, independent requester consent and likewise
does not enable serving.

Site owners can avoid either user recovery setting by publishing
proof-anchored authoritative DoH on HTTPS 443: an HNS `hnsdns=1` declaration
with proven glue and a TLSA pin, or a supported authenticated
`_dns.<NS>` SVCB record.

## ICANN is a separate trust path

Validating ICANN DoH is permitted for the ICANN side of full-host dual-root
resolution. For selected ICANN HTTPS/WSS, it also retrieves and validates the
derived TLSA owner. This is accurately described as `DANE via ICANN DoH`; it
does not make the service an HNS recursive resolver.

Authenticated ICANN TLSA denial or an unsigned delegation may use WebPKI.
Bogus or indeterminate DNSSEC never becomes “no TLSA” and fails closed.

## Legacy settings

Historical public-HNS-DoH values are normalized to disabled without granting
P2P requester consent or populating the new recursive URL. The documented
HNSDoH pool example is `https://hnsdoh.com/dns-query`; Zorro is a listed pool
node, not a separate documented HTTPS endpoint. HNSR and P2P ODoH are not
implemented and fail closed.
