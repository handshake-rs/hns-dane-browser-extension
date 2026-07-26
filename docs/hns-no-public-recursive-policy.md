# No Public Recursive HNS Resolver Policy

The Chromium browser path must not send Handshake names to a public recursive
DNS or DoH service.

## Allowed HNS authority order

After current local Handshake header and Urkel proof validation, delegated HNS
DNS may use:

1. proof-declared authoritative DoH;
2. direct authoritative UDP with TCP fallback; and
3. the experimental HNS P2P DNS-relay requester, only after explicit browser
   opt-in and only as untrusted input to local DNSSEC/DANE validation.

Failure of these paths is an actionable fail-closed result. It is not
permission to use a public HNS resolver.

The extension requester setting maps `false` to `Disabled` and `true` to
direct-authority-first `Auto`. It does not enable opaque relay serving or any
output/provider role. This Chromium product advertises no provider service.

## ICANN is a separate trust path

Validating ICANN DoH is permitted for the ICANN side of full-host dual-root
resolution. For selected ICANN HTTPS/WSS, it also retrieves and validates the
derived TLSA owner. This is accurately described as `DANE via ICANN DoH`; it
does not make the service an HNS recursive resolver.

Authenticated ICANN TLSA denial or an unsigned delegation may use WebPKI.
Bogus or indeterminate DNSSEC never becomes “no TLSA” and fails closed.

## Legacy settings

Historical public-HNS-DoH values are normalized to disabled without granting
P2P requester consent. HNSR and P2P ODoH are not implemented and fail closed.
