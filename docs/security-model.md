# Security Model

## Product boundary

This repository qualifies the Chromium Manifest V3 extension, Rust native
messaging host, authenticated loopback proxy, and their local Handshake and
ICANN resolution stack. Current mobile security claims belong to
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

Five canonical contracts are pinned to
`handshake-rs/hns-dane-engine` revision
`a03648ec85a115362ebc2ab24bb9ea0f1be127fc`:

- session-bound browser request authority;
- checked browser observability;
- generic ICANN DANE policy;
- dual-root namespace resolution; and
- requester/provider policy.

The local Chromium adapter, loopback listener, native messaging, per-install
CA, lifecycle, storage, and origin transport remain product code.

## Trust anchors

### Selected HNS namespace

The HNS path trusts:

1. configured Handshake network/genesis parameters;
2. locally validated headers, proof-of-work, expected difficulty, and best
   chain;
3. locally verified Urkel name proofs anchored to that chain;
4. delegation material derived from the verified name state;
5. delegated DNSSEC signatures and authenticated denial; and
6. TLSA/DANE matching for selected HTTPS/WSS origins.

Selected HNS HTTPS never falls back to WebPKI or a public recursive HNS
resolver.

### Selected ICANN namespace

The ICANN path uses a validating ICANN DoH boundary for full-host address,
alias, HTTPS/SVCB, denial, and TLSA observations. For HTTPS/WSS:

- securely present supported TLSA is enforced;
- authenticated TLSA absence uses WebPKI;
- an unsigned/insecure delegation ignores unsigned TLSA and uses WebPKI; and
- bogus or indeterminate DNSSEC, malformed data, or resolver failure fails
  closed.

The TLSA owner is derived from the effective host, port, and transport for
every selected ICANN origin. This is `DANE via ICANN DoH`.

## Namespace ambiguity

The PAC routes ordinary DNS HTTP(S)/WS(S) names but makes no namespace
decision. Rust resolves each complete hostname independently through HNS and
ICANN and retains:

- HNS only;
- ICANN only;
- convergent;
- divergent;
- neither; or
- indeterminate.

Authenticated denial is distinct from timeout, validation failure, malformed
data, and bogus DNSSEC. Any required indeterminate root result fails closed.
The IANA root list can affect scheduling only; it cannot select a root or
bypass complete-host resolution.

For divergence, configured precedence and a persistent binding select one
complete plan and expose the choice. Address, CNAME, HTTPS/SVCB, port,
transport, and TLSA records from different roots are never mixed. Decision
fingerprints partition connection pools, TLS verifier/resumption state, and
Alt-Svc state.

## Request authority

The native host derives the canonical runtime session from exact authenticated
proxy-session bytes. Every admitted request receives one stamp before DNS
work. The stamp contains the runtime session, runtime generation, policy
generation, and monotonic event identity.

That exact authority follows the request through resolution and transport.
Response-head publication, streamed or file-backed response bodies, downloads,
and tunnels require a live matching permit. Stop, policy change, readiness
loss, proxy rotation, or runtime replacement revokes older work and status.
Concurrent requests keep request-local namespace plans so a shared cache update
cannot change another request's published choice.

## Loopback proxy and local CA

- The listener binds a randomized `127.0.0.1` port.
- Each proxy generation has fresh authentication credentials.
- Credentials are accepted only by the active generation.
- The per-install P-256 CA private key remains in protected native-host data.
- Rust issues exact-host, short-lived leaf certificates only after name and
  request admission.
- PAC activation requires successful user-level CA trust installation and the
  matching certificate marker.
- Proxy stop, native disconnect, malformed health state, or failed policy/PAC
  update clears active browser proxy configuration.

The local CA can authenticate the browser-to-loopback hop only. It is not an
origin trust substitute; selected-origin DNSSEC/DANE or WebPKI policy is
enforced independently inside Rust.

## Status boundary

Internal response metadata is observed before being stripped from the
browser-visible response. The native host converts typed evidence into a
bounded checked status. JavaScript does not parse DNS, certificates, proofs,
P2P state, or private headers.

The extension renders a result only when its session, runtime generation,
policy generation, and event identity match current authority. Missing exact
transport or namespace evidence produces explicit unavailable state. Error
strings and legacy trace fields cannot fabricate DNSSEC, TLSA, DANE, or
namespace success.

## Experimental relay

The browser's P2P DNS-relay requester is explicit opt-in:
`false → Disabled`, `true → direct-authority-first Auto`. A relay supplies raw
DNS bytes only; local proof, DNSSEC, HTTPS/SVCB, TLSA, and DANE checks remain
authoritative.

This Chromium product advertises no service. Opaque relay serving is opted out
and every output/provider role is disabled. HNSR and P2P ODoH are unimplemented
and fail closed. Ordinary P2P TCP does not hide queries from the relay or
network observers and must not be described as ODoH.

## Threats and responses

| Threat | Response |
| --- | --- |
| ICANN later adds an HNS-colliding TLD | Full-host dual-root resolution; IANA list is not authority |
| Both roots resolve differently | Divergent outcome, explicit precedence/binding, visible choice |
| Bogus DNSSEC presented as absence | Typed bogus/indeterminate state fails closed |
| Unsigned TLSA attempts to override WebPKI | Ignore unsigned TLSA under the insecure-delegation fallback |
| Stale async response after restart/policy change | Exact admission stamp and publication permit |
| Cross-root pool or Alt-Svc reuse | Namespace-decision fingerprint partitioning |
| Local process reaches proxy port | Per-generation proxy authentication and bounded framing |
| Page forges security metadata | Strip internal headers; publish only native checked status |
| Relay lies or sets AD | Treat response as untrusted and validate locally |
| Requester consent enables serving | Typed policy separation; all provider roles off |
| Unsupported HNSR/ODoH request | Reject policy; no silent downgrade |

## Known release boundaries

Portable tests do not prove browser-store distribution or target-OS
installation behavior. A signed release still requires supported-browser
testing on Windows and macOS, CA lifecycle and uninstall verification, upgrade
testing, store signing/review, and artifact provenance tied to the reviewed
commit/tag.
