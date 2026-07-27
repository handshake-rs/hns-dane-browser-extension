# Security Model

## Product boundary

This repository qualifies the Chromium Manifest V3 extension, Rust native
messaging host, authenticated loopback proxy, and their local Handshake and
ICANN resolution stack. Current mobile security claims belong to
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

Five canonical contracts are pinned to
`handshake-rs/hns-dane-engine` revision
`7f7bb8fa100c2393f2cd5a64c64bf5e20a0f3ab5`:

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

Selected HNS HTTPS never falls back to WebPKI. It has no automatic public
recursive resolver; an explicit user-configured recursive endpoint is an
optional transport only and cannot replace local HNS trust validation.

The locally validated canonical tip must also be current. A 144-block window
is used only to retain proof-cache anchors across conservative
reorganizations; it does not authorize a day-old chain view. Live browser
decisions use a two-block maximum lag against a recent corroborated median
from at least three independent peer address groups. A raw maximum peer claim
and the ideal ten-minute schedule estimate remain diagnostics. Missing or
expired corroboration is `Unknown`, not current, and fails closed for HNS
admission. Header-height evidence has its own persisted observation timestamp;
proof retrieval, DNS-relay traffic, and unrelated transport success cannot
refresh it or promote a version-packet height. Native status derives the last
Unix second through which at least three independent observations remain, and
the extension requests synchronization two minutes before that point. Failed
attempts retain a bounded one-minute urgent retry window through two minutes
after that known deadline; unrelated stale or unknown state remains on the
ten-minute attempt floor.
Missing or expired evidence still fails closed; the deadline is scheduling
metadata, not an extension of its validity.

Direct authoritative UDP/TCP 53 remains first when usable. A positive matching
TEST-NET canary reply stops futile TCP and remaining direct-server attempts
and continues through independently authenticated proof-pinned authoritative
DoH. Ordinary direct transport failure may also continue to that endpoint. A
timeout or inconclusive probe does not classify interception or authenticated
absence.

The complete delegated transport order is direct authoritative UDP/TCP,
proof-anchored owner authoritative DoH, the independently opted-in
requester-only P2P relay, and then an independently opted-in user-configured
recursive HNS DoH endpoint. The final transport is eligible only for typed
`DnsTransport` failure or positive `Port53InterceptionDetected`; DNS response
codes, malformed replies, DNSSEC failure, relay DNSSEC failure, and
missing/stale chain or proof evidence remain terminal.

Configured endpoint hostnames are bootstrapped only through built-in
fixed-address validating ICANN DoH. Connections use an explicit public IP and
retain WebPKI hostname authentication, so the system resolver cannot select
the endpoint. Returned RFC 8484 bytes remain untrusted until the local
HNS-derived DS chain, DNSSEC denial/positive data, HTTPS/SVCB, TLSA, and DANE
checks accept them. Resolver AD is never trust evidence. A blank setting sends
nothing to a recursive HNS DoH operator, and historical resolver settings
cannot revive the new consent.

For HTTPS/SVCB, supported protocols in the effective RFC 9460 ALPN set are
evaluated in `h3` → `h2` → `http/1.1` order; the HTTP/1.1 HTTPS default applies
unless `no-default-alpn` is present. TLSA owners are transport-scoped. Only
securely authenticated TLSA absence may advance to the next protocol. Bogus or
indeterminate DNSSEC remains terminal, and valid UDP TLSA retains HTTP/3.

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

Securely present ICANN TLSA remains on the local Rust TLS-termination path so
Rust can enforce DANE. The two defined WebPKI outcomes take a different path:
the proxy tries a bounded rotating batch of exact public IPs from the retained
namespace plan under one aggregate timeout and carries Chromium's TLS bytes
over the selected raw CONNECT tunnel. Canonical authority is rechecked before
each dial, and the socket-reported peer must match the authenticated endpoint
set. Chromium therefore performs the end-to-end WebPKI handshake and displays
the origin's actual certificate chain; the local CA is neither presented nor
issued for that connection. A selected-WebPKI origin-connect failure is
terminal at CONNECT and cannot fall back to local TLS.

The raw tunnel owns independent bounded reader and writer halves so an idle
upload cannot throttle a download, and vice versa. It cannot move bytes before
the namespace binding is committed and the authenticated CONNECT 200 is
written under the same invalidation-exclusion boundary. The tunnel remains
gated unless the CONNECT write succeeds.
Header maintenance advances a native epoch which revokes both halves; stop,
policy change, readiness loss, or generation rotation also closes them.

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

The local CA authenticates the browser-to-loopback hop only on branches where
Rust must terminate TLS, including HNS DANE and ICANN DANE. It is not an
origin trust substitute. For a defined ICANN WebPKI fallback, Rust
authenticates the namespace and DNSSEC/TLSA policy decision, then bypasses
local TLS so Chromium validates and displays the real origin certificate.

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

The user-configured recursive HNS DoH setting is a separate opt-in and does
not enable P2P requesting or any provider role. Its operator can observe
qnames, qtypes, request timing, and source IP.

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
| Configured recursive resolver lies or sets AD | Treat raw RFC 8484 bytes as untrusted and validate locally |
| Configured resolver hostname is captured by local DNS | Bootstrap only through fixed-address validating ICANN DoH; connect by explicit public IP with WebPKI hostname validation |
| One peer advertises an extreme height | Recent multi-address-group corroboration; raw maximum is diagnostic only |
| No fresh peer target is available | Currentness is unknown and HNS admission fails closed |
| Requester consent enables serving | Typed policy separation; all provider roles off |
| Unsupported HNSR/ODoH request | Reject policy; no silent downgrade |

## Known release boundaries

Portable tests do not prove browser-store distribution or target-OS
installation behavior. A signed release still requires supported-browser
testing on Windows and macOS, CA lifecycle and uninstall verification, upgrade
testing, store signing/review, and artifact provenance tied to the reviewed
commit/tag.
