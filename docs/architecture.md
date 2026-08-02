# Architecture

This repository is the Chromium extension, native-host, and desktop setup
product. Current Android and iOS work lives in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

The Chromium adapter consumes five canonical browser contracts from
the checksum-verified `handshake-rs/hns-dane-engine` crates.io `0.1.0`
release. The canonical
`hns-browser-runtime` owns session-bound request authority;
`hns-browser-observability` checks typed status;
`hns-icann-dane` owns ICANN TLSA policy;
`hns-namespace-resolution` owns dual-root outcomes; and
`hns-resolution-policy` owns requester/provider policy types.

## Request path

```text
Chromium request
  -> syntax-only PAC for ordinary DNS HTTP(S)/WS(S)
  -> authenticated 127.0.0.1 proxy generation
  -> one canonical admission stamp
  -> full hostname resolved independently through HNS and ICANN
  -> one immutable selected namespace plan
  -> DNSSEC + HTTPS/SVCB + TLSA/DANE or defined WebPKI policy
  -> DANE: local TLS termination and Rust origin validation
     WebPKI fallback: raw exact-IP CONNECT and Chromium origin validation
  -> origin HTTP/1.1, HTTP/2, HTTP/3, or WebSocket transport
  -> authority check at response head, body/download, and tunnel publication
  -> sanitized checked status to the native host and extension
```

The PAC contains no IANA classification, resolver call, socket operation, DoH
endpoint, or fallback. It routes every ordinary DNS hostname for HTTP, HTTPS,
WS, and WSS to Rust, covering initial pages, redirects, subresources, Service
Workers, downloads, and WebSockets through the browser proxy boundary.
Malformed names, IP literals, special-use names, and non-web schemes are not
classified as public DNS names by the PAC.

Some HNS proofs contain the selected origin address, service, and TLSA data
without requiring delegated DNS. Those successful results use the shared
status-only `LocalHnsProof` provenance. It never enters the network transport
plan or transport admission, and prevents a proof-contained main-frame result
from being discarded merely because no DNS socket was used.

## Dual-root authority

Rust constructs an independent, complete plan for each root. A plan retains
the effective A/AAAA and CNAME path, HTTPS/SVCB policy, service port and
transport, TLSA observation, security state, and bounded freshness.

The decision is:

| HNS | ICANN | Outcome |
| --- | --- | --- |
| present | securely absent | HNS only |
| securely absent | present | ICANN only |
| same effective plan | same effective plan | convergent |
| different effective plan | different effective plan | divergent |
| securely absent | securely absent | neither |
| bogus, indeterminate, or failed | any required state | indeterminate |

A whole-name authenticated denial can establish absence. NODATA for one
address family cannot hide the other. Divergent names use the configured
precedence and a persistent namespace binding; the selected root and reason
remain visible in checked status. Connection pools, TLS verifier state,
resumption, and Alt-Svc state are partitioned by the decision fingerprint.

The bundled IANA list is a cache/performance hint only. It cannot select a
namespace, bypass either full-host resolution, or cause a later IANA root
change to silently reclassify an HNS name.

## Header currentness

Header synchronization performs network I/O, quorum collection, snapshot
preparation, and peer merging in a private staged database without holding the
live proxy's maintenance lock. The stage is bound to the live header
generation and canonical tip, and a SQLite delta journal records the exact
candidate suffix. Publication briefly takes the process-wide header/peer
publication locks and the runtime maintenance write lock, rechecks that
baseline, validates the delta, and atomically publishes the canonical headers,
peer observations, and readiness generation. A stale, incomplete, or
superseded stage is rejected. Request validation uses the read side of the
maintenance lock, so a page cannot publish against a chain that changes under
it while routine synchronization no longer pauses the live proxy.

An unchanged-header peer refresh publishes updated quorum evidence without
rotating the header-maintenance epoch. A header advance or reorganization
rotates that epoch and invalidates proof-cache and status evidence bound to the
old chain.

Live currentness is intentionally separate from cache retention:

```text
proof-cache/reorganization retention   144 blocks
browser currentness allowance            2 blocks
peer target evidence lifetime           20 minutes
minimum independent address groups       3
```

The effective target is an outlier-resistant median of recent
header-sync-owned peer observations across address groups. Height evidence has
its own persisted timestamp; proof retrieval, relay use, and ordinary
transport liveness cannot refresh it. The raw maximum advertised height and a
genesis-time schedule estimate are shown only as diagnostics. No corroborated
target produces `Unknown`, which is non-admissible for HNS resolution.
The native status includes the last Unix second through which a quorum remains
valid, derived from the remaining independent observations. The extension
schedules one synchronization two minutes before that point and reuses the
existing five-minute local health alarm as a safety path, rather than adding
another periodic peer poll. Failed attempts in routine stale or unknown state
remain rate-limited to a ten-minute retry interval. Only around a previously
authenticated quorum deadline, failed automatic or manual attempts use a
bounded one-minute retry cadence from the two-minute lead window through two
minutes after expiry. An explicit toolbar action can still request one
immediate sync.

## ICANN DANE

For every selected ICANN HTTPS/WSS origin, Rust derives the TLSA owner from the
effective origin:

```text
_<port>._tcp.<host>.   HTTP/1.1, HTTP/2, and WSS
_<port>._udp.<host>.   HTTPS/SVCB-selected HTTP/3
```

The record is retrieved through validating ICANN DoH. The policy has four
closed outcomes:

- securely present and supported TLSA: enforce DANE;
- authenticated TLSA denial: use WebPKI;
- unsigned/insecure delegation: ignore unsigned TLSA bytes and use WebPKI;
- bogus/indeterminate DNSSEC, malformed response, or resolver failure: fail
  closed.

An exact insecure origin RRset from validating DoH establishes the
insecure-delegation branch without a redundant TLSA query. This does not apply
when only the aggregate alias chain is insecure: a covering RRSIG on the
origin RRset keeps TLSA discovery mandatory even if the CNAME target is
unsigned.

Status names this path `DANE via ICANN DoH`. Bogus DNSSEC is not absence.
Typed DANE failure is preserved across HTTP/1.1, HTTP/2, HTTP/3, CONNECT, and
WebSocket paths rather than inferred from error strings.

ICANN WebPKI CONNECT uses only public numeric endpoints retained in that
decision. It tries a bounded rotating batch under one aggregate connect
timeout, rechecks canonical authority before every dial, and verifies the
socket's actual peer against the authenticated endpoint set. Internally
constructed HTTP/1.1 RFC 8484 POSTs may retry once on a fresh exact-IP
connection after a stale idle pooled socket fails; ordinary POSTs remain
non-replayable.

Secure ICANN TLSA and every selected HNS HTTPS/WSS plan stay on the intercept
path because Rust must inspect the certificate and enforce DANE. Authenticated
ICANN TLSA denial and proven-insecure delegation instead return a pre-TLS
passthrough disposition. The origin transport connects only to the explicit
IP and effective TCP port in the selected plan; no system DNS lookup is
possible. Its socket is split into independently pumped bounded read/write
halves. Chromium carries out the end-to-end TLS handshake, so its certificate
viewer shows the origin chain rather than the local CA.

The proxy publishes CONNECT 200, the persistent namespace binding, and a
host/port-scoped decision before either tunnel half may move bytes. The
decision has no HTTP-status or main-frame claim; the extension may correlate
it only with a successful Chromium navigation in the same runtime tuple and
native maintenance epoch. Header synchronization advances that epoch and
revokes both halves. If the selected raw origin socket cannot open, the proxy
returns a pre-TLS CONNECT failure and never substitutes local TLS.

## Request authority and publication

The native host derives the canonical runtime session from the exact
authenticated proxy-session bytes. Before DNS work, a request obtains one
stamp containing the active runtime session, runtime generation, policy
generation, and monotonic event identity. The exact stamp follows that request
through resolution and transport.

Final response-head publication requires a live authority permit. Streamed
bodies, file-backed bodies, downloads, and tunnels retain equivalent guards.
Stop, policy change, readiness loss, or generation rotation revokes the permit
and clears stale status. Concurrent resolution cannot overwrite a
request-local namespace plan with another request's cached state.

The extension receives only bounded, sanitized, checked status. JavaScript
does not parse DNS, certificates, proofs, or trace headers and never invents
cryptographic state. When exact evidence is unavailable, the status is
explicitly unavailable.

## Rust layers

- `hns-browser-setup`: version-matched GUI/CLI distribution boundary that
  installs or repairs the embedded native host, selected exact browser
  registrations, and per-user CA; it is not part of request admission after
  installation.
- `hns-chromium-native-host`: native messaging, policy, per-install CA,
  lifecycle, installers, and sanitized schema conversion.
- `hns-chromium-platform-runtime`: Chromium storage/network adapter, sync,
  dual-root plan construction, canonical authority integration, and status
  observation.
- `hns-loopback-proxy`: authenticated HTTP/CONNECT endpoint, local DANE TLS
  termination, raw browser-WebPKI duplex tunneling, response-head publication,
  and Upgrade tunneling.
- `hns-gateway` and `hns-transport`: selected-plan HTTP/TLS/QUIC execution and
  exact-IP split browser-WebPKI sockets.
- `hns-resolver`, `hns-dnssec`, `hns-dane`: verified Handshake resolution,
  delegated DNSSEC, and DANE primitives.
- `hns-chain`, `hns-sync`, `hns-p2p`, and `hns-urkel`: local Handshake header
  and proof trust path.

The product-specific adapter remains in this repository. The canonical engine
contracts constrain authority and policy without claiming that every product
adapter has already been consolidated into the engine.

## Setup and runtime separation

Each released setup target embeds the native host built for the same tag,
operating system, and CPU. Setup accepts exact extension IDs and explicit
browser selections, performs user-level registration and CA trust, and writes
a bounded pre-trust ownership transaction followed by a completed receipt for
repair and exact removal. It downloads no executable payload.

Browser selections are compatibility intent rather than storage isolation.
Opera's published native-messaging contract includes a Chrome registration
location, as do the Windows Brave and Vivaldi fallbacks. Setup may therefore
write one deduplicated path observed by more than one Chromium flavor. The
allowed extension origins remain exact, and Setup refuses to replace or remove
content that is not proven to belong to this installation.

The setup application exits before ordinary browsing. It cannot mint a
successful security result, authorize a namespace decision, or weaken the
runtime fail-closed policy. The extension still requires the native host's
current session, policy generation, CA marker, and checked status on every
active runtime.

## Experimental relay boundary

The browser can consume the private HNS P2P DNS-relay transport only after an
explicit extension opt-in. Unchecked maps to `Disabled`; checked maps to
direct-authority-first `Auto`. Relayed DNS remains untrusted input to local
proof, DNSSEC, HTTPS/SVCB, TLSA, and DANE checks.

This repository implements no provider service. It opts out of opaque relay
serving and leaves every output-node role disabled. HNSR and P2P ODoH are
unimplemented and fail closed.

## Explicit recursive HNS DoH recovery

The new user-configured recursive endpoint is a terminal, separately
generation-bound requester transport:

```text
direct authoritative UDP/TCP
  -> proof-anchored owner authoritative DoH
  -> opted-in requester-only P2P relay
  -> opted-in user-configured recursive HNS DoH
  -> fail closed
```

The last edge exists only when the new URL is nonblank and Rust accepts its
strict HTTPS/hostname/port form. It is taken only for `DnsTransport` or
positively confirmed `Port53InterceptionDetected`. Response codes, malformed
wire data, DNSSEC failure, relay DNSSEC failure, and stale/missing chain or
proof evidence cannot cross it.

Endpoint bootstrap uses fixed-address validating ICANN DoH, never system DNS.
The connection targets an explicit public IP while WebPKI authenticates the
configured hostname. Its RFC 8484 response remains raw input to the local HNS
DNSSEC/TLSA/DANE stack; AD is ignored. Canonical status reports
`userConfiguredRecursiveHnsDoh` and
`userConfiguredRecursiveResolver`, never authoritative DoH.
