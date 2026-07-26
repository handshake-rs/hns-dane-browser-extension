# Architecture

This repository is the Chromium extension and native-host product. Current
Android and iOS work lives in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

The Chromium adapter consumes five canonical browser contracts from
`handshake-rs/hns-dane-engine` at immutable revision
`fe38e805ba9d8ba26d486c5c7aa67c87c8cf9159`. The canonical
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

Status names this path `DANE via ICANN DoH`. Bogus DNSSEC is not absence.
Typed DANE failure is preserved across HTTP/1.1, HTTP/2, HTTP/3, CONNECT, and
WebSocket paths rather than inferred from error strings.

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

- `hns-chromium-native-host`: native messaging, policy, per-install CA,
  lifecycle, installers, and sanitized schema conversion.
- `hns-chromium-platform-runtime`: Chromium storage/network adapter, sync,
  dual-root plan construction, canonical authority integration, and status
  observation.
- `hns-loopback-proxy`: authenticated HTTP/CONNECT endpoint, local TLS
  termination, response-head publication, and Upgrade tunneling.
- `hns-gateway` and `hns-transport`: selected-plan HTTP/TLS/QUIC execution.
- `hns-resolver`, `hns-dnssec`, `hns-dane`: verified Handshake resolution,
  delegated DNSSEC, and DANE primitives.
- `hns-chain`, `hns-sync`, `hns-p2p`, and `hns-urkel`: local Handshake header
  and proof trust path.

The product-specific adapter remains in this repository. The canonical engine
contracts constrain authority and policy without claiming that every product
adapter has already been consolidated into the engine.

## Experimental relay boundary

The browser can consume the private HNS P2P DNS-relay transport only after an
explicit extension opt-in. Unchecked maps to `Disabled`; checked maps to
direct-authority-first `Auto`. Relayed DNS remains untrusted input to local
proof, DNSSEC, HTTPS/SVCB, TLSA, and DANE checks.

This repository implements no provider service. It opts out of opaque relay
serving and leaves every output-node role disabled. HNSR and P2P ODoH are
unimplemented and fail closed.
