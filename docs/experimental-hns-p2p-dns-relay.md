# Experimental HNS P2P DNS relay

Status: private proof of concept. The service bit and packet identifiers are
temporary private values, not Handshake protocol assignments. HNSR and P2P
ODoH are different designs and are not implemented by this browser.

## Purpose

The requester already validates Handshake headers and Urkel name proofs
locally, derives a delegation from that state, validates delegated DNSSEC, and
applies HTTPS/SVCB and TLSA/DANE policy locally. The relay adds only an
untrusted DNS transport for proof-backed HNS names when direct authority is
unreachable.

The direct-authority-first order is:

1. current local header and verified proof state;
2. direct authoritative UDP with TCP fallback;
3. proof-declared authoritative DoH after direct authority is unavailable or
   fails, including when a positive matching TEST-NET canary classifies port
   53 as intercepted;
4. experimental HNS P2P DNS relay, when the browser requester is explicitly
   opted in.

A positive canary stops futile TCP and remaining direct-server attempts for
the intercepted path. A timeout or inconclusive canary does not classify
interception or authenticated absence.

No production path uses a public recursive HNS resolver. Relayed bytes never
set `secure` by themselves and cannot replace a missing or stale local proof.

## Consent and role separation

The Chromium option controls requester behavior only:

- unchecked maps to canonical requester policy `Disabled`;
- checked maps to canonical direct-authority-first policy `Auto`.

The extension advertises no relay service and enables no provider role.
Opaque P2P relaying and an output node are separate ecosystem roles: a product
that implements opaque relaying may make that role default-on with opt-out,
while every output/provider role requires explicit opt-in. Neither role is
enabled by this requester's checkbox.

## Temporary negotiation and framing

Handshake P2P frames use the existing nine-byte header. This experiment uses:

| Item | Private value |
| --- | ---: |
| `EXPERIMENTAL_DNS_RELAY_SERVICE` | `0x40000000` (bit 30) |
| `EXPERIMENTAL_GET_DNS_RELAY` | `0xf0` |
| `EXPERIMENTAL_DNS_RELAY` | `0xf1` |

A requester sends `0xf0` only after the current version handshake advertises
the service bit. Cached observations never override the live handshake.
Relay-only requester handshakes advertise zero local services, including no
`SERVICE_NETWORK`. Their remote version heights are not promoted into
header-sync currentness.

The payloads are little-endian except for the embedded DNS wire message:

```text
GetDnsRelay {
    request_id: u64,
    query_length: u16,
    query: [u8; query_length]
}

DnsRelay {
    request_id: u64,
    status: u8,
    response_length: u16,
    response: [u8; response_length]
}
```

Parsers reject trailing bytes, zero request IDs, and non-canonical or
out-of-bound lengths before copying data. Query size is bounded at 4,096 bytes
and response size at 65,535 bytes.

Transport statuses are:

| Value | Name |
| ---: | --- |
| 0 | `OK` |
| 1 | `REFUSED` |
| 2 | `UNSUPPORTED` |
| 3 | `BUSY` |
| 4 | `INVALID_QUERY` |
| 5 | `RESOLVER_UNAVAILABLE` |
| 6 | `TIMEOUT` |
| 7 | `INTERNAL_ERROR` |

DNS RCODE, truncation, and DNSSEC material remain inside an `OK` DNS message.
An unknown future status closes the affected exchange/connection without
automatically changing peer score or cooldown.

## Query and response profile

Before transmission the requester requires:

- one complete standard DNS query with one `IN` question;
- `RD` and `CD` set, and response-only header flags clear;
- one root-owner EDNS(0) OPT, `DO` set, payload size 512 through 4,096;
- no ECS or other EDNS option except well-formed padding;
- a syntactically valid Handshake rightmost label; and
- a bounded allowlist of record types needed for address, delegation, denial,
  service, and DANE processing.

ANY, zone transfer, update, private infrastructure, ICANN-rooted questions,
and HNS roots absent from current local name state are refused. The query does
not carry a destination address or port.

The client accepts a response only for a live request on the same connection
and checks request ID, DNS transaction ID, opcode, exact question tuple,
framing, and size. Unsolicited, duplicate, late, mismatched, or malformed
responses are rejected. The AD bit is never used as a trust decision.

Relayed answers enter the normal validation chain unchanged:

```text
validated headers -> verified Urkel proof -> proof-derived NS/DS
  -> raw relayed DNS -> local DNSSEC and denial validation
  -> HTTPS/SVCB -> TLSA -> local DANE certificate validation
```

Invalid DNSSEC, TLSA mismatch, stale Handshake state, and malformed data remain
fail-closed. A relay is recorded only as an intermediary; it never replaces
the delegated nameserver as authority.

## Bounds and privacy

The prototype output-node implementation applies per-peer rate and concurrency
bounds, a global in-flight bound, a three-second recursive deadline, and
bounded response size. Responses use the established TCP connection, so this
does not create a UDP reflection surface.

Normal logs and persisted diagnostics omit full qnames, DNS messages, URLs,
headers, bodies, and stable browser identifiers. Aggregate counts, coarse
latency/size buckets, retry count, transport class, and validation stage are
permitted. The experiment adds no ECS, telemetry, speculative prefetch, or
measurement query.

Ordinary Handshake TCP is plaintext and exposes the query to the peer and
network observers. Brontide may protect a compatible peer connection, but this
single-hop relay is not oblivious DNS and must never be described as ODoH.

## Qualification

The fast tier validates deterministic framing, negotiation, failover, query
profile, bounds, local DNSSEC/DANE enforcement, and privacy-oriented artifacts.
The full tier uses four real patched `hsd` processes on regtest and verifies
convergent chain/name state, Urkel proofs, relay failover, DNSSEC, TLSA/DANE,
and an HTTPS origin.

See
[Experimental P2P DNS-relay runbook](experimental-p2p-dns-relay-runbook.md).
Passing either tier is experiment evidence, not a public-protocol assignment or
a signed browser-release qualification.
