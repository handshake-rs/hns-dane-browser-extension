# Experimental HNS P2P DNS-relay verification runbook

This runbook qualifies a private requester transport. It does not assign a
public protocol, make relayed DNS trusted, enable a provider role in the
Chromium extension, or turn the relay into a general resolver.

## Prerequisites

- Python 3 and OpenSSL;
- Docker with Compose support for `up --wait`;
- a sibling patched `hsd` checkout with installed dependencies; and
- Rust 1.92.0 for the native full-tier client.

Set `HSD_REPO` when the checkout is not `../hsd`.

## Commands

```sh
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay.sh --preflight
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay.sh
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay.sh --load

HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay-full.sh --preflight
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay-full.sh
```

`--preflight` validates shared fixtures, generates a disposable certificate,
checks Compose syntax when available, and performs no daemon-dependent
acceptance run. A successful preflight is not evidence that the topology ran.

The execution modes create a temporary artifact directory and report its path.
Use `--keep` only for deliberate local inspection; otherwise the runner
collects logs and removes containers, volumes, and disposable key material.

## Fast isolated tier

The fast tier uses deterministic scripted roles:

| Role | Capability | Purpose |
| --- | --- | --- |
| `hsd-proof` | no relay | Handshake/proof source |
| `hsd-relay-good` | relay | Valid DNS, UDP-to-TCP fallback, connection reuse |
| `hsd-relay-bad` | relay | Deterministic mismatch, timeout, busy, and size failures |
| `hsd-legacy` | no relay | Negotiation compatibility boundary |

It validates framing, current-handshake capability, zero-service requester
handshakes, complete HIP query-profile enforcement, strict correlation,
bad-to-good failover, bounded load, and local DNSSEC/TLSA/DANE decisions. These
roles do not own independent blockchains, so this tier does not prove real HSD
chain convergence or Urkel interoperability.

## Real four-`hsd` regtest tier

The full tier starts four independent patched `hsd` processes and identities.
The owner/good node mines and registers `relaytest`; all nodes synchronize to
the same chain and tree root. The provisioner requires inclusion proof
verification on every node before the browser-side client runs.

The test uses a disposable `www.relaytest` certificate and an exact TLSA owner
of `_18443._tcp.www.relaytest.`. Its authoritative DNS server exists only on a
Docker-internal bridge. The bad relay cannot reach the accepted authority and
the client must retry the good relay.

| Role | Relay bit | Expected behavior |
| --- | --- | --- |
| `hsd-owner-good` | yes | mines/registers, supplies proofs, completes relay DNS |
| `hsd-proof` | no | independent synchronized proof-capable node |
| `hsd-relay-bad` | yes | advertises service but refuses the private authority |
| `hsd-legacy` | no | synchronized node without the private capability |

Acceptance requires:

- all four chain/tree tips converge;
- every node proves the registered name;
- the requester obtains current local proof state independently of relay DNS;
- the bad relay is attempted and the good relay succeeds;
- relayed A/AAAA, denial, HTTPS/SVCB, and TLSA data are locally validated;
- the certificate matches the secure TLSA policy;
- the HTTPS origin returns the expected response; and
- no legacy public HNS resolver is contacted.

The full-tier native client enables the explicit requester policy for the test.
It does not advertise an opaque relay or output-node service.

## Artifacts

Review the reported directory rather than relying only on the command exit
code. Expected evidence includes:

- runner and Compose logs;
- per-role status/metrics;
- deterministic request and failure-case results;
- fast-tier or full-tier JSON acceptance output;
- TLSA owner, DNSSEC/DANE decision, and HTTPS result; and
- bad-to-good retry evidence.

Normal artifacts must not contain full browsing history, URL paths, request
headers/bodies, stable browser identifiers, or unrelated qnames. Disposable
certificates are allowed; private keys must be removed after teardown.

## Controlled canary

Any network canary is manual and requires:

1. explicitly enabled patched output nodes;
2. explicit tester opt-in to the browser requester;
3. independent relay operators and an immediate disable path;
4. monitoring limited to aggregate availability, bounds, and validation stage;
5. confirmation that invalid DNSSEC, TLSA, or DANE always fails closed; and
6. language that accurately describes ordinary TCP visibility.

Prefer Brontide where interoperable, but do not call the one-hop transport
ODoH. Stop the canary on a privacy leak, validation discrepancy, bound failure,
single-relay dependency, or ambiguous provenance. Disable the requester first,
then the experimental output nodes.

HNSR and P2P ODoH remain unimplemented. Promoting any temporary identifier
requires a separate interoperable specification, privacy review, and public
assignment process.
