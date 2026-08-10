# Security Model

## Product boundary

This repository qualifies the Chromium Manifest V3 extension, Rust native
messaging host, cross-platform setup application, authenticated loopback
proxy, and their local Handshake and ICANN resolution stack. Current mobile
security claims belong to
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

Five canonical contracts and the consolidated private adapters are pinned to
one exact reviewed `handshake-rs/hns-dane-engine` Git revision recorded in
the manifest, lockfile, source-policy verifier, and notices:

- session-bound browser request authority;
- checked browser observability;
- generic ICANN DANE policy;
- dual-root namespace resolution; and
- requester/provider policy.

The local Chromium adapter, loopback listener, native messaging, per-install
CA, lifecycle, storage, and origin transport remain product code.

The MeshMine public-feed verifier core separately pins
`hns-light-chain 0.2.0` to that engine revision and
`hns-service-authority 0.2.0` to exact `hns-rs` revision
`b24b66c382de53330ec21dd3137e056a2bea3e2d`. Source policy and the lock reject
moving or registry substitutions for either authority type.

The setup application is a distribution boundary, not a browser trust anchor.
Every released target embeds the native host built from the same tag and
rejects runtime native-host overrides. It installs only exact extension IDs
supplied by the user and downloads no executable payload. Successful setup
cannot replace runtime session, generation, namespace, DNSSEC, TLSA, DANE, or
publication checks.

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

### MeshMine public pool statistics

The native verifier does not accept an HTTP endpoint, operator label, response
origin, JavaScript verdict, raw name hash, or decoded resource as HNSA
authority. Its public entry requires the independent exact lowercase HNS name,
configured Handshake network, and a non-forgeable current
`VerifiedHnsResource`. From that resource it admits
one canonical `hsa1` string and verifies the exact `pool-stats`/`0xff00`
identity, zero flags and constraints, read-only capability, authorization and
delegation signatures, current height/time, endpoint key/sequence, and strict
low-S endpoint snapshot signature and lifetime.

Authorization serial, endpoint delegation sequence, global per-operator
snapshot sequence/digest, resource/policy generation and trusted-time
high-water, and sticky equal-sequence conflict
or bounded-capacity exhaustion live in one canonical checksummed state. The
checksum detects corruption only. The API exposes a minimized verified value
only after a platform commit compares the previously loaded generation and
durably accepts the entire mutation; that commit must add atomicity,
authenticity, rollback resistance, and per-name/network serialization. Failed inputs
can still advance trusted time or terminal conflict state and therefore still
require a commit.

The minimized result carries its verification time, resource and policy
generations, committed admission generation, signed snapshot expiry, and an
effective validity deadline capped by proof-anchor expiry. Cached use requires
both current trusted time and an exact persisted admission-generation match;
any later authorization, delegation, revocation, snapshot, conflict, or
context mutation invalidates it. Reported tips, counts, mode, and
`production_eligible` are authenticated operator claims, not chain consensus,
payment, or settlement facts.

A higher valid service-authorization serial resets delegation-sequence scope,
while the global operator sequence survives service and endpoint-key rotation.
A newer valid delegation with capability `0` is committed as a revocation
before the feed becomes unavailable, so an older read-capable delegation
cannot be replayed. Only a different proof-backed `hsa1` authority at a greater
resource generation resets operator history and terminal authority state.

No such platform store or Chromium proof-authority adapter is joined. The
existing cache type lacks the private chainwork/currency constructor required
by `VerifiedHnsResource`, so treating it as equivalent would fabricate trust.
The native protocol reports `meshmineVerifiedPoolStats: false`; the popup's
bounded JavaScript decoder remains explicitly unverified and advances no
native state. HNSR, private/admin feeds, wallet/value operations, provider
roles, settlement, and marketplaces remain unavailable.

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

When validating DoH has already returned an exact origin RRset as insecure,
the insecure-delegation result is established before TLSA discovery. The
runtime does not issue a TLSA query that cannot authenticate DANE policy.
Aggregate insecure alias evidence is insufficient for this shortcut: a signed
origin CNAME into an unsigned target still requires the origin TLSA lookup.

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

## Wallet authority and artifact boundary

Wallet access cannot widen browser authority. A provider request first needs
the exact HTTPS main-frame namespace/TLS result and document generations, then
a native opaque browser-engine authority context, and finally the exact wallet
session, permission generation, method capability, and approval binding.
Extension-supplied authority-shaped JSON is never authentication. No released
engine-authority adapter is consumable at this native-host boundary, so native
wallet capability and request commands fail closed and provider code is not
injected.

The optional `data/wallet-abi-v2` service staging area accepts the wallet-owned
signed-artifact manifest schema v2. The complete file must be canonical RFC
8785 JCS; the verifier independently canonicalizes the signature-omitted
payload, checks its declared SHA-256, and verifies Ed25519 only against
verifier-owned key/release-line roots. A trusted signature is still
insufficient: admission requires an exact compiled target, sequence, release
ID, manifest digest, and artifact digest pin plus a compiled release-line
floor. Production root, pin, and floor tables are currently empty, and test
keys cannot become production trust.

Unix inspection retains current-user-owned, non-shared-writable, no-follow
directory and single-link regular-file handles and checks size and metadata
around a bounded same-handle digest. Launch-qualified manifest and artifact
files must have no write bit. Per-release-line high-water state is outside the
replaceable artifact directory under the stable data-directory handle; its
canonical checksummed bytes and read-only mode are durably replaced with
file-fsync, atomic rename, and directory-fsync. A retained stable-parent lock
serializes the entire state transaction across processes and is held through
launch revalidation, sealed copy, and spawn, so a newer admission cannot race
an older cached launch. Because same-user state is not a trust root, its
checksum is corruption/torn-write detection rather than tamper-proof secure
storage, and the compiled floor and exact pin remain mandatory.

Linux launch rebinds every retained directory/file inode to its installed path,
rehashes while copying to a sealed memfd, and executes only that sealed
descriptor with an empty environment and private pipes. macOS and Windows
launch remain unavailable until reviewed platform equivalents exist. The
controller does not call this launcher until private transport, runtime
negotiation, public projection, and opaque engine authority are released, so
overall provider availability and value movement remain false.
Every launch reparses the retained signed manifest bytes and rechecks
publication, not-before, and expiry against a fresh wall-clock sample before
and after path/state work; expiry or clock rollback fails closed.
The seal covers the executable image, not a dynamically requested ELF
interpreter or shared-library closure; production must qualify those
dependencies or require a self-contained service artifact. Manifest
publication, not-before, and expiry checks also depend on a sane local wall
clock, which remains an installation/operations qualification input.

The private wallet ABI is version 2 while the website-facing provider schema
remains version 1 and the public approval projection is version 3. Approval
prompts form a closed union of 12 typed variants:
permissions, module enablement, send, name transfer, name finalize, typed
signature, name offer, name purchase, market intent, fill acceptance, swap
redeem, and swap refund. The extension rejects mismatched method/kind, asset,
base-unit, maximum-fee asset, chain/finality, warning, identifier, or expiry
bindings. Approval, rejection, and window closure consume the exact dispatch
context retained in service-worker memory. Provider results cannot contain
inline events; only authority-bound service event frames enter event routing.
The browser validates an approval-schema-v3 public projection, not a raw private
ABI frame: canonical approval IDs are nonzero 16-byte wire IDs, every permission
summary has an explicit minimized `hnsNames` list, and the trusted window renders
each validated canonical name with its exact SHA3-256 hash. Private authority
handles and revisions are forbidden in public results and events. No adapter
that constructs this projection is joined or enabled yet.

Replay and rate state survives repeated initialization under identical
generations. Runtime replacement, navigation invalidation, and header
maintenance rotate or remove the router's internal authority-generation token;
header maintenance also consumes pending approvals before synchronization.
Every awaited native capability, request, and approval result is followed by a
fresh document-authority derivation before injection, return, or event dispatch.
A stale completion is surfaced without automatic retry because a mutation may
already have committed. The same binding applies to reads.

## Loopback proxy and local CA

- The listener binds a randomized `127.0.0.1` port.
- Each proxy generation has fresh authentication credentials.
- Credentials are accepted only by the active generation.
- The per-install P-256 CA private key remains in protected native-host data.
- Rust issues exact-host, short-lived leaf certificates only after name and
  request admission.
- PAC activation requires successful user-level CA trust installation and the
  matching certificate marker.
- Before a native process is stopped, disconnected, or replaced, JavaScript
  moves from the mandatory live PAC to a confirmed fixed blocking PAC. A
  malformed health state or failed policy transition remains on that blocker;
  runtime lifecycle paths never expose system or direct routing. Disabling or
  uninstalling the extension is the browser-owned path that removes its proxy
  setting.
- During first-run header catch-up, the newly authenticated native listener
  replaces the fixed transition blocker before synchronization begins. ICANN
  requests remain inside Rust and can proceed; HNS admission remains
  fail-closed until current corroborated target evidence is available.

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
| Setup package substitutes a different native host | Target-matched native host embedded at build time; runtime override rejected; release checksum and binary-format/architecture gates |
| Setup removes another native registration or broad user data | Fixed per-user root, exact owned-path/manifest checks, recorded trust-store identity and CA fingerprints, pre-trust transaction recovery, effective-trust verification, and unsafe-root/redirect refusal |
| Chromium flavors share a native-messaging location | Treat browser selection as compatibility intent; deduplicate shared paths, bind exact allowed extension origins, and refuse replacement or removal unless the manifest is proven to be owned by this installation |
| Page forges security metadata | Strip internal headers; publish only native checked status |
| Page forges wallet origin, generations, or permission fields | Treat them only as lookup candidates; require a native opaque engine authority context and exact wallet generations; current release remains unavailable |
| Wallet manifest changes shape, versions, capabilities, or signing bytes | Consume exact schema v2 with denied unknown fields; require full-file and signature-omitted JCS, recomputed payload hash, fixed ABI/protocol/schema/frame values, closed unique capabilities, and all five base capabilities |
| Artifact supplies a key or relies on a matching hash | Ignore artifact-supplied trust; require verifier-owned release-line Ed25519 root, exact qualified manifest/artifact pin, and compiled minimum sequence |
| Local path, symlink, or directory replacement substitutes a wallet artifact | Relative no-follow retained handles, parent-to-child inode rebinding, immutable single-link files, bounded same-handle hashes, and Linux execution only from a freshly rehashed sealed memfd |
| Artifact-directory replacement or restart attempts a wallet downgrade | Keep canonical per-release-line high-water state under the stable parent data directory; require strict sequence increase and predecessor-manifest linkage, with compiled floor/pin as the non-owner-state authority |
| Concurrent wallet admissions regress a sequence or lose another release line | Serialize the complete state transaction with one stable-parent interprocess lock; retain it through launch state/time/path checks, sealed copy, and spawn |
| Cached admission launches after expiry or local clock rollback | Reparse retained signed manifest bytes and re-evaluate publication/not-before/expiry at every launch |
| Stale wallet request is retried after a generation change | Preserve replay state for repeated initialization and surface stale completion without automatic retry |
| Browser uninstall removes independent wallet keys or databases | Store only the staged adapter manifest/artifact below browser data; wallet-owned state must remain in an independent wallet-owned location |
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

The wallet join has additional release gates: publish and independently review
a signed service artifact; provision the production root, exact release pin,
and line floor; qualify the Linux sealed launcher and private child-pipe
transport; implement equivalent macOS and Windows ownership/execution
boundaries; release the browser-engine opaque-authority and public-projection
adapters; exercise persistent runtime restart/upgrade/downgrade behavior; and
prove browser uninstall preserves independent wallet state. The admission
source and negative tests do not satisfy those product gates. Until they do,
every transport/provider/value gate remains false.
