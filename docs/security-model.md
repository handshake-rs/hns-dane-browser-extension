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

The MeshMine public-feed verifier no longer consumes the superseded
`hns-service-authority`/`hsa1` model. Its production-shaped boundary consumes
only the canonical engine's nonconstructible current HRM/HNSA guard; the mapped
local authority remains noncloneable and has no public constructor. Chromium
does not yet implement the engine broker's platform backend.

The setup application is a distribution boundary, not a browser trust anchor.
Every released target embeds the native host and canonical header bootstrap
built from the same tag and rejects runtime payload overrides. It installs
only exact release-baked or explicitly entered extension IDs and downloads no
executable payload. Setup validates both snapshot digests and bounds
decompression; the native host independently validates genesis, linkage,
proof-of-work, difficulty, checkpoints, count, trailing data, and the exact
height-300,000 tip. Successful setup cannot replace runtime session,
generation, namespace, DNSSEC, TLSA, DANE, or publication checks.

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
the extension requests synchronization ten minutes before that point. Failed
attempts retain a bounded one-minute urgent retry window through two minutes
after that known deadline; unrelated stale or unknown state remains on the
ten-minute attempt floor.
Missing or expired evidence still fails closed; the deadline is scheduling
metadata, not an extension of its validity.

### MeshMine public pool statistics

The native profile verifier does not accept an HTTP endpoint, response origin,
JavaScript verdict, raw name hash, or decoded DNS resource as HRM/HNSA
authority. It requires an opaque `CurrentHrmNamedService` bound to the exact
network/name, HRM sequence and envelope hash, current aggregate revision and
trusted operation time, service resource/delegation IDs and generation,
service key, validity intervals, capability/constraint policy, and fenced
lease generation. That type has no public constructor. The sole
production-shaped adapter accepts only the canonical engine's live
`CurrentCommittedNamedService`, rejects withdrawal, maps its exact active
service, and checks the engine lease both before mapping and after profile
persistence. The surrounding engine broker retains and release-checks the
owned guard across the complete callback.

Beneath that boundary, schema 2 canonically parses the HRM-backed HNSA endpoint
delegation, verifies its strict-DER low-S service-controller signature under
the exact HNSA domain, and matches network, service IDs/generation, endpoint
key/sequence, time, lifetime, capabilities, and constraints. The endpoint-
signed application record separately binds those values, the calculated
endpoint-delegation ID, private profile `0xff00`, an independently selected
route ID, record sequence, and expiry under a distinct profile domain. The old
`hsa1`, fixed service authorization, and old document schema are rejected, not
fallbacks.

Handshake root labels use consensus grammar, which permits interior `_` as
well as `-` and rejects `example`, `invalid`, `local`, `localhost`, and `test`;
the HNSA service name remains the distinct hyphen-only `pool-stats`. The parser
does not reserve zero for an unsigned network/time or opaque cryptographic
digest/ID field unless the defining draft says nonzero. Both endpoint and
snapshot signatures must round-trip to the exact strict-DER bytes in addition
to being low-S. An unchanged aggregate revision must carry the exact retained
HRM root and service observation or the profile state becomes conflicted.
A greater trusted operation time is durably retained locally but cannot be
used beneath the old broker revision: the trusted-time-only aggregate
transition itself requires a fresh acknowledged revision before authorization.

Endpoint and global per-operator sequence/digest history, current authority
observation, trusted-time high-water, and sticky conflict/capacity state live
in one canonical checksummed profile state. A minimized result is released
only after compare-generation commit of every mutation and must reconfirm the
exact authority revision, lease generation, trusted time, state generation,
and validity before use. The checksum detects corruption only; the embedding
must add atomic authenticated storage, external rollback floors, exact retry
of ambiguous writes, and subject-wide serialization. Reported tips, counts,
mode, and `production_eligible` remain operator claims, not consensus, payment,
wallet, or settlement facts.

For this private profile, the compressed endpoint key is the logical endpoint
replacement key. Snapshot sequence is global to an operator ID within one
service generation, across endpoint keys; changing signed bytes at an equal
sequence is equivocation. Service-controller replacement clears both histories
only after a greater service generation is admitted.

The canonical engine now supplies complete HRM/HNSA validation, durable
authority-state transitions, and the guarded broker/consumer contract, and the
profile crate is joined to that guard. Chromium still supplies no qualified
backend for current HNS/HRM retrieval, trusted time, authenticated aggregate
CAS, external rollback floor, or cross-process fencing, and it has no native
message or UI join. Native capabilities therefore report
`meshmineHrmAuthorityAdapter: false`,
`meshmineLegacyHsa1Accepted: false`, and
`meshmineVerifiedPoolStats: false`; the JavaScript decoder remains explicitly
unverified and advances no native state. HNSR, private/admin feeds,
wallet/value operations, provider roles, settlement, and marketplaces remain
unavailable.

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
gated unless the CONNECT write succeeds. Header publication pauses both halves
while state is incomplete. It advances the native epoch and revokes them only
when the exact authoritative name-tree root changes or becomes unavailable;
stop, policy change, readiness loss, or generation rotation also closes them.

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
private Linux source can call this launcher only through its exact-database
read-session composition, and each restart generation must consume one
`WalletBootstrapLease`. The lease joins the retained database identity to an
opaque read-only close-on-exec pipe plus canonical network/magic, a nonzero
opaque namespace and lease generation, and a broker-owned currentness guard;
the browser does not parse its packet.
Launch maps it collision-safely to fixed child descriptor 3 while leaving
stdin/stdout exclusively for ABI-v2 frames, argv exactly
`--database <path>`, and the environment empty. Failure consumes the lease and
closes the pipe end. `NativeHostController` does not construct that session and
the production source returns no lease. Public projection and opaque engine
authority remain unreleased, so overall provider availability and value
movement remain false.

The lease authorizes one launch attempt and transfers its currentness guard to
the admitted session. The guard must remain current around each read and across
authority acquisition, dependent callback, exact status/account/revision/
lifecycle comparison, and final database/process revalidation. A guard denial,
callback misuse, context mismatch, or unwind poisons and synchronously reaps
the child; the lifecycle removes it before a panic resumes. The production
source returns no lease until a real wallet broker provides those semantics.
The guard does not make descendant/database exclusivity true without that
broker's separate qualification.

The borrowed dependent callback is read-only by contract. Its release-boundary
check can detect late authority loss but cannot undo an external side effect
that already completed. Signing, value movement, and wallet mutation require a
separate precommit/commit authority protocol and are never authorized by this
borrowed read authority.

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
  replaces the fixed transition blocker before synchronization begins. A
  packaged, enabled declarative main-frame rule is already present during
  first install and extension upgrade. It keeps HTTP(S) GET navigation on a
  local waiting page until the exact corroborated name-tree authority is ready,
  then a higher-priority session rule permits the waiting document to resume
  its own URL once. The allow rule closes before peer evidence can expire, and
  already-admitted main-frame GETs are transferred before native state changes.
  A request/error safety path handles stale allows after worker suspension or
  OS sleep. It never replays POST or adds a direct-routing fallback.
- Established transport continuity is bound to the exact authoritative
  network, root height, and tree-root hash rather than the incidental SQLite
  generation. Same-root header publication can therefore preserve an ICANN
  WebPKI tunnel, while a new root or readiness loss still revokes it.

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
| Setup package substitutes a different native host or header bootstrap | Target-matched native host and hash-pinned snapshot embedded before platform signing; runtime overrides rejected; strict decompression and independent native chain validation; release checksum and binary-format/architecture gates |
| Extension update reaches an older or newer native host | Compare the exact release version in `hello` before activation; retain the blocking gate; expose a structured update-required state and a once-per-session embedded Setup handoff |
| Setup removes another native registration or broad user data | Fixed per-user root, exact owned-path/manifest checks, recorded trust-store identity and CA fingerprints, pre-trust transaction recovery, effective-trust verification, and unsafe-root/redirect refusal |
| Chromium flavors share a native-messaging location | Treat browser selection as compatibility intent; deduplicate shared paths, bind exact allowed extension origins, and refuse replacement or removal unless the manifest is proven to be owned by this installation |
| Page forges security metadata | Strip internal headers; publish only native checked status |
| Page forges wallet origin, generations, or permission fields | Treat them only as lookup candidates; require a native opaque engine authority context and exact wallet generations; current release remains unavailable |
| Wallet manifest changes shape, versions, capabilities, or signing bytes | Consume exact schema v2 with denied unknown fields; require full-file and signature-omitted JCS, recomputed payload hash, fixed ABI/protocol/schema/frame values, closed unique capabilities, and all five base capabilities; read-session admission additionally requires both signed `walletOperations` and `hnsReadOperationsV1` markers and a matching runtime hello; authority use additionally requires signed/runtime `hnsWalletAuthorityContextV1` |
| Artifact supplies a key or relies on a matching hash | Ignore artifact-supplied trust; require verifier-owned release-line Ed25519 root, exact qualified manifest/artifact pin, and compiled minimum sequence |
| Local path, symlink, or directory replacement substitutes a wallet artifact | Relative no-follow retained handles, parent-to-child inode rebinding, immutable single-link files, bounded same-handle hashes, and Linux execution only from a freshly rehashed sealed memfd |
| Configured wallet path is aliased, replaced, shared, or redirected between admission and a read | Accept one explicit canonical absolute path only; walk ancestors no-follow; retain owner-private parent/database handles; rebind device/inode/owner/mode/link identity around launch, negotiation, and every read; after hello, boundedly attest that the immediate child holds the retained base inode; poison, kill, wait, and remove the generation on change. This detects but cannot prevent a pre-hello wrong-inode open/migration, does not attest SQLite sidecars or exclusive use, and assumes same-UID state tampering is outside the isolation boundary |
| A restart launches without fresh wallet bootstrap authority or replays one | Require a generation-bound, single-use `WalletBootstrapLease`; consume it before discovery/launch; accept only an opaque read-only close-on-exec FIFO; bind it to canonical network/magic plus a nonzero opaque namespace/generation and broker guard; map it collision-safely to child descriptor 3 while preserving ABI-only stdin/stdout; keep the production source unavailable. The transferred guard must remain held through dependent use and final revalidation. |
| Wallet authority, revision, lifecycle, or namespace changes during dependent use | Use only the additive native `hnsWalletAuthorityContextV1` contract; require exact active-wallet/account and nonzero revisions with persistent/ready/nonrecovering/nonretiring state; re-read and compare under the same guard after the callback; poison, kill, reap, and remove on mismatch, lease loss, callback misuse, or caught unwind; keep the release gate false and require the exact negotiated marker even after a future gate flip |
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
and line floor; qualify the Linux sealed launcher, exact-database composition,
and private child-pipe transport; implement equivalent macOS and Windows
ownership/execution
boundaries; release the browser-engine opaque-authority and public-projection
adapters; exercise persistent runtime restart/upgrade/downgrade behavior; and
prove browser uninstall preserves independent wallet state. The admission
source and negative tests do not satisfy those product gates. Until they do,
every transport/provider/value gate remains false.

Linux qualification must additionally prove the exact service's read set and
trusted unlock/account/node join. Broad `walletOperations` alone is rejected;
the signed manifest and runtime hello must also carry `hnsReadOperationsV1`,
which freezes status, list-accounts, and the four HNS balance/receive/history/
module-status reads while excluding workflow and value operations. The marker
does not replace a positive interoperability fixture. Any HRM/HNSA wallet
consumer must additionally carry `hnsWalletAuthorityContextV1`, use a real
network-bound namespace broker lease, and pass mismatch, lease-loss, callback-
misuse, unwind, and exact-`u64` qualification. The qualified artifact
must remain one process with no inherited database-holding descendants because
lifecycle termination owns and waits only for the immediate child.
