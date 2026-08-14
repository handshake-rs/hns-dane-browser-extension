# Architecture

This repository is the Chromium extension, native-host, and desktop setup
product. Current Android and iOS work lives in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).

The Chromium adapter consumes five canonical browser contracts and the private
Chromium adapters from one exact reviewed `handshake-rs/hns-dane-engine`
`0.2.1` Git revision. The canonical
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
it. Routine synchronization does not tear down the live proxy;
same-authority publication pauses existing work only for the brief commit
window.

An unchanged-authority refresh publishes updated headers or quorum evidence
without rotating the header-maintenance epoch. Publication rotates that epoch
when the exact authoritative network, root height, or tree-root hash changes
or becomes unavailable, invalidating proof-cache and status evidence bound to
the old name state.

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
schedules one synchronization ten minutes before that point and reuses the
existing five-minute local health alarm as a safety path, rather than adding
another periodic peer poll. Failed attempts in routine stale or unknown state
remain rate-limited to a ten-minute retry interval. Only around a previously
authenticated quorum deadline, failed automatic or manual attempts use a
bounded one-minute retry cadence from the ten-minute lead window through two
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
native maintenance epoch. Same-authority publication briefly pauses and then
resumes both halves; a changed or unavailable authoritative root advances the
epoch and revokes them. If the selected raw origin socket cannot open, the
proxy returns a pre-TLS CONNECT failure and never substitutes local TLS.

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
- `hns-loopback-proxy`: exact-commit engine-owned Chromium adapter for the
  authenticated HTTP/CONNECT endpoint, local DANE TLS termination, raw
  browser-WebPKI duplex tunneling, response-head publication, and Upgrade
  tunneling.
- `hns-gateway` and `hns-transport`: exact-commit engine-owned Chromium
  adapters for selected-plan HTTP/TLS/QUIC execution and exact-IP split
  browser-WebPKI sockets.
- `hns-resolver`, `hns-dnssec`, `hns-dane`: exact-commit private adapters from
  `hns-dane-engine` for verified Handshake resolution, delegated DNSSEC, and
  DANE primitives. The resolver retains the browser-only light-proof and
  dual-root boundary; full-node recursion remains in `hns-resolverd`.
- `hns-chain`, `hns-sync`, `hns-p2p`, and `hns-urkel`: exact-commit private
  adapters from `hns-dane-engine` for the Handshake header and proof trust path.
  The source-policy gate forbids restoring product-local copies.
- `hns-meshmine-pool-stats`: schema-2 profile verification beneath an opaque
  current HRM/HNSA broker authority. It verifies the canonical service-signed
  endpoint delegation and endpoint-signed, route-bound snapshot and maintains
  bounded commit-before-release replacement state. The opaque authority has no
  public constructor, so this crate has no current product, HTTP, HNSR, wallet,
  value, provider, or marketplace role.

The product-specific adapter remains in this repository. The canonical engine
contracts constrain authority and policy without claiming that every product
adapter has already been consolidated into the engine.

The current Chromium cache exposes browsing proof results but not the complete
current HRM/HNSA authority aggregate. Consequently the verifier core is a
native dependency and reported capability, but no message reaches it and no
verified pool value reaches JavaScript. A future sole broker must preserve the
authenticated current name/root, deterministic HRM, exact service observation,
trusted-time, withdrawal/generation history, revision floor and fenced lease,
then commit complete state atomically before returning a minimized snapshot.

The display-only popup already collects the expected exact canonical HNS root
separately from the public HTTP endpoint, validates Handshake's consensus name
grammar (including interior underscores and the five blacklisted roots), and
derives the SHA3-256 Handshake name hash before any request. It does not infer
an endpoint from the active tab. This mirrors `hns-covenants::validate_name`
and `hns-covenants::hash_name`; it is intentionally distinct from HNSA's
hyphen-only service-name grammar. The selection remains local presentation
state until a native request binds it to proof authority and the authenticated
rollback-resistant verifier store; neither the endpoint nor its response can
supply trusted identity.

## Setup and runtime separation

Each released setup target embeds the native host and canonical height-300,000
mainnet header snapshot built for the same tag, operating system, and CPU.
Setup starts with the exact canonical and catalog extension IDs baked into the
release, accepts explicit advanced additions and browser selections, performs
user-level registration and CA trust, and writes a bounded pre-trust ownership
transaction followed by a completed receipt for repair and exact removal. It
downloads no executable or bootstrap payload.

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

The extension and native host share one release version. The worker validates
the `hello` response before requesting runtime activation. An absent,
malformed, older, or newer native component leaves the fixed blocking gate in
place, publishes a structured update-required status, and opens the embedded
Setup handoff at most once per browser session for that required version. It
never treats an incompatible host as a degraded-but-routable runtime.

## Wallet ABI boundary

The wallet provider remains subordinate to the browser's namespace and TLS
authority. The extension's tab, document, origin, and generation values are
lookup candidates only; they cannot authenticate a native wallet operation.
Dispatch requires an opaque authority context produced by the browser engine,
plus exact wallet ABI, framed-service protocol, provider-schema, capability,
wallet-session, permission-generation, and approval-generation agreement.

The native host has a signed-release admission boundary for a future
independently released wallet service under `data/wallet-abi-v2`. It consumes
the wallet repository's exact signed-artifact manifest schema v2: target,
source, release, anti-rollback, and signature objects; private wallet ABI 2;
framed-service protocol 2; website provider schema 1; approval schema 3; the
bounded frame maximum; and the wallet contract's closed service-capability
vocabulary with the five foundation capabilities required. The complete
stored manifest must itself be RFC 8785 JCS even though the upstream schema
requires JCS only for the signature-omitted payload. This intentional stricter
admission rule makes duplicate keys, whitespace, member order, payload digest,
and signature bytes deterministic.

Unix inspection preserves bounded no-follow, handle-based ownership, metadata,
single-link, and same-handle SHA-256 checks. Authenticity then requires a
verifier-owned Ed25519 root selected by key ID and release line; launch
admission additionally requires the exact manifest and artifact digests,
target, release ID, and sequence in a compiled qualification pin. A compiled
per-line minimum is authoritative even if user-owned state is removed. A
canonical high-water record stored under the stable native-host data directory
is written as an immutable temporary file, fsynced, atomically renamed, and
followed by a directory fsync. Upgrades must link
`previousManifestSha256` to the accepted predecessor.
One stable-parent advisory lock serializes the complete read/compare/write/
verify transaction across native-host processes, so concurrent release lines
cannot lose entries and concurrent sequences cannot regress the high-water.
The state checksum detects corruption and torn/incomplete replacement; it does
not turn same-user storage into a tamper-proof trust anchor. The compiled floor
and exact release pin supply that independent admission authority.

Immediately before Linux launch, the verifier rebinds the retained parent,
ABI-directory, manifest, and artifact handles to their installed path inodes,
rechecks the stable high-water record and signed publication/not-before/expiry
window, and copies and rehashes the artifact into a sealed memfd. The same
stable-parent lock is held across both revalidations, the sealed copy, and
process spawn, preventing a newer admission from racing an older cached launch.
Only that sealed descriptor is executed with an empty environment and private
pipes. The verifier has no `PATH` search, `dlopen`/plugin fallback, or sibling
wallet-crate fallback. macOS and Windows execution reject until reviewed
sealed/ACL equivalents exist.
Sealing protects the main executable bytes, not an ELF interpreter or shared
libraries requested by a dynamically linked artifact. Production
qualification must therefore require a self-contained artifact or separately
pin and audit its complete runtime dependency closure.

The Linux module also owns a dormant ABI-v2 read-only subprocess controller.
It uses absolute-deadline nonblocking frames, correlates exact host/service
sessions, restart generations, directional sequences, and request IDs, rejects
runtime capabilities outside its caller-supplied admitted ceiling, and kills
and reaps a child after any transport or protocol failure. Its private request
surface covers wallet status, one exact HNS account admitted by
`listAccounts`, and HNS balance, receive target, transaction history, and
module status. The controller supplies no caller-selected account or module,
and each value call has only its own synchronization authority rather than a
shared snapshot across calls. The additive private `hnsReadOperationsV1`
marker freezes exactly those six operations and excludes workflow status.

A dormant Linux-only native composition now joins that controller to admitted
artifact launch around one single-use `WalletBootstrapLease` obtained for the
new restart generation. The lease owns one typed, explicitly supplied,
pre-existing wallet database configuration and one opaque read-only
close-on-exec pipe end. Discovery cannot proceed without it, a source cannot
replay it, and launch failure consumes and closes it. The browser never parses
the opaque packet. The launcher installs a collision-safe copy at fixed child
descriptor 3 and moves the sealed executable descriptor away from that slot
when necessary; the original bootstrap descriptor remains close-on-exec.
Standard input/output remain exclusively ABI-v2 framing, the environment is
empty, and the sealed child receives exactly
`--database <configured-absolute-path>` with no additional mode or caller
arguments.

The database configuration accepts only an absolute canonical UTF-8 path with
a closed basename, walks every parent component without following symlinks,
retains the owner-private `0700` parent and nonempty owner-only `0600`
single-link database handles, and rebinds their device/inode/owner/mode/link
identity before launch, after spawn and negotiation, and around each read.
Database length and write timestamps may change under SQLite without changing
the retained identity. After negotiation and before and after nonpoisoning
reads, the host also scans the live child's Linux descriptor table and requires
a descriptor for the retained database inode. This makes a
wrong base-database open detectable after hello, before the session is admitted,
even when the pathname has already been restored before the host rechecks it.
The scan is bounded and covers the immediate child's base-database descriptors;
it does not attest SQLite sidecars, prevent an open/migration side effect before
hello, prove exclusive descriptor use, or turn same-UID filesystem tampering
into a supported isolation boundary.

The manifest-derived negotiation ceiling requires the five foundation
capabilities plus both `walletOperations` and `hnsReadOperationsV1`, admits only
the persistent-permission and provider-dispatch scaffolding currently reported
by the standalone persistent service, and excludes `valueMovement` and
`browserIntegration`. The runtime hello and every closed request require both
operation markers. The request enum itself has no workflow, provider, unlock,
lock, approval, or mutation variant. A generation-owning slot kills and waits
for the prior child before restart, never reuses a failed generation, and does
not let a stale invalidation stop a newer session. Path change, malformed
hello/frame, timeout, EOF, or drop poisons and reaps the child; a poisoned read
also removes that generation from the active lifecycle slot.

`WalletBootstrapLease` currently means authorization for one launch attempt,
not a renewable broker session or an ongoing revocation/database-exclusivity
lease. Descriptor closure does not prove that no process or descendant retains
wallet state. Those semantics require a future wallet-owned lifecycle protocol.

The checked-in wallet-service executable currently opens the database into its
locked control runtime. That runtime can return status but does not provide the
account/balance/receive/history/module read set and does not advertise
`hnsReadOperationsV1`, so the browser rejects read-session admission. The
synchronized HNS runtime also needs trusted account and authenticated
loopback-node configuration, and the browser's closed read enum intentionally
supplies no unlock secret. Broad `walletOperations` is therefore insufficient.
A future signed manifest and matching hello must both carry the exact marker;
the changed manifest must be signed and exactly release-qualified. A positive
sealed launch through that service, trusted unlock/configuration join, and a
single-process/no-inherited-descendant invariant remain required before product
integration.

This composition is not installed in `NativeHostController`: no native-message
variant supplies a database path, a bootstrap packet, or invokes it. Its
production bootstrap source is deliberately unavailable. Negotiating provider
scaffolding does not satisfy browser authority, projection, release, or
availability gates.

No production trust root, release pin, or release floor is configured yet, and
test keys are compiled only for tests. No independently released service,
released Chromium transport join, or native-to-public approval projection
adapter is joined, and the current engine exposes no consumable opaque wallet
authority context. The browser controller therefore never calls the launcher.
All three parsed wallet command envelopes fail closed,
`handshakeWalletProvider` is false, and provider injection cannot occur. The
browser's DANE runtime is independent of this unavailable optional join.

Repeated provider initialization under an identical authority preserves replay
and rate state. A generation transition replaces it. Header maintenance rotates
an internal router-authority generation, clears document and approval state,
and marks navigation authority maintenance-pending before native sync. Native
capability, request, and approval completions are followed by fresh authority
derivation before injection, return, or event dispatch. A stale result is
returned without automatic retry because a mutating wallet operation may
already have executed.

The native capability snapshot accepts permission generation zero for an
authority that has never had a permission record or tombstone. Its negotiated
method set may still contain the non-permissioned bootstrap methods needed to
request access; methods are runtime support, not granted permission. The first
grant is generation one. Accepting the initial zero does not relax the exact
wallet-session and permission-generation binding on native event delivery.

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
