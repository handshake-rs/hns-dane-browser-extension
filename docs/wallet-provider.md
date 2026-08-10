# Handshake wallet provider (private ABI v2)

The Chromium product has a Handshake-specific, event-discovered provider. It
does not create `window.ethereum` and does not reproduce a generic Ethereum or
Bitcoin signer.

## Authority path

1. An isolated content bridge starts at `document_start` for HTTPS main frames.
2. The service worker resolves the sender to Chromium's exact tab and
   `documentId`.
3. `NavigationReceiptStore` must have a current, non-restored, non-maintenance
   security receipt for the same serialized origin. The runtime must be active
   with its mandatory proxy installed.
4. The native host must independently obtain the browser engine's opaque
   provider-authority context and negotiate the exact private wallet ABI v2
   contract. The website-facing provider schema remains version 1 and the
   public approval projection is exactly schema 3; neither is the private
   host/service ABI version.
   Extension-supplied origin and generation fields are lookup candidates, not
   native authentication. Until both joins exist, the capability probe fails
   and no MAIN-world provider is installed.
5. The service worker injects `provider-inpage.js` into that exact `documentId`.

The first document-start probe is expected to precede the completed navigation
receipt. A receipt-ready message to the exact document, plus a small bounded
fallback retry window, closes that lifecycle race without polling indefinitely.

The binding carried only inside the isolated bridge includes origin, selected
namespace, browser-authority session, runtime generation, policy generation,
navigation generation, wallet session, permission generation, and document ID.
Every request re-derives browser authority and compares every generation.
History changes, BFCache restore, policy/runtime replacement, header
maintenance, wallet restart, and permission replacement make prior requests
and pending approvals stale. Header maintenance synchronously rotates an
internal router-authority generation, clears document bindings, consumes
approval contexts, and marks navigation receipts maintenance-pending before
native synchronization begins. Approval revalidation obtains fresh browser and
wallet capability generations immediately before a decision is dispatched.
Repeating initialization under the identical authority and wallet generations
does not reset sequence, request-ID, pending, or rate-limit state. A genuine
generation change creates a new replay domain.

## Discovery and calls

Applications listen for `hns:announceProvider` and dispatch
`hns:requestProvider`. The announced provider has only:

```js
provider.request({ method, params })
provider.on(event, listener)
provider.removeListener(event, listener)
```

The complete method/event allowlists live in
`extension/src/wallet-provider-protocol.js`. Frames are versioned and bounded;
sequences are monotonic; duplicate IDs within the bounded document replay
window and replayed sequences fail; global and per-method read/mutation rates
are independently limited. External-asset calls accept
only `bitcoin` or `ethereum`. The default website API explicitly rejects raw
Ethereum calls/signatures, chain changes, PSBT signing, and raw transaction
signing.

The page never supplies a native-host command. The service worker maps an
allowlisted provider-schema-v1 request into the private ABI-v2 boundary. The
only other wallet-native commands are the capability probe and an approval
decision.
The bridge never automatically retries a request after a stale-context,
permission-generation, or wallet-session result: a mutating call may already
have executed. It returns that error and requires a new explicit page request.
Reads use the same replay and idempotency binding. After each awaited native
capability, request, or approval result, the router checks its internal
authority-generation token and re-derives exact document authority before it
injects, returns, or dispatches response events. That post-operation check is
separate from native enforcement of the opaque authority context.

## Approval and event ownership

The native wallet may return a versioned `approvalRequired` descriptor. The
extension accepts the ABI-v2 closed union of exactly 12 typed public summaries:
`permissions`, `moduleEnablement`, `send`, `nameTransfer`, `nameFinalize`,
`typedSignature`, `nameMarketOffer`, `nameMarketPurchase`, `marketIntent`,
`fillAcceptance`, `swapRedeem`, and `swapRefund`. It validates the exact origin,
expiry, method-to-kind pairing, nested asset and integer base-unit amounts,
maximum-fee asset, chain/finality, enumerated warnings, and applicable public
identifiers. Missing, extra, kind-mismatched, or free-form display data fails
closed.

That descriptor is a browser-owned public projection with approval schema 3,
not the raw private `ApprovalPrompt` frame. Every `permissions` summary requires
an `hnsNames` list. It is empty without Names authority and for
`hns_requestAccounts`; otherwise it contains at most 64 strictly ordered,
unique canonical names and lowercase hashes that exactly equal
`hns-covenants::hash_name` (SHA3-256 over the raw name bytes). Canonical names
are 1–63 lowercase ASCII letters or digits with `-` and `_` allowed only
internally, subject to the pinned reserved-name exclusions. The trusted window
renders every disclosed name/hash pair and rejects missing, malformed,
mismatched, duplicated, or reordered disclosures. Private `authorityHandle` and
`authorityRevision` fields remain native-only and are forbidden in page results
and event payloads. A future native adapter must decode ABI-v2 frames, retain
those fields behind the native boundary, and construct the exact public
projection; that adapter is not implemented or enabled in this release.

Only the validated public prompt is placed in `chrome.storage.session`; the
exact tab, document, authority generations, provider request, and native
approval dispatch context remain in service-worker memory. Approval, explicit
rejection, and approval-window closure all consume that exact stored context;
the extension never reconstructs authority from page-shaped or window-shaped
fields. A worker restart intentionally makes an in-flight approval stale rather
than persisting an authorization capability.

Allowlisted versioned service event frames are delivered back only to a
matching originating tab and `documentId`, after fresh authority validation
immediately before dispatch, then checked against the same generation binding
in the isolated bridge before reaching the page. Provider call results cannot
carry inline events; events are accepted only through the service event
channel.

## Native artifact and ABI boundary

The native host looks only at this versioned, installation-owned location:

```text
<native-host data>/wallet-abi-v2/manifest.json
<native-host data>/wallet-abi-v2/<artifact basename>
<native-host data>/wallet-abi-v2-admission-state.json
<native-host data>/wallet-abi-v2-admission.lock
```

The manifest is bounded to 16 KiB, denies unknown fields, and consumes the
wallet repository's exact signed-artifact schema v2. Its nested target declares
private wallet ABI 2, service protocol 2, website provider schema 1, approval
schema 3, the 1,048,576-byte frame maximum, current target triple and executable
format, and a closed unique service-capability set containing at least
`canonicalFraming`, `restartIsolation`, `opaqueAuthorityRegistry`,
`structuredApprovals`, and `typedEvents`. Additional schema-defined
capabilities do not enable product behavior; the exact qualified manifest pin
binds the complete list and runtime availability is negotiated separately.

The stored complete manifest must equal its RFC 8785 JCS encoding. This is an
intentional verifier invariant stricter than the wallet schema, which specifies
JCS for the signature-omitted payload. The verifier removes the signature
member, canonicalizes again, recomputes `signedPayloadSha256`, enforces
canonical base64url Ed25519 signature bytes, and verifies only a key selected
from verifier-owned key-ID/release-line roots. It accepts no public key from
the artifact.

On Unix, inspection opens the data directory, version directory, manifest, and
artifact with no-follow and close-on-exec semantics; children are opened
relative to retained directory handles. Metadata and size come from the opened
handles, the files must be current-user-owned single-link regular files,
group/other write bits are forbidden, and the artifact must be executable.
The bounded artifact digest is streamed from that same handle with surrounding
metadata checks. Launch-qualified manifest and artifact files additionally
have no owner write bit.

A trusted signature remains insufficient. A verifier-owned qualification entry
must exactly pin key ID, release line/sequence/ID, target triple, complete
manifest digest, and artifact digest, and a compiled per-line sequence floor
must admit the sequence. The stable parent data directory stores a bounded
canonical high-water record for each release line. Genesis must be explicitly
qualified; an upgrade is strictly increasing and its signed
`previousManifestSha256` must equal the accepted predecessor. The new state is
written to an exclusive temporary file, fsynced, made read-only, fsynced again,
atomically renamed, and followed by a parent-directory fsync. This
owner-maintained state detects restart/replacement rollback but never grants
trust; the compiled floor and exact pin remain authoritative.
The empty, private, single-link stable-parent lock file supplies the advisory
lock that covers the entire read/compare/write/verify transaction across
processes and remains held through launch and spawn.

Immediately before Linux process creation, the retained parent-to-version
directory, manifest, and artifact inode bindings, high-water record, and signed
publication/not-before/expiry window are rechecked. The time window is checked
again after path/state work. The artifact is rehashed while copied into a
sealed memfd, and only that sealed descriptor is executed with an empty
environment and piped standard I/O. The verifier has no `PATH`,
`dlopen`/plugin, or reopen-by-artifact-path fallback. macOS and Windows reject
launch pending reviewed platform equivalents.
The memfd seal covers only the main executable. A dynamically linked
interpreter/library closure and the local wall clock used for signed
not-before/expiry checks remain explicit production-qualification inputs.

## Lifecycle, upgrade, and removal

Inspection runs when the native host opens and is refreshed at the initial
hello and proxy start. Status distinguishes missing, rejected, integrity
checked, signature verified but unqualified, and launch admitted. Every state
still reports transport, runtime, engine authority, provider availability, and
value movement false. Status, diagnostics, and wallet-command rejection reuse
the bounded cached result instead of letting document probes repeatedly hash a
large artifact. A future service restart must rotate its wallet-session
generation; native-host disconnect, service-worker restart, browser authority
change, or permission generation change invalidates prior document and approval
state.

The version directory is staging for a service adapter only. Wallet databases,
seeds, encryption keys, backups, approval state, and other wallet-owned data
must never be stored under the browser installation's `data` directory. A
future independently released wallet installer must keep that state in its own
owned location, stage a signed versioned artifact transactionally (manifest
last), and explicitly migrate between ABI directories. It must leave an old or
partially upgraded contract unavailable rather than reinterpret it.

Complete Uninstall removes the browser installation root, including a staged
`wallet-abi-v2` manifest/artifact. It must not locate or delete the independent
wallet service's database, keys, backups, or other state. Repair and browser
upgrade likewise must not migrate or overwrite external wallet state.

## Current deployment boundary

The injection, hostile-frame validation, exhaustive typed approval-window,
service-event routing, strict native command parsing, and fail-closed artifact
discovery source exists. The standalone wallet repository also contains the
private ABI-v2 framed subprocess foundation and its 12 typed approval summaries.
The Chromium product is still not end-to-end wallet complete:

- no independently signed wallet service artifact has been qualified, so the
  production signer, exact-release, and release-floor tables remain empty;
- the Linux sealed-execution primitive is not joined to a released Chromium
  child-pipe transport, and macOS/Windows equivalents do not exist;
- no released browser-engine opaque-authority adapter is consumable by this
  native host;
- no reviewed native-to-public approval projection adapter is joined; and
- the checked-in wallet subprocess runtime advertises framing, restart,
  authority-registry, structured-approval, and typed-event foundations only.
  It does not advertise provider dispatch, browser integration, wallet
  operations, or value movement.

The native host therefore parses typed command envelopes only to return an
explicit unavailable error. With empty production trust and qualification
tables, artifact authenticity is false; service transport, runtime negotiation,
engine authority, overall provider availability, and value movement are also
false. The controller never invokes the admission-only launcher, never treats
caller-supplied authority fields as authentication, never exports secrets,
advertises `handshakeWalletProvider: false`, and injects no MAIN-world provider.
The DANE runtime continues to work independently.

## Focused verifier evidence

At exact source `a39f8759c0161b5e49cb93c0c5aea1f0298e3108`, the focused
offline `wallet_abi::tests` filter passed 17 tests with 0 failures and 24
filtered in the library target; the main target contained 0 tests. The first
invocation at `17d3efae6e0367e1f0ee2ef8cdafa67b5cdc20af` compiled
successfully, with 2 pure encoding passes and 15 shared
`walletArtifactDirectoryUnsafe` failures caused only by fixture directories
inheriting mode `0775`. Production was correct to reject them. Commit
`a39f8759` made the fixture root and ABI directory `0700`, and the cached
rerun passed.

This focused result does not cover the full repository gate, builds or
packages, installed browsers, platform launchers, transport, engine authority,
provider projection, or product qualification. Production roots, pins, and
floors remain empty and every provider/value gate remains false. The exact
command is recorded in
[milestones](milestones.md#current-qualification-evidence-and-remaining-release-work).

The static demonstration application is in `demo-dapp/`. It must be served from
an HTTPS logical origin approved by the browser trust layer; opening it as a
`file:` URL or from ordinary HTTP cannot enable the provider.
