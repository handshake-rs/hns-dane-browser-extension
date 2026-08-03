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
   contract. The website-facing provider schema remains version 1; it is not
   the private host/service ABI version.
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
```

The manifest is bounded to 16 KiB, denies unknown fields, and must declare
manifest schema 1, private wallet ABI 2, service protocol 2, website provider
schema 1, a 1,048,576-byte maximum frame, a bounded release ID and artifact
basename, a lowercase SHA-256 digest, and exactly these ABI-v2 foundation
capabilities with no duplicates: `canonical_framing`, `restart_isolation`,
`opaque_authority_registry`, `structured_approvals`, and `typed_events`.
Compiled method vocabulary is never treated as negotiated availability.

On Unix, discovery opens the data directory, version directory, manifest, and
artifact with no-follow and close-on-exec semantics; children are opened
relative to retained directory handles. Metadata and size come from the opened
handles, the files must be owned by the current user, regular files must have
one link, group/other write bits are forbidden, and the artifact must be
executable. The artifact digest is streamed from that same bounded handle and
metadata is rechecked afterward. Basenames reject separators and Windows
alternate-stream/path-ambiguous `:` and `+` characters. Platforms without a
reviewed ownership/ACL implementation, currently Windows, reject discovery.
There is no `PATH`, environment-variable, sibling-Cargo-dependency, dynamic
library, or `dlopen` fallback.

A matching digest proves only local integrity against the manifest; it is not
release authenticity because no signing key is pinned. The artifact is an
owner-writable discovery snapshot and is never executed today. Any future
launcher must first verify a signed release and then execute the retained
checked descriptor, or repeat all checks immediately before execution; it must
never verify one path and reopen it later.

## Lifecycle, upgrade, and removal

Discovery runs when the native host opens and is refreshed at the initial
hello and proxy start. Status, diagnostics, and wallet-command rejection reuse
the bounded cached result instead of letting document probes repeatedly hash a
large artifact. Staging changes therefore require a native-host restart (or a
new start lifecycle) before discovery changes. Missing, rejected, incompatible,
or locally integrity-checked artifacts all report `available: false` with a
specific safe reason. A future service restart must rotate its wallet-session
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

- no independently signed wallet service artifact, pinned signer, private
  Chromium child-pipe launcher, or released transport join exists;
- no released browser-engine opaque-authority adapter is consumable by this
  native host; and
- the checked-in wallet subprocess runtime advertises framing, restart,
  authority-registry, structured-approval, and typed-event foundations only.
  It does not advertise provider dispatch, browser integration, wallet
  operations, or value movement.

The native host therefore parses the typed command envelopes only to return an
explicit unavailable error. Artifact authenticity, service transport, runtime
negotiation, engine authority, overall provider availability, and value
movement all remain false. It never treats caller-supplied authority or
permission fields as authentication, never launches or executes the staged
artifact, never exports secrets, advertises `handshakeWalletProvider: false`,
and injects no MAIN-world provider. The DANE runtime continues to work
independently.

The static demonstration application is in `demo-dapp/`. It must be served from
an HTTPS logical origin approved by the browser trust layer; opening it as a
`file:` URL or from ordinary HTTP cannot enable the provider.
