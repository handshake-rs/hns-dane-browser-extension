# Handshake wallet provider (ABI v1)

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
   provider-authority context and negotiate the exact wallet ABI v1 contract.
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
and pending approvals stale. Approval revalidation obtains fresh browser and
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
allowlisted request to `walletProviderRequest` under ABI v1. The only other
wallet-native commands are the capability probe and an approval decision.
The bridge never automatically retries a request after a stale-context,
permission-generation, or wallet-session result: a mutating call may already
have executed. It returns that error and requires a new explicit page request.
Reads use the same replay and idempotency binding.

## Approval and event ownership

The native wallet may return a versioned `approvalRequired` descriptor. The
extension validates its exact origin, expiry, method, kind, and method-specific
public summary. Only that public prompt is placed in `chrome.storage.session`;
the full tab/document/generation context remains in service-worker memory. The
window requires canonical base-unit amounts and all applicable recipient, fee,
chain, confirmation-policy, price-round, and refund-timeout fields. The
original provider request remains pending. Approval is consumed once, all
authority generations are revalidated, and the terminal native result resolves
or rejects the original request. A worker restart intentionally makes an
in-flight approval stale rather than persisting an authorization capability.

Allowlisted response events and versioned unsolicited native events are
delivered back only to a matching originating tab and `documentId`, after fresh
authority validation, then checked against the same generation binding in the
isolated bridge before reaching the page.

## Native artifact and ABI boundary

The native host looks only at this versioned, installation-owned location:

```text
<native-host data>/wallet-abi-v1/manifest.json
<native-host data>/wallet-abi-v1/<artifact basename>
```

The manifest is bounded to 16 KiB, denies unknown fields, and must declare
manifest schema 1, wallet ABI 1, service protocol 1, provider schema 1, a
1,048,576-byte maximum frame, a bounded release ID and artifact basename, a
lowercase SHA-256 digest, and exactly these capabilities with no duplicates:
`approval_decision`, `canonical_framed_json`, `provider_request`,
`restart_generation`, and `secret_minimizing_chromium`.

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
`wallet-abi-v1` manifest/artifact. It must not locate or delete the independent
wallet service's database, keys, backups, or other state. Repair and browser
upgrade likewise must not migrate or overwrite external wallet state.

## Current deployment boundary

The injection, hostile-frame validation, approval-window, event-routing, strict
native command parsing, and fail-closed artifact discovery source exists. The
Chromium product is still not end-to-end wallet complete:

- `hns-wallet-ffi` is a bounded Rust JSON-frame library/trait, not a service
  executable, C ABI, or dynamic library;
- no independently signed wallet service artifact or canonical process
  transport has been released;
- the pinned browser engine does not expose an opaque provider-authority
  context consumable by this native host; and
- the standalone wallet's generic approval summary has no reviewed mapping to
  the extension's method-specific public approval descriptor.

The native host therefore parses the three typed command envelopes only to
return an explicit unavailable error. It never treats caller-supplied authority
or permission fields as authentication, never launches the staged artifact,
never exports secrets, advertises `handshakeWalletProvider: false`, and no
MAIN-world provider is injected. Wallet application UI, notifications,
database migration/backup, and live settlement demonstrations remain
unimplemented. The DANE runtime continues to work independently.

The static demonstration application is in `demo-dapp/`. It must be served from
an HTTPS logical origin approved by the browser trust layer; opening it as a
`file:` URL or from ordinary HTTP cannot enable the provider.
