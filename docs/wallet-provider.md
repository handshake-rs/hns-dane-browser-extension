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
4. The native host must advertise wallet ABI v1. Until it does, no MAIN-world
   provider is installed and discovery finds nothing.
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

## Current deployment boundary

The injection, hostile-frame validation, approval-window, and event-routing
source exists and has focused tests, but the Chromium product is not end-to-end
wallet complete. The current Rust native host does not yet dispatch the three
wallet-provider commands or adapt the standalone wallet ABI. It therefore
reports `walletUnavailable`, and no MAIN-world provider is injected. Wallet
application UI, notifications, database migration/backup/removal, and live
settlement demonstrations remain unimplemented. The DANE runtime continues to
work independently.

The static demonstration application is in `demo-dapp/`. It must be served from
an HTTPS logical origin approved by the browser trust layer; opening it as a
`file:` URL or from ordinary HTTP cannot enable the provider.
