# Privacy Policy

Last updated: 2026-07-26

The HNS DANE Browser Extension does not operate a telemetry, analytics,
advertising, or browsing-history service.

## Local data

The extension and native host keep only data needed to provide the browser
feature, including:

- extension settings and the explicit P2P DNS-relay requester choice;
- native-host registration and installation markers;
- a per-install local CA key and certificate;
- Handshake headers, peer state, verified proof/resource cache, namespace
  bindings, and bounded resolver state;
- current proxy/runtime generations and credentials; and
- a bounded in-memory security-result window for the popup and diagnostics.

The raw internal resolution trace is not sent through native messaging because
it can contain URLs or certificate material. Browser-visible responses do not
receive private `X-HNS-*` metadata. Checked status contains bounded protocol
state and intermediaries, not page bodies.

## Network disclosure

Ordinary DNS HTTP(S)/WS(S) hosts are resolved independently through HNS and
ICANN by the Rust native host. ICANN resolution and TLSA discovery use the
configured validating ICANN DoH service. That resolver can observe queried
ICANN names and the caller's network address.

HNS names are not sent to a public recursive HNS resolver. After local header
and proof validation, direct delegated authority is preferred. If the user
explicitly enables the experimental P2P DNS-relay requester, a selected peer
can observe the relayed qname, qtype, timing, and source connection. Ordinary
Handshake TCP does not provide query confidentiality. The relay is not ODoH.
Relayed answers remain untrusted and are validated locally.

The browser setting controls requester behavior only. This product advertises
no opaque relay or output-node/provider service.

## Retention and removal

Normal logs must omit full qnames, URLs, headers, bodies, raw DNS messages, and
stable browser identifiers. Temporary diagnostic state is bounded and cleared
on lifecycle or authority changes.

The supplied uninstaller removes the product's user-level native-host
registrations, exact per-install trust anchor, native executable, CA key
material, marker, chain/cache state, and runtime data. Browser-managed
extension storage is removed according to the browser's extension-removal
behavior.

## Scope

This policy covers the Chromium extension and native host in this repository.
The mobile product has its own current source and disclosures in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).
