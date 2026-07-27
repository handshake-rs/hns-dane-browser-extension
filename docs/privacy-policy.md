# Privacy Policy

Last updated: 2026-07-26

HNS DANE Browser Extension is published by Denuo Web, LLC. Privacy and
support questions can be sent to `info@denuoweb.com`. Do not post personal
information to the public issue tracker.

The HNS DANE Browser Extension does not operate a telemetry, analytics,
advertising, or browsing-history service. Denuo Web does not sell personal or
sensitive data. Donations are optional, do not unlock features, and do not
change how browsing data is handled.

## Local data

The extension and native host keep only data needed to provide the browser
feature, including:

- extension settings, the explicit P2P DNS-relay requester choice, the
  independently configured recursive HNS DoH URL, and the local timestamp of
  the last header-sync attempt used for retry limiting;
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
built-in validating Cloudflare DNS-over-HTTPS endpoint at
`cloudflare-dns.com`, bootstrapped through the documented `1.1.1.1` and
`1.0.0.1` address families without system DNS. Cloudflare can observe queried
hostnames and record types, request timing, protocol metadata, and the
caller's network address. Denuo Web does not operate Cloudflare's resolver or
control its logging and retention.

HNS names are not sent automatically to a public recursive HNS resolver. After
local header and proof validation, Rust tries direct delegated authority and
proof-anchored owner authoritative DoH first. If the user explicitly enables
the experimental P2P DNS-relay requester, a selected peer can observe the
relayed qname, qtype, timing, and source connection. Ordinary Handshake TCP
does not provide query confidentiality. The relay is not ODoH. Relayed answers
remain untrusted and are validated locally.

A separate recursive HNS DoH field is blank by default and no request is sent
to such an operator while it remains blank. If the user enters and applies a
URL, that operator can observe HNS qnames and qtypes, request timing, and the
user's source IP when the typed recovery path is selected. Historical
resolver values are not migrated. The configured hostname is bootstrapped
through built-in validating ICANN DoH rather than system DNS; the configured
operator's raw replies remain subject to local HNS DNSSEC/TLSA/DANE
validation, and its AD bit is not trusted.

The browser setting controls requester behavior only. This product advertises
no opaque relay or output-node/provider service.

Websites the user visits receive ordinary connection and request data needed
to serve the page, which can include the caller's network address, requested
URL, headers, cookies, and content the user submits. Denuo Web does not proxy
that traffic through a developer-operated browsing service.

## Retention and removal

Normal logs must omit full qnames, URLs, headers, bodies, raw DNS messages, and
stable browser identifiers. Temporary diagnostic state is bounded and cleared
on lifecycle or authority changes.

To attach a Rust security receipt to the correct active tab after
back/forward-cache, History API, or HTTP-cache navigation, the extension keeps
a bounded set of exact HTTP(S) URLs, Chromium document/tab identifiers, and
sanitized receipts in `chrome.storage.session`. This browser-managed state is
not sent to the native host or any network service, is scoped to the exact
runtime and policy generation, and is cleared when the browser session ends.
Header maintenance prevents those URL entries from authorizing a new cached
document.

For Chromium-owned ICANN WebPKI tunnels, session state may also retain the
native decision's exact host and port, runtime tuple, event number,
maintenance epoch, sanitized namespace/evidence fields, native observation
time, and Chromium-observed completion status and time. It does not add an
HTTP-status or main-frame claim to the Rust decision, and it stores no request
or response headers, bodies, certificate bytes, cookies, or URL fragments.

The supplied uninstaller removes the product's user-level native-host
registrations, exact per-install trust anchor, native executable, CA key
material, marker, chain/cache state, and runtime data. Browser-managed
extension storage is removed according to the browser's extension-removal
behavior.

Users can clear the configured recursive resolver, disable the P2P requester,
remove the extension, or run the complete uninstaller at any time. No
developer-operated account or server-side profile exists, so Denuo Web holds
no account record or synced browsing history to delete.

## Scope

This policy covers the Chromium extension and native host in this repository.
The mobile product has its own current source and disclosures in
[`handshake-rs/hns-dane-browser-mobile`](https://github.com/handshake-rs/hns-dane-browser-mobile).
