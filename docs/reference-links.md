# Reference Links

These are implementation references, not evidence that an unqualified feature
or release gate has passed.

## Canonical Handshake Rust ecosystem

- Browser extension:
  https://github.com/handshake-rs/hns-dane-browser-extension
- Mobile browser:
  https://github.com/handshake-rs/hns-dane-browser-mobile
- Canonical DANE/browser contracts:
  https://github.com/handshake-rs/hns-dane-engine
- Engine source used here:
  exact Git revision recorded in `rust/Cargo.toml`
- HRM/HNSA drafts used for the dormant profile boundary:
  `references/HIPs/HIP-xxxx-HRM.md` and
  `references/HIPs/HIP-xxxx-HNSA.md` in the ecosystem workspace
- Canonical HRM/HNSA Rust publication:
  not yet consumed; the local opaque adapter remains unavailable until exact
  released types and vectors are reviewed
- MeshMine public pool-statistics profile:
  https://github.com/handshake-rs/MeshMine/blob/main/specs/pool-stats-profile.md
- Handshake full node:
  https://github.com/handshake-org/hsd
- Handshake documentation:
  https://hsd-dev.org/

## DNS and DNSSEC

- DNS concepts and facilities, RFC 1034:
  https://www.rfc-editor.org/rfc/rfc1034
- DNS implementation and specification, RFC 1035:
  https://www.rfc-editor.org/rfc/rfc1035
- DNSSEC introduction and requirements, RFC 4033:
  https://www.rfc-editor.org/rfc/rfc4033
- DNSSEC resource records, RFC 4034:
  https://www.rfc-editor.org/rfc/rfc4034
- DNSSEC protocol modifications, RFC 4035:
  https://www.rfc-editor.org/rfc/rfc4035
- NSEC3, RFC 5155:
  https://www.rfc-editor.org/rfc/rfc5155
- DNS over HTTPS, RFC 8484:
  https://www.rfc-editor.org/rfc/rfc8484
- Service binding and HTTPS records, RFC 9460:
  https://www.rfc-editor.org/rfc/rfc9460
- DNS server SVCB discovery, RFC 9461:
  https://www.rfc-editor.org/rfc/rfc9461
- IANA root-zone database:
  https://www.iana.org/domains/root/db

The IANA database is useful input and may seed a performance hint. It is not
the authoritative namespace classifier in this browser; full-host HNS and
ICANN resolution is.

## DANE and TLS

- DANE/TLSA, RFC 6698:
  https://www.rfc-editor.org/rfc/rfc6698
- DANE operational guidance, RFC 7671:
  https://www.rfc-editor.org/rfc/rfc7671
- DANE for raw public keys, RFC 7672:
  https://www.rfc-editor.org/rfc/rfc7672
- TLS 1.3, RFC 8446:
  https://www.rfc-editor.org/rfc/rfc8446
- HTTP Alternative Services, RFC 7838:
  https://www.rfc-editor.org/rfc/rfc7838

## Chromium extension and native messaging

- Manifest V3:
  https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3
- Native messaging:
  https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
- Proxy API:
  https://developer.chrome.com/docs/extensions/reference/api/proxy
- Edge native messaging:
  https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging
- Opera extension messaging:
  https://help.opera.com/en/extensions/message-passing/
- WebSocket protocol, RFC 6455:
  https://www.rfc-editor.org/rfc/rfc6455
- HTTP/2, RFC 9113:
  https://www.rfc-editor.org/rfc/rfc9113
- HTTP/3, RFC 9114:
  https://www.rfc-editor.org/rfc/rfc9114

## Privacy experiments

- Oblivious DoH, RFC 9230:
  https://www.rfc-editor.org/rfc/rfc9230

The private HNS DNS-relay transport described in this repository is not ODoH.
HNSR and P2P ODoH are not implemented by the Chromium native host.
