# Store Purpose and Permission Justifications

## Single purpose

Provide fail-closed Handshake/ICANN dual-root resolution and locally verified
DNSSEC/TLSA/DANE policy for web navigation through a Rust native host, while
showing the selected namespace and security evidence to the user.

## Remote code

`No.` The Manifest V3 extension executes only JavaScript packaged in the
uploaded ZIP. It does not download or evaluate remote scripts, WebAssembly, or
configuration as code. Network DNS and web responses are data processed by
the native Rust host, not executable extension code.

## Permissions

- `alarms`: run a five-minute health safety check, schedule one-shot header
  refresh before authenticated peer-target evidence expires, and bound
  reconnect retries. It is not used for tracking.
- `nativeMessaging`: communicate with the installed Rust resolver, proxy, CA,
  policy, and diagnostics host. JavaScript does not implement the trust path.
- `proxy`: install the mandatory, Rust-generated PAC that routes ordinary web
  DNS hostnames to the authenticated loopback proxy. Fail-closed lifecycle
  transitions replace it with a confirmed fixed blocking PAC; startup,
  failure, and retry paths never clear proxy control to system or direct
  routing.
- `scripting`: inject the packaged wallet-provider bootstrap into the exact
  HTTPS main-frame document only after the native host returns a current,
  generation-bound browser-authority decision and wallet ABI capability. No
  remote or page-supplied code is executed, and unavailable authority or ABI
  leaves the provider absent.
- `storage`: retain user settings locally and keep bounded session-only
  navigation/security receipts needed to bind native results to the exact
  active document.
- `webNavigation`: bind redirects, commits, History API changes, BFCache
  restores, and errors to the corresponding Rust security receipt.
- `webRequest`: observe bounded request lifecycle metadata so main-frame,
  cache, redirect, and tunnel decisions cannot be attached to the wrong tab or
  document. The extension does not read or modify page bodies.
- `webRequestAuthProvider`: answer authentication challenges only for the
  current `127.0.0.1` proxy generation with ephemeral credentials supplied by
  Rust.
- `<all_urls>` host permission: every ordinary DNS web hostname, redirect,
  subresource, download, Service Worker request, and WebSocket must be covered
  by the same dual-root decision. A hostname allowlist would permit security
  bypasses. There are no content scripts.

## Local CA

The native installer creates one per-user P-256 CA. Rust uses it only when
terminating TLS is required to enforce HNS or ICANN DANE. On authenticated
ICANN WebPKI fallback, Rust tunnels TLS unchanged so the browser validates and
displays the origin's real certificate. The complete uninstaller removes the
exact installed CA.
