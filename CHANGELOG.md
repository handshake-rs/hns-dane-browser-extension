# Current application source

## 1.0.0 - Current source

- Shakescape V1 provides the browser identity. Runtime engine dependencies use
  exact published crate versions; Denuo Web provides publisher, package,
  domain, and signing identity.
- The authenticated Handshake name-tree root remains current while background
  peer evidence refreshes. `Syncing` denotes catch-up needed to reach a newer
  tree-root epoch.
- Unsupported Handshake networks are rejected before header-status envelopes
  can be displayed as authoritative or activate the proxy.

Qualify and publish the exact candidate through the
[release procedure](docs/release.md).
