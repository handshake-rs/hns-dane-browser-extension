# Current application source

## 1.0.1 - 2026-10-24

- Refresh the browser engine and protocol crates to the published patched
  cryptography stack, including `k256` 0.14 and `crypto-bigint` 0.7.7.
- Update the Setup GUI to `eframe` 0.37. Its Unix accessibility adapter still
  resolves retired D-Bus packages, so Setup screen-reader integration is
  disabled on this release line while the extension and native host retain
  their existing interfaces.
- Refresh the release lockfiles, supply-chain notices, and browser qualification
  inputs for the exact published dependency cohort.

## 1.0.0

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
