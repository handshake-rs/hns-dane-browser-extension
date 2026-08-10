# Version Audit

Audit date: 2026-08-09

This table records configured versions for the Chromium extension, native
host, and Setup build. It does not claim that each entry is the newest
upstream release.

| Component | Configured version/source |
| --- | --- |
| Extension package | `0.5.5` |
| Rust workspace | `0.5.5` |
| HNS DANE Browser Setup | `0.5.5` |
| Rust toolchain | `1.92.0` |
| Node.js | `>=22` |
| eframe | `0.35.0` |
| Consolidated engine adapters | Git `b8bdfbf7e234e64166886ade6f79d698e23056af`, version `0.2.0` |
| Canonical compatibility patches | Git `1ab4ab626f945712b0f960945986cb52efef7c`, version `0.1.0` |
| rustls | `0.23.41` |
| webpki-roots | `1.0.8` |
| rcgen | `0.14.8` |
| quinn | `0.11.11` |
| h3 | `0.0.8` |
| h3-quinn | `0.0.10` |
| rusqlite | `0.39` |
| p256 | `0.13` |
| ring | `0.17.14` |

Published `v0.5.5` used the five checksum-verified crates.io `0.1.0` packages
below. Current unreleased source patches those packages from exact engine Git
revision `1ab4ab626f945712b0f960945986cb52efefef7c` and consumes the consolidated
private adapters at `b8bdfbf7e234e64166886ade6f79d698e23056af`:

- `hns-browser-runtime`;
- `hns-browser-observability`;
- `hns-icann-dane`;
- `hns-namespace-resolution`; and
- `hns-resolution-policy`.

The committed Cargo lock, source-policy verifier, notice generator, cargo-deny
policy, and CI gates must change together for an intentional engine upgrade.
Current source head `08ba480fcbae4144a329c90e478ccae4bcab5000` passed CI and CodeQL but is
unreleased. It predates the engine's HNSA admission at `3c12ace`; HNSA/HNSR
product claims remain unavailable until one final engine revision is adopted
and installed-browser qualification passes.

## Moving-source review

Run:

```sh
./scripts/audit-versions.sh
```

The report is advisory: it identifies upstream Rust, Cargo, Node, browser, and
dependency movement for review. It must not rewrite manifests or lockfiles.
Security-sensitive upgrades require release-note review, lock and notice
regeneration, the complete portable gate, and target-browser qualification.

## Compatibility notes

- `rustls` uses the stable 0.23 line and the `ring` provider in this workspace.
- DANE and DNSSEC algorithms not explicitly supported remain fail-closed.
- HNSR, HNSA, and P2P ODoH are not versioned features of the current product.
  Engine source exists for HNSR requester/HNSA admission, but this extension
  has not adopted or qualified it.
- The bundled IANA snapshot has no authority version. It may be refreshed as a
  hint without changing the requirement to resolve the full hostname through
  both roots.
