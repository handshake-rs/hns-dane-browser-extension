# Version Audit

Audit date: 2026-07-29

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
| Canonical browser contracts | `handshake-rs/hns-dane-engine` at `7f7bb8fa100c2393f2cd5a64c64bf5e20a0f3ab5` |
| rustls | `0.23.41` |
| webpki-roots | `1.0.8` |
| rcgen | `0.14.8` |
| quinn | `0.11.11` |
| h3 | `0.0.8` |
| h3-quinn | `0.0.10` |
| rusqlite | `0.39` |
| p256 | `0.13` |
| ring | `0.17.14` |

The canonical Git source is limited to these five packages:

- `hns-browser-runtime`;
- `hns-browser-observability`;
- `hns-icann-dane`;
- `hns-namespace-resolution`; and
- `hns-resolution-policy`.

All five resolve to the exact revision shown above. The committed Cargo lock,
source-policy verifier, notice generator, cargo-deny policy, and CI gates must
change together for an intentional engine upgrade.

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
- HNSR and P2P ODoH are not versioned features of this product; they are
  unimplemented.
- The bundled IANA snapshot has no authority version. It may be refreshed as a
  hint without changing the requirement to resolve the full hostname through
  both roots.
