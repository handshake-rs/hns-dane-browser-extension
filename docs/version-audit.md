# Version Audit

Audit date: 2026-08-20

This table records configured versions for the Chromium extension, native
host, and Setup build. It does not claim that each entry is the newest
upstream release.

| Component | Configured version/source |
| --- | --- |
| Extension package | `1.0.0` |
| Rust workspace | `1.0.0` |
| Shakescape Setup | `1.0.0` |
| Rust toolchain | `1.92.0` |
| Node.js | `>=22` |
| eframe | `0.35.0` |
| Consolidated engine source | Git `69e60d7bfce368d7d23c6c901946f02b173f00c4`, version `0.2.1` |
| MeshMine HNSA profile core | Dormant schema 2 over canonical engine guard; no Chromium platform backend |
| rustls | `0.23.41` |
| webpki-roots | `1.0.8` |
| rcgen | `0.14.8` |
| quinn | `0.11.11` |
| h3 | `0.0.8` |
| h3-quinn | `0.0.10` |
| rusqlite | `0.39` |
| p256 | `0.13` |
| k256 | `0.13` |
| ring | `0.17.14` |
| webbrowser | `1.2.2` |

Published `v0.5.5` used the five checksum-verified crates.io `0.1.0` packages
below. The `1.0.0` candidate consumes their `0.2.1` successors and the private
adapters from the one exact, final dated engine Git revision shown above:

- `hns-browser-runtime`;
- `hns-browser-observability`;
- `hns-icann-dane`;
- `hns-namespace-resolution`; and
- `hns-resolution-policy`.

The committed Cargo lock, source-policy verifier, notice generator, cargo-deny
policy, and CI gates must change together for an intentional engine upgrade.
The MeshMine profile core consumes the canonical engine's current HRM/HNSA
guard, but its mapped authority remains deliberately unconstructible by product
callers. The product has no Chromium backend supplying complete current HNS/HRM
retrieval, authenticated aggregate CAS and external floor, real fenced lease,
native request/UI join, or exact-artifact installed-browser qualification.
Verified HNSA feed display therefore remains unavailable. HNSR transport,
discovery, and persistence remain explicitly disabled.

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
  Their engine source is present, but this extension has not joined or
  qualified those lifecycles and explicitly disables every HNSR role.
- The bundled IANA snapshot has no authority version. It may be refreshed as a
  hint without changing the requirement to resolve the full hostname through
  both roots.
