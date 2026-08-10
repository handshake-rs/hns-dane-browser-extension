# Version Audit

Audit date: 2026-08-10

This table records configured versions for the Chromium extension, native
host, and Setup build. It does not claim that each entry is the newest
upstream release.

| Component | Configured version/source |
| --- | --- |
| Extension package | `0.5.6` |
| Rust workspace | `0.5.6` |
| HNS DANE Browser Setup | `0.5.6` |
| Rust toolchain | `1.92.0` |
| Node.js | `>=22` |
| eframe | `0.35.0` |
| Consolidated engine source | Git `2b23bd55d14d36fe60073606869d75b4796c54f7`, version `0.2.0` |
| HNSA authority source | `hns-rs` Git `b24b66c382de53330ec21dd3137e056a2bea3e2d`, version `0.2.0` |
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

Published `v0.5.5` used the five checksum-verified crates.io `0.1.0` packages
below. The `0.5.6` candidate consumes their `0.2.0` successors and the private
adapters from the one exact, final dated engine Git revision shown above:

- `hns-browser-runtime`;
- `hns-browser-observability`;
- `hns-icann-dane`;
- `hns-namespace-resolution`; and
- `hns-resolution-policy`.

The committed Cargo lock, source-policy verifier, notice generator, cargo-deny
policy, and CI gates must change together for an intentional engine or HNSA
authority upgrade. The native MeshMine verifier core is source-complete for
the private read-only profile, but the product has no compatible Chromium
`VerifiedHnsResource` adapter, authenticated rollback-resistant store, native
request/UI join, or exact-artifact installed-browser qualification. Verified
HNSA feed display therefore remains unavailable. HNSR transport, discovery,
and persistence remain explicitly disabled. Version alignment and exact Git
pins prepare a candidate; they do not publish it or satisfy those product
gates.

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
