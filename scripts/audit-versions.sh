#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
Review these moving version sources before dependency upgrades:
- Chrome extensions platform: https://developer.chrome.com/docs/extensions
- Chrome release notes: https://developer.chrome.com/release-notes
- Node.js release schedule: https://github.com/nodejs/Release
- Rust releases: https://releases.rs/
- cargo-deny: https://github.com/EmbarkStudios/cargo-deny/releases
- rustls: https://crates.io/crates/rustls
- ring: https://crates.io/crates/ring
- webpki-roots: https://crates.io/crates/webpki-roots
- rcgen: https://crates.io/crates/rcgen
- quinn: https://crates.io/crates/quinn
- h3: https://crates.io/crates/h3
- hickory-proto: https://crates.io/crates/hickory-proto
EOF
