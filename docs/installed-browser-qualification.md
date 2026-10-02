# Installed-browser qualification

Portable tests prove source and package invariants; they do not prove that the
same native host works through Chromium native messaging, owns the active
proxy/CA lifecycle, or enforces the expected product gates. Every release
candidate therefore needs an installed-browser run using the exact native and
JavaScript artifacts built from that candidate commit.

## Exact-SHA CI inputs

Required CI builds a static Linux arm64 native host and the canonical-ID
unpacked extension package on a hosted arm64 runner. The read-only job receives
no repository secrets or signing credentials and uploads:

- `hns-chromium-native-host`, the exact raw executable;
- its deterministic `linux-arm64` native-host archive and checksum sidecar;
- the canonical-ID `-mv3.zip` and checksum sidecar; and
- `QUALIFICATION-PROVENANCE.json`.

The artifact name is
`installed-browser-qualification-<40-character-commit>-linux-arm64` and it is
retained for 14 days. Provenance records the source repository and commit,
runner/platform/Rust target, and every file's name, size, role, and SHA-256.
The archives use candidate metadata with commit-scoped source and license links;
they contain no release-tag or release-URL claim. Tagged release packaging
remains a separate, tag-required mode. The upload rejects anything beyond the
six expected top-level regular files, including nested directories.
Generation rejects symlinks, archive links, unsafe paths, encrypted ZIP
entries, secret-bearing filenames, PEM private-key material, bad sidecars,
source/target mismatches, and a native archive that does not contain the exact
raw executable. The extension identity embedded in the canonical package is a
committed public key; no extension private key exists in the artifact.

The provenance deliberately records these product capabilities as false:

- HNSA admission;
- HNSR requester and provider roles;
- wallet provider;
- value movement; and
- P2P marketplace.

It also records `pendingInstalledBrowserRun`. Building or downloading this
bundle is not qualification and does not enable any capability.

After exact-current-main Required CI succeeds, download only the matching
artifact:

```sh
commit=<exact 40-character main commit>
run_id=<successful CI run for that exact commit>
gh run download "$run_id" \
  --repo handshake-rs/hns-dane-browser-extension \
  --name "installed-browser-qualification-$commit-linux-arm64" \
  --dir "qualification-$commit"
jq -e --arg commit "$commit" \
  '.schemaVersion == 1 and
   .source.commit == $commit and
   .platform.operatingSystem == "linux" and
   .platform.architecture == "arm64" and
   .platform.rustTarget == "aarch64-unknown-linux-musl" and
   .qualification.status == "pendingInstalledBrowserRun" and
   (.securityBoundary | all(.[]; . == false))' \
  "qualification-$commit/QUALIFICATION-PROVENANCE.json"
```

Recompute each listed SHA-256 before extraction. Prefer the native archive for
installation because it retains executable modes; if the raw executable is
used, restore only its execute bit after verifying its digest.

## Isolated-profile gate

Never replace an operator's normal Chromium profile or native-host
registration during candidate qualification. Use a disposable directory for
`HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, the Chromium `--user-data-dir`,
native registration, runtime data, and the generated local CA. Start Chromium
without sync or a pre-existing profile, load the extracted canonical extension
through **Load unpacked**, and register only its exact canonical ID against the
artifact's exact host. The local CA private key is generated inside that
disposable runtime during installation; it is not shipped in the CI bundle.

`welcome`, as used by PAC and routing tests, is a synthetic hostname. It proves
that an ordinary DNS name is routed to Rust; it is not a guaranteed live
HNS/DANE origin and must not be used as release evidence without the same
preflight as any other candidate origin.

Before counting an HNS/DANE navigation, preflight and record that the origin
has:

- a current authenticated HNS name proof under the candidate's current header
  state;
- either redundant reachable authoritative DNS or proof-anchored
  authoritative DoH on HTTPS 443;
- a valid DS-anchored DNSSEC chain for delegated answers;
- a secure `_443._tcp.<host>` TLSA RRset for the tested HTTPS service; and
- an HTTPS certificate matching that TLSA policy and hostname.

Record at least:

1. the commit, CI run, artifact name, provenance digest, raw host digest,
   extension manifest digest, Chromium version, OS, and architecture;
2. byte identity between the loaded extension and the extracted canonical ZIP;
3. native connection, CA/proxy activation, restart/reconnect, and clean
   teardown;
4. an ordinary ICANN WebPKI passthrough navigation with its namespace,
   DNSSEC/DoH, routing, and browser-owned TLS evidence;
5. one current HNS/DANE navigation when an authenticated current header state
   and suitable test origin are available; and
6. negative diagnostics proving HNSA admission, every HNSR role, relay/market
   gossip, ODoH, wallet artifact/authenticity/qualification/launch, private
   wallet transport, runtime negotiation, provider authority/availability,
   value movement, settlement, and P2P marketplace controls remain absent or
   false.

The run must fail if the native host reports an older schema or release, if a
different binary answers native messaging, if the extension or host hash
differs, if direct/system routing is exposed while Rust is unavailable, or if
any disabled capability becomes available. Remove the disposable profile,
registration, CA, runtime data, and extracted artifacts afterward; retain only
non-secret hashes and observations in release evidence.
