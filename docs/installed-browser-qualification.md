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

## Current `0.5.6` exact-artifact evidence (partial)

Exact source `5a7683e70162220c8bfbdae9e8a7d4c3c37acf02` passed
[CI run 31404782077](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31404782077)
and
[CodeQL run 31404781059](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31404781059).
The CI artifact used for the isolated Debian 13 arm64 / Chromium
`149.0.7827.196` run had these exact SHA-256 identities:

- provenance: `bc73451efe1c9490d2da171683b0ea3c734da78a749defbd211edd3a15fd6bdd`;
- raw native host: `096be59083d014e821433a18dc8a206ee5e5491bec85e9771f7937e5650b4e65`;
- native-host archive: `454be5151e0bb9e880018d413321e245bd149c9ce4f7af012db81c98ee561d53`;
- canonical extension ZIP: `5e81b3f5e2df4d8090784714b7c7f30335d453aadde5a26d5a62f26d3dae8567`;
  and
- extension manifest: `4329a0cfde5d24b10c1f0723589a342b70e4fc1eeeea74c6c43e0a8606c5b171`.

The loaded package and registered native host were byte-identical to those
inputs under canonical ID `idejjnoplngbhpnpjekblpalblbianio`. Current
corroborated headers, proxy/CA activation, ordinary ICANN WebPKI passthrough,
native-host restart/reconnect with a fresh runtime session, and the required
false HNSA/HNSR/relay/ODoH/wallet/provider/value/settlement/market diagnostics
passed. Clean uninstall removed the isolated registration, runtime, CA, and
profile without touching the normal Chromium profile.

Two `https://welcome/` attempts failed closed with a local 502 because the
synthetic routing hostname's sole delegated authority was unreachable from the
qualification network and did not supply the DS/DNSSEC/TLSA evidence required
for HNS HTTPS. This is not evidence of a proxy regression, but it is also not a
positive HNS/DANE navigation. The positive-origin gate remains open and must be
rerun with a preflighted known-good origin.

The later documentation-only main commit
`d091bcf3ecd72ed36acdf17ce54dad80c3003bd0` passed
[CI run 31409759063](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31409759063)
and
[CodeQL run 31409753614](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31409753614).
If that commit is selected as the release tag, its exact SHA-keyed artifact
still needs the installed-profile observations above plus the positive
known-good HNS/DANE navigation; evidence from `5a7683e` is not silently
relabelled as evidence for a later commit.

## Historical mixed-version evidence

On 2026-08-10, source
`ae702ebdea59050dd9395636f549ff9c2b8f2e4b` passed
[CI run 31394858244](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31394858244)
and
[CodeQL run 31394857474](https://github.com/handshake-rs/hns-dane-browser-extension/actions/runs/31394857474).
That source pinned the consolidated engine at
`d57eb672030ebbcd0ccd44780720e0efc73a4e87`.
Its linted/built JavaScript was loaded unpacked into Chromium
`149.0.7827.196` on Debian 13 using a disposable profile. The loaded manifest
was byte-identical to the build; `src/service-worker.js` was
`7c7088942a69bdba1503ce59c5a218ce9f129031336e958150cbf5cb7effe2b3`
and `src/hns-name-hash.js` was
`1b9c61622df13f5e6c197b7d0a1999846f4e4d7c46abd0c688d70c2f38fcf8dc`.

The existing native host connected, activated its CA/proxy, and reported a
current corroborated mainnet header state with 12 peer groups. `example.com`
loaded through `browserWebPkiPassthrough` as ICANN-only with ICANN DoH/DNSSEC
verified. DNS relay, HNSR endpoint/relay, market gossip, ODoH, and P2P relay
were disabled/fail-closed; options remained blank/false/off. There was no
wallet marker or provider announcement. HNSA had no endpoint or verification
and remained display-only. Native wallet artifact, authenticity,
qualification, launch, transport, negotiation, provider authority, and
availability diagnostics were all false.

That was intentionally mixed-version evidence. The installed host digest was
`537b0b9e8b78add058e44971b37fe9f0c4344db307549405e427a356406c89a5`;
it had been built on 2026-08-09 from older engine checkouts `b8bdfbf` and
`1ab4ab6` and reported approval schema 2 while `ae702eb` JavaScript required
schema 3. It therefore proves the exact browser code stayed fail-closed when
paired with an incompatible old host, not that the `ae702eb` native source or
any later release candidate passed installed-browser qualification. The
temporary profile and registration were removed and the normal profile was
not changed.

The current `0.5.6` candidate repins the engine to
`2b23bd55d14d36fe60073606869d75b4796c54f7`; its newer exact-artifact evidence
and remaining positive-origin gate are recorded above.
