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

The `0.5.6` candidate repins the engine to
`2b23bd55d14d36fe60073606869d75b4796c54f7`. It still requires a new run of
the isolated-profile gate using the exact SHA-keyed CI artifact from the final
candidate commit.
