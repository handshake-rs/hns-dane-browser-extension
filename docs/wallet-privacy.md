# Wallet provider privacy boundary

The website receives no wallet data merely because the provider is present.
Accounts, balances, transactions, names, modules, market activity, and swap
state require their corresponding origin-scoped native permission. Permission
revocation advances the permission generation and invalidates old bindings.

The Chromium extension does not store or transport recovery phrases, seed
bytes, private keys, passphrases, database encryption keys, HTLC preimages, or
native wallet capability secrets. Those values must never appear in provider
frames, logs, `window`, DOM nodes, `localStorage`, `sessionStorage`, extension
storage, approval URLs, or native-messaging diagnostics.

The isolated bridge retains only a bounded public authority binding in memory.
Approval storage contains one short-lived public review descriptor from the
private-ABI-v2/public-approval-v3 closed union: permissions, module enablement,
send, name transfer, name finalize, typed signature, name offer, name purchase,
market intent, fill acceptance, swap redeem, or swap refund. Its exact origin,
method, expiry, nested asset and base-unit amounts, recipient, maximum fee and
fee asset, chain/finality, price round, refund timing, warnings, and identifiers
are typed per variant. A permission descriptor also carries the explicit
minimized `hnsNames` list; every disclosed canonical name and SHA3-256 hash is
rendered for review. Warnings are enumerated codes rather than free-form native
text.
The full tab/document/generation/provider-request decision context exists only
in service-worker memory. Approval, explicit rejection, and window closure use
that exact stored context and then remove it; navigation invalidation and
periodic expiry cleanup remove it as well.

Events are allowlisted and scoped to the exact tab/document binding. Provider
results cannot smuggle inline events; events enter only as typed service event
frames. Requests and results have byte, string, object-entry, depth,
pending-count, and rate bounds; secret-named native result fields fail closed.
This is defense in depth, not a substitute for typed response construction in
the native wallet. The demonstration dapp has no custodial backend, does not
create keys, and makes no network request of its own; it displays only approved
public wallet results.

The browser-owned `data/wallet-abi-v2` directory is only a versioned staging
location for a service manifest and executable artifact. It must contain no
wallet database, seed, encryption material, approval record, log, backup, or
other wallet state. Native status exposes only bounded contract versions, a
release identifier, local-integrity digest, availability booleans, and a safe
reason code; it never reads or reports wallet secrets.

An independently released wallet service must keep all wallet-owned state in
its own private location and own its migration, backup, and deletion UX. Browser
repair and Complete Uninstall may replace or remove the staged adapter files
but must not discover, migrate, or delete that external wallet state. The
current production verifier has no wallet trust root, release pin, or floor,
the controller launches no wallet artifact, and it exports no wallet result.
The browser-owned anti-rollback record contains only release line/sequence/ID,
signer ID, and manifest/artifact digests; it contains no wallet state or secret.

The Chromium popup's wallet-readiness panel is a privileged, display-only view
of that bounded admission status. The service worker accepts only the exact
known contract and internally consistent admission stages; unknown fields,
malformed metadata, or any claim that transport, runtime negotiation, provider
authority, or provider availability is enabled collapse to a fixed unavailable
view. The panel does not issue a wallet native command, start or connect to a
wallet process, persist wallet status, or expose it to a website. Consequently,
lock state, active wallet, and enabled modules are explicitly unavailable, and
provider, value, and settlement remain disabled.
