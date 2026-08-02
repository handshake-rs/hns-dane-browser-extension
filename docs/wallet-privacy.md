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
Approval storage contains a short-lived public review descriptor: exact origin,
method, expiry, asset, base-unit amount, recipient, fee, chain, confirmation
policy, price round, refund timeout, and similarly non-secret identifiers when
applicable. It is removed after a decision, navigation invalidation, window
closure, or periodic expiry cleanup. Review fields have per-field types;
warnings are enumerated codes rather than free-form native text.

Events are allowlisted and scoped to the exact tab/document binding. Requests
and results have byte, string, object-entry, depth, pending-count, and rate
bounds; secret-named native result fields fail closed. This is defense in depth,
not a substitute for typed response construction in the native wallet. The
demonstration dapp has no custodial backend, does not create keys, and makes no
network request of its own; it displays only approved public wallet results.
