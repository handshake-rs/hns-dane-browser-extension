# Store Privacy Declarations

Use these as conservative drafts and reconcile every saved dashboard answer
with the exact release before submission.

## Data handled

- **Web history / website activity:** `Yes, locally and for core
  functionality.` Exact URLs and document/tab identifiers may be retained in
  bounded `chrome.storage.session` receipts until the browser session ends.
  During a proxy/root transition, the packaged waiting page also keeps its
  exact credential-free GET target and local gate revision in that tab's
  `sessionStorage` to prevent a resume loop. During a first-install or upgrade
  bootstrap, the worker may also hold at most one target per tab in memory for
  up to one minute. They are not sent to Denuo Web.
- **Domain-level DNS activity:** `Yes, for core functionality.` Queried
  hostnames, record types, timing, protocol metadata, and the user's network
  address are necessarily visible to the built-in Cloudflare validating ICANN
  DoH resolver. When independently enabled, a selected HNS relay peer or
  user-configured recursive HNS DoH operator can see the HNS query and network
  source described in the privacy policy.
- **Website content:** `No collection by the extension.` Page bodies, form
  contents, cookies, credentials, and downloads are not sent to Denuo Web.
  They pass between the user and the selected website as ordinary browsing
  requires.
- **User-configured MeshMine endpoint:** `Yes, locally and for core
  functionality when used.` The endpoint is stored on-device. A direct,
  credential-free statistics request discloses the caller's network address
  and timing to the selected operator; neither the endpoint nor response is
  sent to Denuo Web.
- **Personally identifiable, health, financial/payment, authentication,
  personal communications, location, and user-generated content:** `No
  developer collection.`

## Use and sharing

- Used only to provide dual-root resolution, navigation correlation, security
  verification, diagnostics, and user-requested browsing.
- Not sold, not used for advertising or creditworthiness, and not transferred
  to data brokers.
- No Denuo Web analytics, telemetry, crash-upload, account, or browsing-history
  backend exists.
- DNS disclosure is necessary to provide the user-requested resolver
  functionality and is described by operator and consent boundary in the
  public privacy policy.
- Data use complies with the Chrome Web Store limited-use requirement.

## Controls and retention

- User policy stays on the device.
- Navigation receipts are bounded and session-only.
- Transition waiting-page targets are tab-scoped, retained only for the tab's
  page session (or for at most one minute in worker memory during bootstrap),
  and discarded when that tab or session ends; POST requests are never queued
  or replayed.
- Resolver, proof, header, namespace-binding, and peer state remain in the
  local native-host data directory.
- Users can clear the optional recursive resolver, disable P2P requester use,
  clear the MeshMine endpoint, remove the extension, and use HNS DANE Browser
  Setup's Complete Uninstall.
- Setup stores only a local receipt—or a bounded ownership transaction while
  installation is in progress—containing product version, selected browser
  flavors, exact registered extension IDs, owned/trust-store paths, and the
  local CA fingerprints needed for repair and exact removal.
- No developer account or server-side user profile exists.

Privacy URL:
`https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/docs/privacy-policy.md`
