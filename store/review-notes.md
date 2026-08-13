# Store Reviewer Notes

HNS DANE Browser intentionally fails closed until HNS DANE Browser Setup
installs its embedded native Rust host, validated height-300,000 header
bootstrap, and per-user local CA. The extension cannot launch an executable;
its reviewed ZIP contains six fixed Setup archives and offers the one matching
the review machine as an ordinary user-initiated download.

## Setup

1. Submit the keyless
   `hns-dane-browser-extension-v<version>-mv3-store.zip` release asset, then
   install it from the store/test channel. The similarly named `-mv3.zip`
   asset carries the canonical development public key and is not the
   first-submission package.
2. The first-install page identifies the operating system and CPU and offers
   the matching Setup archive embedded in that submitted ZIP. Save it.
3. Close the browser being tested.
4. Open Setup and confirm each exact 32-character catalog extension ID baked
   into the release. Select the browser under review and choose
   **Install or Repair**. The manual native-host archive and shell/PowerShell
   installers remain release assets only as an expert fallback with less
   transactional recovery than Setup.
5. Reopen the browser. The popup should report `Rust security path active` and
   `DANE local CA: Installed`.

On Windows, Setup and its embedded native host carry the project's self-signed
Authenticode signature and an RFC 3161 SHA-256 timestamp. The certificate is
not publicly trusted, so SmartScreen or **Unknown Publisher** may still appear.
Before running Setup, compare the archive SHA-256 and displayed publisher
certificate fingerprint with the release metadata. Setup never installs that
publisher certificate into Windows trust.

Setup is user-level. Linux packages include the required NSS certificate
utility and non-system runtime libraries. Setup registers only the exact
release-baked or explicitly entered extension origins, creates one local CA,
installs that CA in the
current user's browser trust database, and writes the activation marker only
after trust installation succeeds. It does not scan browser profiles or infer
an extension ID.

## Suggested checks

- Open `https://reddit.com/r/handshake`. For ordinary ICANN WebPKI fallback,
  the browser must display Reddit's real public certificate, not the local CA.
- Open `https://dane-test.denuoweb.com/`. The popup should show ICANN and a
  securely present TLSA/DANE path.
- Open a working HNS HTTPS name. The popup should show HNS proof, DNSSEC, TLSA,
  DANE, page anchor, and header-chain status.
- Use a bad DNSSEC/TLSA test case and confirm the request fails closed.
- Remove or make the native host/CA unavailable and confirm the extension
  moves a top-level GET to its packaged waiting page before installing the
  fixed blocking PAC. The packaged rule is enabled before first-start/update
  worker code runs. Restore the host and confirm that exact navigation
  resumes once rather than surfacing a proxy-tunnel error or silently
  bypassing through system/direct routing. POST requests are never replayed.
- Choose **Complete Uninstall…** in the extension dropdown, save the selected
  Setup archive, close all supported browsers, run Setup, and choose
  **Complete Uninstall**. Confirm native registrations, exact CA, binary, and
  runtime data are removed. Browser profiles, bookmarks, and extensions must
  remain.
- Install an extension update while the preceding native-host version remains
  installed. Confirm the extension retains its blocking gate, reports that
  Setup must be rerun, and opens that handoff only once in the browser session.
  Run the newly embedded Setup, choose **Install or Repair**, reopen the
  browser, and confirm normal activation.

No login, paid feature, region lock, telemetry endpoint, or remote executable
code is involved. Donations are external, optional, and do not unlock
features.

Public product disclosures:

- Product: <https://denuoweb.com/work/hns-dane-browser-extension>
- Privacy: <https://denuoweb.com/work/hns-dane-browser-extension/privacy>
- License and user agreement: <https://denuoweb.com/work/hns-dane-browser-extension/legal>

The same privacy summary, bundled release policy, product license, user
agreement, and third-party notices are available from the extension's
**Privacy & Legal** screen without an account or network connection. The
public pages remain available for store review and pre-install reading.
