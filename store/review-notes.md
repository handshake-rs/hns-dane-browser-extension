# Store Reviewer Notes

HNS DANE Browser intentionally fails closed until HNS DANE Browser Setup
installs its embedded native Rust host and per-user local CA. The extension ZIP
cannot embed or launch an arbitrary platform executable.

## Setup

1. Submit the keyless
   `hns-dane-browser-extension-v<version>-mv3-store.zip` release asset, then
   install it from the store/test channel. The similarly named `-mv3.zip`
   asset carries the canonical development public key and is not the
   first-submission package.
2. The first-install page shows the exact 32-character catalog extension ID.
3. Follow the first-install page's version-specific GitHub Release link and
   download the matching Setup package. Use its separately labeled
   latest-release link only as an intentional compatibility fallback.
4. Close the browser being tested.
5. Open Setup, paste the exact ID, select the browser under review, and choose
   **Install or Repair**. The manual native-host archive and shell/PowerShell
   installers remain release assets only as an expert fallback with less
   transactional recovery than Setup.
6. Reopen the browser. The popup should report `Rust security path active` and
   `DANE local CA: Installed`.

Setup is user-level. Linux packages include the required NSS certificate
utility and non-system runtime libraries. Setup registers only the exact
supplied extension origin, creates one local CA, installs that CA in the
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
- Disable/remove the native host or CA and confirm the PAC is cleared and
  browsing is blocked rather than silently bypassed.
- Run the supplied uninstaller and confirm native registrations, exact CA,
  binary, and runtime data are removed.

No login, paid feature, region lock, telemetry endpoint, or remote executable
code is involved. Donations are external, optional, and do not unlock
features.
