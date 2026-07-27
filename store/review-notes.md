# Store Reviewer Notes

HNS DANE Browser intentionally fails closed until its separately distributed
native Rust host and per-user local CA are installed. The extension ZIP cannot
embed or launch an arbitrary platform executable.

## Setup

1. Submit the keyless
   `hns-dane-browser-extension-v<version>-mv3-store.zip` release asset, then
   install it from the store/test channel. The similarly named `-mv3.zip`
   asset carries the canonical development public key and is not the
   first-submission package.
2. The first-install page shows the exact 32-character catalog extension ID.
3. Follow the first-install page's version-specific GitHub Release link and
   download the matching native-host bundle. Use its separately labeled
   latest-release link only as an intentional compatibility fallback.
4. Close the browser being tested.
5. Unpack the bundle and run its installer with that exact ID and browser:
   - Linux/macOS:
     `bash extension/install/install.sh --extension-id ID --browser chrome`
   - Microsoft Edge:
     use `--browser edge`
   - Opera:
     use `--browser opera`
   - Windows PowerShell:
     `Set-ExecutionPolicy -Scope Process Bypass -Force; & .\extension\install\install.ps1 -ExtensionId ID -Browser edge`
6. Reopen the browser. The popup should report `Rust security path active` and
   `DANE local CA: Installed`.

Linux requires `certutil` from `libnss3-tools`/`nss-tools`. The installer is
user-level. It registers only the exact supplied extension origin, creates one
local CA, installs that CA in the current user's browser trust database, and
writes the activation marker only after trust installation succeeds.

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
