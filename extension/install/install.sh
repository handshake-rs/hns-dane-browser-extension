#!/usr/bin/env bash
set -euo pipefail

host_name="com.denuoweb.hns_dane_browser"
ca_common_name="HNS DANE Browser Local CA"
manual_root_marker_value="HNS DANE Browser manual installer root v1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_dir/../.." && pwd)"
native_host="$repository_root/rust/target/release/hns-chromium-native-host"
notice_source="$repository_root/extension/THIRD_PARTY_NOTICES.txt"
license_source="$repository_root/LICENSE"
extension_ids=()
browsers=()

usage() {
  echo "Usage: $0 --extension-id ID [--extension-id ID ...] [--browser NAME ...] [--native-host PATH]" >&2
  echo "Browsers: all, chrome, chromium, edge, brave, vivaldi, opera (default: all)" >&2
}

directory_has_entries() {
  local directory="$1"
  local entries
  shopt -s nullglob dotglob
  entries=("$directory"/*)
  shopt -u nullglob dotglob
  ((${#entries[@]} > 0))
}

nss_certificate_sha256() {
  local database="$1"
  local nickname="$2"
  local exported_certificate
  local fingerprint
  exported_certificate="$(mktemp "${TMPDIR:-/tmp}/hns-dane-browser-nss.XXXXXX")"
  if ! certutil -d "sql:$database" -L -n "$nickname" -a >"$exported_certificate"; then
    rm -f -- "$exported_certificate"
    return 1
  fi
  if ! fingerprint="$(
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$exported_certificate" |
      sed '/-----BEGIN CERTIFICATE-----/d; /-----END CERTIFICATE-----/d' |
      tr -d '\r\n' |
      base64 --decode 2>/dev/null |
      sha256sum |
      awk '{print $1}'
  )"; then
    rm -f -- "$exported_certificate"
    return 1
  fi
  rm -f -- "$exported_certificate"
  [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$fingerprint"
}

while (($# > 0)); do
  case "$1" in
    --extension-id)
      (($# >= 2)) || { usage; exit 2; }
      extension_ids+=("$2")
      shift 2
      ;;
    --browser)
      (($# >= 2)) || { usage; exit 2; }
      browsers+=("$2")
      shift 2
      ;;
    --native-host)
      (($# >= 2)) || { usage; exit 2; }
      native_host="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unsupported argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

((${#extension_ids[@]} > 0)) || {
  echo "At least one --extension-id is required." >&2
  exit 2
}
for extension_id in "${extension_ids[@]}"; do
  [[ "$extension_id" =~ ^[a-p]{32}$ ]] || {
    echo "Invalid Chromium extension ID: $extension_id" >&2
    exit 2
  }
done
if ((${#browsers[@]} == 0)); then
  browsers=(all)
fi
for browser in "${browsers[@]}"; do
  case "$browser" in
    all|chrome|chromium|edge|brave|vivaldi|opera) ;;
    *)
      echo "Unsupported browser: $browser" >&2
      exit 2
      ;;
  esac
done
[[ -f "$native_host" && -x "$native_host" ]] || {
  echo "Release native host is missing or not executable: $native_host" >&2
  echo "Build it with: cargo +1.92.0 build --release --locked --manifest-path rust/Cargo.toml -p hns-chromium-native-host" >&2
  exit 1
}
[[ -s "$notice_source" ]] || {
  echo "Third-party notices are missing: $notice_source" >&2
  exit 1
}
[[ -s "$license_source" ]] || {
  echo "Product license is missing: $license_source" >&2
  exit 1
}

case "$(uname -s)" in
  Linux)
    platform="linux"
    config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
    data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
    [[ "$config_home" == /* && "$data_home" == /* ]] || {
      echo "XDG_CONFIG_HOME and XDG_DATA_HOME must be absolute paths." >&2
      exit 1
    }
    install_root="$data_home/hns-dane-browser/chromium"
    ;;
  Darwin)
    platform="macos"
    config_home="$HOME/Library/Application Support"
    [[ "$HOME" == /* ]] || {
      echo "HOME must be an absolute path." >&2
      exit 1
    }
    install_root="$config_home/HnsDaneBrowser/Chromium"
    ;;
  *)
    echo "Use install.ps1 on Windows; this installer supports Linux and macOS." >&2
    exit 1
    ;;
esac

data_dir="$install_root/data"
installed_host="$install_root/bin/hns-chromium-native-host"
manifest_source="$install_root/$host_name.json"
certificate_path="$data_dir/chromium-ca/hns-dane-browser-local-ca.pem"
manual_root_marker="$install_root/.manual-install-root"

if [[ -e "$install_root" ]]; then
  [[ -d "$install_root" && ! -L "$install_root" ]] || {
    echo "Refusing unsafe manual install root: $install_root" >&2
    exit 1
  }
  if [[ -e "$manual_root_marker" ]]; then
    [[ -f "$manual_root_marker" && ! -L "$manual_root_marker" ]] || {
      echo "Refusing an invalid manual-install ownership marker." >&2
      exit 1
    }
    [[ "$(<"$manual_root_marker")" == "$manual_root_marker_value" ]] || {
      echo "Refusing a manual install root owned by different content." >&2
      exit 1
    }
  elif directory_has_entries "$install_root"; then
    echo "Refusing a non-empty manual install root without its ownership marker." >&2
    exit 1
  fi
  if [[ -n "$(find "$install_root" -type l -print)" ]]; then
    echo "Refusing a manual install root that contains a symlink." >&2
    exit 1
  fi
fi
for protected_path in \
  "$install_root/bin" \
  "$install_root/licenses" \
  "$data_dir" \
  "$installed_host" \
  "$manifest_source"; do
  [[ ! -L "$protected_path" ]] || {
    echo "Refusing a redirected manual-install path: $protected_path" >&2
    exit 1
  }
done
install -d -m 700 "$install_root" "$install_root/bin" "$install_root/licenses" "$data_dir"
printf '%s\n' "$manual_root_marker_value" >"$manual_root_marker"
chmod 600 "$manual_root_marker"
install -m 700 "$native_host" "$installed_host"
install -m 644 "$notice_source" "$install_root/licenses/THIRD_PARTY_NOTICES.txt"
install -m 644 "$license_source" "$install_root/licenses/LICENSE"

manifest_arguments=(--print-host-manifest)
for extension_id in "${extension_ids[@]}"; do
  manifest_arguments+=(--extension-id "$extension_id")
done
manifest_temporary="$manifest_source.tmp"
"$installed_host" "${manifest_arguments[@]}" >"$manifest_temporary"
[[ -s "$manifest_temporary" ]] || {
  echo "The native host produced an empty registration manifest." >&2
  exit 1
}
chmod 600 "$manifest_temporary"

manifest_directories=()
append_manifest_directory() {
  local candidate="$1"
  local existing
  for existing in "${manifest_directories[@]:-}"; do
    [[ "$existing" == "$candidate" ]] && return
  done
  manifest_directories+=("$candidate")
}
select_browser() {
  local wanted="$1"
  local selected
  for selected in "${browsers[@]}"; do
    [[ "$selected" == all || "$selected" == "$wanted" ]] && return 0
  done
  return 1
}

if [[ "$platform" == linux ]]; then
  select_browser chrome && append_manifest_directory "$config_home/google-chrome/NativeMessagingHosts"
  select_browser chromium && append_manifest_directory "$config_home/chromium/NativeMessagingHosts"
  select_browser edge && append_manifest_directory "$config_home/microsoft-edge/NativeMessagingHosts"
  select_browser brave && append_manifest_directory "$config_home/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  select_browser vivaldi && append_manifest_directory "$config_home/vivaldi/NativeMessagingHosts"
  if select_browser opera; then
    append_manifest_directory "$config_home/opera/NativeMessagingHosts"
    # Opera's published native-messaging contract also searches Chrome's path.
    append_manifest_directory "$config_home/google-chrome/NativeMessagingHosts"
  fi
else
  select_browser chrome && append_manifest_directory "$config_home/Google/Chrome/NativeMessagingHosts"
  select_browser chromium && append_manifest_directory "$config_home/Chromium/NativeMessagingHosts"
  select_browser edge && append_manifest_directory "$config_home/Microsoft Edge/NativeMessagingHosts"
  select_browser brave && append_manifest_directory "$config_home/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  select_browser vivaldi && append_manifest_directory "$config_home/Vivaldi/NativeMessagingHosts"
  if select_browser opera; then
    append_manifest_directory "$config_home/com.operasoftware.Opera/NativeMessagingHosts"
    append_manifest_directory "$config_home/Google/Chrome/NativeMessagingHosts"
  fi
fi

for manifest_directory in "${manifest_directories[@]}"; do
  registered_manifest="$manifest_directory/$host_name.json"
  if [[ -e "$registered_manifest" ]]; then
    [[ -f "$registered_manifest" && ! -L "$registered_manifest" ]] || {
      echo "Refusing an unsafe native-messaging registration: $registered_manifest" >&2
      exit 1
    }
    if ! cmp -s "$registered_manifest" "$manifest_temporary" &&
      { [[ ! -f "$manifest_source" ]] || ! cmp -s "$registered_manifest" "$manifest_source"; }; then
      echo "Refusing to replace a foreign native-messaging registration: $registered_manifest" >&2
      exit 1
    fi
  fi
done

mv -f "$manifest_temporary" "$manifest_source"
for manifest_directory in "${manifest_directories[@]}"; do
  install -d -m 700 "$manifest_directory"
  install -m 600 "$manifest_source" "$manifest_directory/$host_name.json"
done

ca_status="$("$installed_host" --data-dir "$data_dir" --ca-info)"
sha1_fingerprint="$(sed -n 's/.*"certificateSha1": "\([0-9a-f]*\)".*/\1/p' <<<"$ca_status")"
sha256_fingerprint="$(sed -n 's/.*"certificateSha256": "\([0-9a-f]*\)".*/\1/p' <<<"$ca_status")"
[[ "$sha1_fingerprint" =~ ^[0-9a-f]{40}$ && "$sha256_fingerprint" =~ ^[0-9a-f]{64}$ ]] || {
  echo "The native host returned invalid local-CA fingerprints." >&2
  exit 1
}
[[ -f "$certificate_path" ]] || {
  echo "The local CA certificate was not created: $certificate_path" >&2
  exit 1
}

if [[ "$platform" == linux ]]; then
  for required_tool in certutil base64 sha256sum; do
    command -v "$required_tool" >/dev/null 2>&1 || {
      echo "$required_tool is required for exact Linux NSS trust management." >&2
      [[ "$required_tool" != certutil ]] ||
        echo "Install libnss3-tools on Debian/Ubuntu or nss-tools on Fedora." >&2
      exit 1
    }
  done
  legacy_nss_database="$HOME/.pki/nssdb"
  xdg_nss_database="$data_home/pki/nssdb"
  if [[ -e "$legacy_nss_database" ]]; then
    nss_database="$legacy_nss_database"
  else
    nss_database="$xdg_nss_database"
  fi
  [[ ! -L "$nss_database" && ( ! -e "$nss_database" || -d "$nss_database" ) ]] || {
    echo "Refusing an unsafe Chromium NSS database: $nss_database" >&2
    exit 1
  }
  install -d -m 700 "$nss_database"
  if ! certutil -d "sql:$nss_database" -L >/dev/null 2>&1; then
    certutil -d "sql:$nss_database" -N --empty-password
  fi
  ca_nickname="$ca_common_name (${sha256_fingerprint:0:12})"
  if certutil -d "sql:$nss_database" -L -n "$ca_nickname" >/dev/null 2>&1; then
    existing_fingerprint="$(nss_certificate_sha256 "$nss_database" "$ca_nickname")" || {
      echo "Unable to verify the existing NSS certificate exactly; leaving it untouched." >&2
      exit 1
    }
    [[ "$existing_fingerprint" == "$sha256_fingerprint" ]] || {
      echo "Refusing to replace a different NSS certificate with the same nickname." >&2
      exit 1
    }
    certutil -d "sql:$nss_database" -D -n "$ca_nickname"
  fi
  certutil -d "sql:$nss_database" -A -t "C,," -n "$ca_nickname" -i "$certificate_path"
  installed_fingerprint="$(nss_certificate_sha256 "$nss_database" "$ca_nickname")" || {
    echo "Unable to verify the installed NSS certificate exactly." >&2
    exit 1
  }
  [[ "$installed_fingerprint" == "$sha256_fingerprint" ]] || {
    echo "The installed NSS certificate fingerprint did not match the local CA." >&2
    exit 1
  }
else
  command -v security >/dev/null 2>&1 || {
    echo "The macOS security command is required." >&2
    exit 1
  }
  login_keychain="$(
    security login-keychain |
      sed -e '/^[[:space:]]*$/d' \
        -e 's/^[[:space:]]*//' \
        -e 's/[[:space:]]*$//' \
        -e 's/^"\(.*\)"$/\1/'
  )"
  [[ -n "$login_keychain" && "$login_keychain" != *$'\n'* &&
    "$login_keychain" == /* && -f "$login_keychain" && ! -L "$login_keychain" ]] || {
    echo "Unable to resolve one actual, regular login keychain." >&2
    exit 1
  }
  if security find-certificate -a -Z "$login_keychain" 2>/dev/null |
    tr '[:upper:]' '[:lower:]' |
    grep -q "$sha1_fingerprint"; then
    security delete-certificate -t -Z "$sha1_fingerprint" "$login_keychain"
  fi
  security add-trusted-cert -r trustRoot -k "$login_keychain" "$certificate_path"
  security find-certificate -a -Z "$login_keychain" 2>/dev/null |
    tr '[:upper:]' '[:lower:]' |
    grep -q "$sha1_fingerprint" || {
      echo "macOS did not confirm the local CA in the actual login keychain." >&2
      exit 1
    }
fi

# The extension will not activate its PAC until this explicit post-trust marker
# exists. A failed trust-store operation therefore remains fail-closed.
"$installed_host" --data-dir "$data_dir" --mark-ca-installed

echo "Installed HNS DANE Browser native host for: ${browsers[*]}"
echo "Load dist/chromium-extension in each selected browser, using the registered extension ID."
echo "Local CA SHA-256: $sha256_fingerprint"
