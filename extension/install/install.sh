#!/usr/bin/env bash
set -euo pipefail

host_name="com.denuoweb.hns_dane_browser"
ca_common_name="HNS DANE Browser Local CA"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_dir/../.." && pwd)"
native_host="$repository_root/rust/target/release/hns-chromium-native-host"
extension_ids=()
browsers=()

usage() {
  echo "Usage: $0 --extension-id ID [--extension-id ID ...] [--browser NAME ...] [--native-host PATH]" >&2
  echo "Browsers: all, chrome, chromium, edge, brave, vivaldi, opera (default: all)" >&2
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

case "$(uname -s)" in
  Linux)
    platform="linux"
    config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
    data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
    install_root="${HNS_CHROMIUM_INSTALL_ROOT:-$data_home/hns-dane-browser/chromium}"
    ;;
  Darwin)
    platform="macos"
    config_home="$HOME/Library/Application Support"
    install_root="${HNS_CHROMIUM_INSTALL_ROOT:-$config_home/HnsDaneBrowser/Chromium}"
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

install -d -m 700 "$install_root" "$install_root/bin" "$data_dir"
install -m 700 "$native_host" "$installed_host"

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
mv -f "$manifest_temporary" "$manifest_source"

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
  command -v certutil >/dev/null 2>&1 || {
    echo "certutil is required (Debian/Ubuntu: libnss3-tools; Fedora: nss-tools)." >&2
    exit 1
  }
  nss_database="${HNS_CHROMIUM_NSS_DB_DIR:-$HOME/.pki/nssdb}"
  install -d -m 700 "$nss_database"
  if ! certutil -d "sql:$nss_database" -L >/dev/null 2>&1; then
    certutil -d "sql:$nss_database" -N --empty-password
  fi
  ca_nickname="$ca_common_name (${sha256_fingerprint:0:12})"
  if certutil -d "sql:$nss_database" -L -n "$ca_nickname" >/dev/null 2>&1; then
    certutil -d "sql:$nss_database" -D -n "$ca_nickname"
  fi
  certutil -d "sql:$nss_database" -A -t "C,," -n "$ca_nickname" -i "$certificate_path"
else
  command -v security >/dev/null 2>&1 || {
    echo "The macOS security command is required." >&2
    exit 1
  }
  login_keychain="$HOME/Library/Keychains/login.keychain-db"
  if security find-certificate -a -Z "$login_keychain" 2>/dev/null |
    tr '[:upper:]' '[:lower:]' |
    grep -q "$sha1_fingerprint"; then
    security delete-certificate -Z "$sha1_fingerprint" "$login_keychain"
  fi
  security add-trusted-cert -r trustRoot -k "$login_keychain" "$certificate_path"
fi

# The extension will not activate its PAC until this explicit post-trust marker
# exists. A failed trust-store operation therefore remains fail-closed.
"$installed_host" --data-dir "$data_dir" --mark-ca-installed

echo "Installed HNS DANE Browser native host for: ${browsers[*]}"
echo "Load dist/chromium-extension in each selected browser, using the registered extension ID."
echo "Local CA SHA-256: $sha256_fingerprint"
