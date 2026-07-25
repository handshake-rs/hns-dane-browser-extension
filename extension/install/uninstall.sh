#!/usr/bin/env bash
set -euo pipefail

host_name="com.denuoweb.hns_dane_browser"
ca_common_name="HNS DANE Browser Local CA"
browsers=()

usage() {
  echo "Usage: $0 [--browser all]" >&2
  echo "The native host and CA are shared, so uninstall always removes all registrations." >&2
}

while (($# > 0)); do
  case "$1" in
    --browser)
      (($# >= 2)) || { usage; exit 2; }
      browsers+=("$2")
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
if ((${#browsers[@]} == 0)); then
  browsers=(all)
fi
for browser in "${browsers[@]}"; do
  case "$browser" in
    all) ;;
    *)
      echo "Selective uninstall is unsafe for the shared native host; use --browser all." >&2
      exit 2
      ;;
  esac
done

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
    echo "Use uninstall.ps1 on Windows; this uninstaller supports Linux and macOS." >&2
    exit 1
    ;;
esac

data_dir="$install_root/data"
installed_host="$install_root/bin/hns-chromium-native-host"
marker_path="$data_dir/chromium-ca/ca-installed.json"
bundle_path="$data_dir/chromium-ca/ca-bundle.json"

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
  return 0
}

if [[ "$platform" == linux ]]; then
  select_browser chrome && append_manifest_directory "$config_home/google-chrome/NativeMessagingHosts"
  select_browser chromium && append_manifest_directory "$config_home/chromium/NativeMessagingHosts"
  select_browser edge && append_manifest_directory "$config_home/microsoft-edge/NativeMessagingHosts"
  select_browser brave && append_manifest_directory "$config_home/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  select_browser vivaldi && append_manifest_directory "$config_home/vivaldi/NativeMessagingHosts"
  if select_browser opera; then
    append_manifest_directory "$config_home/opera/NativeMessagingHosts"
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
  rm -f -- "$manifest_directory/$host_name.json"
  rmdir --ignore-fail-on-non-empty "$manifest_directory" 2>/dev/null || true
done

ca_status=""
if [[ -x "$installed_host" && -f "$bundle_path" ]]; then
  ca_status="$("$installed_host" --data-dir "$data_dir" --ca-info 2>/dev/null || true)"
  "$installed_host" --data-dir "$data_dir" --clear-ca-installed 2>/dev/null || true
elif [[ -f "$marker_path" ]]; then
  ca_status="$(<"$marker_path")"
fi
sha1_fingerprint="$(sed -n 's/.*"certificateSha1": "\([0-9a-f]*\)".*/\1/p' <<<"$ca_status")"
sha256_fingerprint="$(sed -n 's/.*"certificateSha256": "\([0-9a-f]*\)".*/\1/p' <<<"$ca_status")"

if [[ "$platform" == linux ]] && command -v certutil >/dev/null 2>&1; then
  nss_database="${HNS_CHROMIUM_NSS_DB_DIR:-$HOME/.pki/nssdb}"
  if [[ "$sha256_fingerprint" =~ ^[0-9a-f]{64}$ ]]; then
    ca_nickname="$ca_common_name (${sha256_fingerprint:0:12})"
    if certutil -d "sql:$nss_database" -L -n "$ca_nickname" >/dev/null 2>&1; then
      certutil -d "sql:$nss_database" -D -n "$ca_nickname"
    fi
  elif [[ -d "$nss_database" ]]; then
    while IFS= read -r ca_nickname; do
      [[ -n "$ca_nickname" ]] && certutil -d "sql:$nss_database" -D -n "$ca_nickname"
    done < <(
      certutil -d "sql:$nss_database" -L 2>/dev/null |
        sed -n 's/^\(HNS DANE Browser Local CA ([0-9a-fA-F][0-9a-fA-F]*)\).*/\1/p'
    )
  fi
elif [[ "$platform" == macos ]] && command -v security >/dev/null 2>&1; then
  login_keychain="$HOME/Library/Keychains/login.keychain-db"
  if [[ ! "$sha1_fingerprint" =~ ^[0-9a-f]{40}$ ]]; then
    sha1_fingerprint="$(
      security find-certificate -c "$ca_common_name" -Z "$login_keychain" 2>/dev/null |
        sed -n 's/^SHA-1 hash: //p' |
        tr '[:upper:]' '[:lower:]' |
        head -n 1
    )"
  fi
  if [[ "$sha1_fingerprint" =~ ^[0-9a-f]{40}$ ]]; then
    security delete-certificate -Z "$sha1_fingerprint" "$login_keychain" 2>/dev/null || true
  fi
fi

if [[ -e "$install_root" ]]; then
  [[ "$install_root" != / && "$install_root" != "$HOME" && ${#install_root} -ge 16 ]] || {
    echo "Refusing to purge unsafe install root: $install_root" >&2
    exit 1
  }
  find "$install_root" -depth -delete
fi

echo "Removed the HNS DANE Browser native host, trust anchor, manifests, and runtime data."
