#!/usr/bin/env bash
set -euo pipefail

host_name="com.denuoweb.hns_dane_browser"
ca_common_name="HNS DANE Browser Local CA"
manual_root_marker_value="HNS DANE Browser manual installer root v1"
browsers=()

usage() {
  echo "Usage: $0 [--browser all]" >&2
  echo "The native host and CA are shared, so uninstall always removes all registrations." >&2
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
    echo "Use uninstall.ps1 on Windows; this uninstaller supports Linux and macOS." >&2
    exit 1
    ;;
esac

data_dir="$install_root/data"
installed_host="$install_root/bin/hns-chromium-native-host"
manifest_source="$install_root/$host_name.json"
marker_path="$data_dir/chromium-ca/ca-installed.json"
bundle_path="$data_dir/chromium-ca/ca-bundle.json"
manual_root_marker="$install_root/.manual-install-root"

if [[ ! -e "$install_root" ]]; then
  echo "No manual installation exists at the fixed per-user root: $install_root"
  exit 0
fi
[[ -d "$install_root" && ! -L "$install_root" ]] || {
  echo "Refusing unsafe manual install root: $install_root" >&2
  exit 1
}
[[ -f "$manual_root_marker" && ! -L "$manual_root_marker" &&
  "$(<"$manual_root_marker")" == "$manual_root_marker_value" ]] || {
  echo "Refusing recursive removal without the exact manual-install ownership marker." >&2
  exit 1
}
[[ ! -L "$manifest_source" && ! -L "$installed_host" ]] || {
  echo "Refusing redirected files in the manual install root." >&2
  exit 1
}
if [[ -n "$(find "$install_root" -type l -print)" ]]; then
  echo "Refusing recursive removal because the manual install root contains a symlink." >&2
  exit 1
fi

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
  registered_manifest="$manifest_directory/$host_name.json"
  if [[ -e "$registered_manifest" ]]; then
    if [[ -f "$registered_manifest" && ! -L "$registered_manifest" &&
      -f "$manifest_source" ]] &&
      cmp -s "$registered_manifest" "$manifest_source"; then
      rm -f -- "$registered_manifest"
    else
      echo "Leaving foreign or unverifiable registration untouched: $registered_manifest" >&2
    fi
  fi
  rmdir "$manifest_directory" 2>/dev/null || true
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

if [[ "$platform" == linux ]]; then
  for required_tool in certutil base64 sha256sum; do
    command -v "$required_tool" >/dev/null 2>&1 || {
      echo "$required_tool is required to remove the exact Linux NSS trust anchor; preserving the manual install root." >&2
      exit 1
    }
  done
  [[ "$sha256_fingerprint" =~ ^[0-9a-f]{64}$ ]] || {
    echo "Exact Linux CA metadata is unavailable; preserving trust state and the manual install root." >&2
    exit 1
  }
  legacy_nss_database="$HOME/.pki/nssdb"
  xdg_nss_database="$data_home/pki/nssdb"
  ca_nickname="$ca_common_name (${sha256_fingerprint:0:12})"
  for nss_database in "$legacy_nss_database" "$xdg_nss_database"; do
    [[ ! -L "$nss_database" && ( ! -e "$nss_database" || -d "$nss_database" ) ]] || {
      echo "Refusing an unsafe Chromium NSS database: $nss_database" >&2
      exit 1
    }
    if [[ -d "$nss_database" ]] &&
      certutil -d "sql:$nss_database" -L -n "$ca_nickname" >/dev/null 2>&1; then
      existing_fingerprint="$(nss_certificate_sha256 "$nss_database" "$ca_nickname")" || {
        echo "Unable to verify the NSS certificate exactly in $nss_database; preserving it." >&2
        exit 1
      }
      if [[ "$existing_fingerprint" == "$sha256_fingerprint" ]]; then
        certutil -d "sql:$nss_database" -D -n "$ca_nickname"
        if certutil -d "sql:$nss_database" -L -n "$ca_nickname" >/dev/null 2>&1; then
          echo "The exact NSS certificate remained after removal from $nss_database." >&2
          exit 1
        fi
      else
        echo "Leaving a different NSS certificate with the same nickname untouched in $nss_database." >&2
      fi
    fi
  done
elif [[ "$platform" == macos ]]; then
  command -v security >/dev/null 2>&1 || {
    echo "The macOS security command is required to remove the exact trust anchor; preserving the manual install root." >&2
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
  if [[ "$sha1_fingerprint" =~ ^[0-9a-f]{40}$ ]]; then
    if security find-certificate -a -Z "$login_keychain" 2>/dev/null |
      tr '[:upper:]' '[:lower:]' |
      grep -q "$sha1_fingerprint"; then
      security delete-certificate -t -Z "$sha1_fingerprint" "$login_keychain"
    fi
  else
    echo "Exact macOS CA metadata is unavailable; preserving trust state and the manual install root." >&2
    exit 1
  fi
fi

[[ "$install_root" != / && "$install_root" != "$HOME" && ${#install_root} -ge 16 ]] || {
  echo "Refusing to purge unsafe install root: $install_root" >&2
  exit 1
}
find "$install_root" -xdev -depth -delete

echo "Removed the Shakescape native host, trust anchor, manifests, and runtime data."
