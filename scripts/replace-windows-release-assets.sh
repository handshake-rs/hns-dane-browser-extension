#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
windows_signer_metadata="$source_root/release/windows-self-signed-code-signing.json"
windows_signer_certificate="$source_root/release/windows-self-signed-code-signing.cer"
if [[ ! -f "$windows_signer_metadata" ||
      ! -f "$windows_signer_certificate" ]]; then
  echo "::error::Pinned Windows self-signed certificate evidence is missing."
  exit 1
fi
windows_signer_subject="$(jq -er '.subject' "$windows_signer_metadata")"
windows_signer_sha256="$(jq -er '.certificateSha256' "$windows_signer_metadata")"
actual_windows_signer_sha256="$(
  sha256sum "$windows_signer_certificate" | cut -d ' ' -f1
)"
if [[ ! "$windows_signer_sha256" =~ ^[a-f0-9]{64}$ ||
      "$actual_windows_signer_sha256" != "$windows_signer_sha256" ]]; then
  echo "::error::Pinned Windows self-signed certificate evidence is invalid."
  exit 1
fi

required_environment=(
  ASSET_DIR
  BACKUP_DIR
  GH_REPO
  GH_TOKEN
  RELEASE_ID
  RELEASE_TAG
  VERSION
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "::error::Required Windows release replacement input $name is empty."
    exit 1
  fi
done
if [[ "$RELEASE_TAG" != "v$VERSION" ||
      ! "$RELEASE_ID" =~ ^[0-9]+$ ]]; then
  echo "::error::Windows release replacement identity is malformed."
  exit 1
fi

ASSET_DIR="$(cd "$ASSET_DIR" && pwd)"
BACKUP_DIR="$(mkdir -p "$BACKUP_DIR" && cd "$BACKUP_DIR" && pwd)"
workspace="$(mktemp -d "${RUNNER_TEMP:-/tmp}/hns-windows-replacement.XXXXXX")"
cleanup() {
  if [[ "$workspace" == "${RUNNER_TEMP:-/tmp}"/hns-windows-replacement.* ]]; then
    /bin/rm -rf -- "$workspace"
  fi
}
trap cleanup EXIT

archives=(
  "hns-dane-browser-extension-v${VERSION}-mv3.zip"
  "hns-dane-browser-extension-v${VERSION}-mv3-store.zip"
  "hns-dane-browser-native-host-v${VERSION}-linux-x64.tar.gz"
  "hns-dane-browser-native-host-v${VERSION}-linux-arm64.tar.gz"
  "hns-dane-browser-native-host-v${VERSION}-windows-x64.zip"
  "hns-dane-browser-native-host-v${VERSION}-windows-arm64.zip"
  "hns-dane-browser-native-host-v${VERSION}-macos-x64.tar.gz"
  "hns-dane-browser-native-host-v${VERSION}-macos-arm64.tar.gz"
  "hns-dane-browser-setup-v${VERSION}-linux-x64.tar.gz"
  "hns-dane-browser-setup-v${VERSION}-linux-arm64.tar.gz"
  "hns-dane-browser-setup-v${VERSION}-windows-x64.zip"
  "hns-dane-browser-setup-v${VERSION}-windows-arm64.zip"
  "hns-dane-browser-setup-v${VERSION}-macos-x64.tar.gz"
  "hns-dane-browser-setup-v${VERSION}-macos-arm64.tar.gz"
)
all_assets=()
for archive in "${archives[@]}"; do
  all_assets+=("$archive" "${archive}.sha256")
done
all_assets+=("SHA256SUMS")

release_json="$BACKUP_DIR/release-before-windows-signing.json"
gh api "repos/${GH_REPO}/releases/${RELEASE_ID}" >"$release_json"
if [[ "$(jq -er '.tag_name' "$release_json")" != "$RELEASE_TAG" ||
      "$(jq -er '.draft' "$release_json")" != false ]]; then
  echo "::error::The target is not the expected published release."
  exit 1
fi
if [[ "$(jq -r '.assets | length' "$release_json")" != 29 ]]; then
  echo "::error::The published release does not have exactly 29 assets."
  exit 1
fi

mapfile -t remote_names < <(jq -r '.assets[].name' "$release_json" | sort)
mapfile -t expected_names < <(printf '%s\n' "${all_assets[@]}" | sort)
if [[ "${remote_names[*]}" != "${expected_names[*]}" ]]; then
  echo "::error::Published release asset names differ from the expected set."
  exit 1
fi

mkdir "$BACKUP_DIR/assets"
gh release download "$RELEASE_TAG" \
  --repo "$GH_REPO" \
  --dir "$BACKUP_DIR/assets"
for archive in "${archives[@]}"; do
  (
    cd "$BACKUP_DIR/assets"
    sha256sum --check "${archive}.sha256"
  )
done
(
  cd "$BACKUP_DIR/assets"
  sha256sum --check SHA256SUMS
)

replacement_assets=()
for architecture in x64 arm64; do
  for kind in native-host setup; do
    archive="hns-dane-browser-${kind}-v${VERSION}-windows-${architecture}.zip"
    replacement_assets+=("$archive" "${archive}.sha256")
  done
done
replacement_assets+=("SHA256SUMS")

final_dir="$workspace/final"
mkdir "$final_dir"
cp "$BACKUP_DIR/assets/"* "$final_dir/"
for asset in "${replacement_assets[@]:0:8}"; do
  if [[ ! -s "$ASSET_DIR/$asset" ]]; then
    echo "::error::Signed Windows replacement asset is missing: $asset"
    exit 1
  fi
  cp "$ASSET_DIR/$asset" "$final_dir/$asset"
done

for architecture in x64 arm64; do
  native_archive="hns-dane-browser-native-host-v${VERSION}-windows-${architecture}.zip"
  setup_archive="hns-dane-browser-setup-v${VERSION}-windows-${architecture}.zip"
  (
    cd "$final_dir"
    sha256sum --check "${native_archive}.sha256"
    sha256sum --check "${setup_archive}.sha256"
  )
  native_metadata="$(
    unzip -p "$final_dir/$native_archive" \
      "${native_archive%.zip}/RELEASE-METADATA.json"
  )"
  setup_metadata="$(
    unzip -p "$final_dir/$setup_archive" \
      "${setup_archive%.zip}/RELEASE-METADATA.json"
  )"
  jq -e \
    --arg subject "$windows_signer_subject" \
    --arg fingerprint "$windows_signer_sha256" \
    '.nativeHost.codeSigningStatus == "selfSignedAuthenticode" and
     .nativeHost.certificateTrust == "notPubliclyTrusted" and
     .nativeHost.timestampStatus == "rfc3161Sha256" and
     .nativeHost.signerSubject == $subject and
     .nativeHost.signerCertificateSha256 == $fingerprint' \
    <<<"$native_metadata" >/dev/null
  jq -e \
    --arg subject "$windows_signer_subject" \
    --arg fingerprint "$windows_signer_sha256" \
    '.setup.codeSigningStatus == "selfSignedAuthenticode" and
     .setup.certificateTrust == "notPubliclyTrusted" and
     .setup.timestampStatus == "rfc3161Sha256" and
     .setup.signerSubject == $subject and
     .setup.signerCertificateSha256 == $fingerprint' \
    <<<"$setup_metadata" >/dev/null
done

(
  cd "$final_dir"
  sha256sum "${archives[@]}" >SHA256SUMS
  sha256sum --check SHA256SUMS
)

pending_suffix="pending-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"
pending_dir="$workspace/pending"
mkdir "$pending_dir"
pending_names=()
for asset in "${replacement_assets[@]}"; do
  pending_name="${asset}.${pending_suffix}"
  cp "$final_dir/$asset" "$pending_dir/$pending_name"
  pending_names+=("$pending_name")
done
gh release upload "$RELEASE_TAG" \
  --repo "$GH_REPO" \
  "$pending_dir/"*

assets_json="$workspace/assets-with-pending.json"
gh api \
  --paginate \
  "repos/${GH_REPO}/releases/${RELEASE_ID}/assets?per_page=100" |
  jq -s 'add' >"$assets_json"
for index in "${!replacement_assets[@]}"; do
  pending="${pending_names[$index]}"
  local_path="$final_dir/${replacement_assets[$index]}"
  local_size="$(stat --format=%s "$local_path")"
  local_digest="sha256:$(sha256sum "$local_path" | cut -d ' ' -f1)"
  match_count="$(
    jq --arg name "$pending" \
      '[.[] | select(.name == $name)] | length' \
      "$assets_json"
  )"
  remote_size="$(
    jq -r --arg name "$pending" \
      '.[] | select(.name == $name) | .size' \
      "$assets_json"
  )"
  remote_digest="$(
    jq -r --arg name "$pending" \
      '.[] | select(.name == $name) | .digest // ""' \
      "$assets_json"
  )"
  if [[ "$match_count" != 1 ||
        "$remote_size" != "$local_size" ||
        "$remote_digest" != "$local_digest" ]]; then
    echo "::error::Pending Windows upload $pending is not exact."
    exit 1
  fi
done

for index in "${!replacement_assets[@]}"; do
  canonical="${replacement_assets[$index]}"
  pending="${pending_names[$index]}"
  old_id="$(
    jq -er --arg name "$canonical" \
      '[.[] | select(.name == $name)] |
       if length == 1 then .[0].id else error("canonical asset is not unique") end' \
      "$assets_json"
  )"
  pending_id="$(
    jq -er --arg name "$pending" \
      '[.[] | select(.name == $name)] |
       if length == 1 then .[0].id else error("pending asset is not unique") end' \
      "$assets_json"
  )"
  gh api --method DELETE "repos/${GH_REPO}/releases/assets/${old_id}"
  gh api \
    --method PATCH \
    "repos/${GH_REPO}/releases/assets/${pending_id}" \
    -f name="$canonical" >/dev/null
done

final_json="$workspace/release-after-windows-signing.json"
gh api "repos/${GH_REPO}/releases/${RELEASE_ID}" >"$final_json"
mapfile -t final_remote_names < <(jq -r '.assets[].name' "$final_json" | sort)
if [[ "${final_remote_names[*]}" != "${expected_names[*]}" ]]; then
  echo "::error::Final published release asset names are not exact."
  exit 1
fi
for asset in "${all_assets[@]}"; do
  local_path="$final_dir/$asset"
  local_size="$(stat --format=%s "$local_path")"
  local_digest="sha256:$(sha256sum "$local_path" | cut -d ' ' -f1)"
  remote_size="$(
    jq -er --arg name "$asset" \
      '.assets[] | select(.name == $name) | .size' \
      "$final_json"
  )"
  remote_digest="$(
    jq -er --arg name "$asset" \
      '.assets[] | select(.name == $name) | .digest' \
      "$final_json"
  )"
  if [[ "$remote_size" != "$local_size" ||
        "$remote_digest" != "$local_digest" ]]; then
    echo "::error::Final published asset $asset does not match locally."
    exit 1
  fi
done

notes_file="$workspace/release-notes.md"
jq -r '.body // ""' "$release_json" >"$notes_file"
python3 - "$notes_file" "$windows_signer_sha256" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
fingerprint = sys.argv[2]
text = path.read_text(encoding="utf-8")
old = "Automated Windows bundles are unsigned."
new = (
    "Windows native hosts and setup executables carry the project's "
    "self-signed Authenticode signature and RFC 3161 SHA-256 timestamps. "
    "The certificate is not publicly trusted, so SmartScreen or Unknown "
    "Publisher warnings may appear. Verify the archive SHA-256 and published "
    f"certificate fingerprint {fingerprint}."
)
if old not in text:
    raise SystemExit("published release notes lack the expected Windows signing disclosure")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
gh api \
  --method PATCH \
  "repos/${GH_REPO}/releases/${RELEASE_ID}" \
  --raw-field body="$(cat "$notes_file")" >/dev/null

gh api "repos/${GH_REPO}/releases/${RELEASE_ID}" \
  >"$BACKUP_DIR/release-after-windows-signing.json"
if ! jq -er '.body' "$BACKUP_DIR/release-after-windows-signing.json" |
  grep -Fq "self-signed Authenticode signature"; then
  echo "::error::The final release notes do not disclose Windows signing."
  exit 1
fi

printf 'Windows release assets and SHA256SUMS replaced for %s.\n' "$RELEASE_TAG"
