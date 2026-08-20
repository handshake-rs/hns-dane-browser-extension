#!/usr/bin/env bash
set -euo pipefail

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
    echo "::error::Required release replacement input $name is empty."
    exit 1
  fi
done
if [[ "$RELEASE_TAG" != "v$VERSION" ||
      ! "$RELEASE_ID" =~ ^[0-9]+$ ]]; then
  echo "::error::Release replacement identity is malformed."
  exit 1
fi

ASSET_DIR="$(cd "$ASSET_DIR" && pwd)"
BACKUP_DIR="$(mkdir -p "$BACKUP_DIR" && cd "$BACKUP_DIR" && pwd)"
workspace="$(mktemp -d "${RUNNER_TEMP:-/tmp}/hns-release-replacement.XXXXXX")"
cleanup() {
  if [[ "$workspace" == "${RUNNER_TEMP:-/tmp}"/hns-release-replacement.* ]]; then
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

release_json="$BACKUP_DIR/release-before-macos-signing.json"
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
  echo "::error::Published release asset names differ from the expected v$VERSION set."
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
    archive="hns-dane-browser-${kind}-v${VERSION}-macos-${architecture}.tar.gz"
    replacement_assets+=("$archive" "${archive}.sha256")
  done
done
replacement_assets+=("SHA256SUMS")

final_dir="$workspace/final"
mkdir "$final_dir"
cp "$BACKUP_DIR/assets/"* "$final_dir/"
for asset in "${replacement_assets[@]:0:8}"; do
  if [[ ! -s "$ASSET_DIR/$asset" ]]; then
    echo "::error::Signed replacement asset is missing: $asset"
    exit 1
  fi
  cp "$ASSET_DIR/$asset" "$final_dir/$asset"
done

for architecture in x64 arm64; do
  native_archive="hns-dane-browser-native-host-v${VERSION}-macos-${architecture}.tar.gz"
  setup_archive="hns-dane-browser-setup-v${VERSION}-macos-${architecture}.tar.gz"
  (
    cd "$final_dir"
    sha256sum --check "${native_archive}.sha256"
    sha256sum --check "${setup_archive}.sha256"
  )
  inspection="$workspace/inspection-$architecture"
  mkdir "$inspection"
  tar -xzf "$final_dir/$native_archive" -C "$inspection"
  tar -xzf "$final_dir/$setup_archive" -C "$inspection"
  jq -e \
    '.nativeHost.codeSigningStatus == "developerIdSigned" and
     .nativeHost.notarizationStatus == "acceptedOnlineTicket"' \
    "$inspection/${native_archive%.tar.gz}/RELEASE-METADATA.json" >/dev/null
  jq -e \
    '.setup.codeSigningStatus == "developerIdSigned" and
     .setup.notarizationStatus == "acceptedAndStapled"' \
    "$inspection/${setup_archive%.tar.gz}/RELEASE-METADATA.json" >/dev/null
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
  canonical="${replacement_assets[$index]}"
  pending="${pending_names[$index]}"
  local_path="$final_dir/$canonical"
  local_size="$(stat --format=%s "$local_path")"
  local_digest="sha256:$(sha256sum "$local_path" | cut -d ' ' -f1)"
  match_count="$(
    jq \
      --arg name "$pending" \
      '[.[] | select(.name == $name)] | length' \
      "$assets_json"
  )"
  if [[ "$match_count" != 1 ]]; then
    echo "::error::Pending upload $pending is not unique."
    exit 1
  fi
  remote_size="$(
    jq -r \
      --arg name "$pending" \
      '.[] | select(.name == $name) | .size' \
      "$assets_json"
  )"
  remote_digest="$(
    jq -r \
      --arg name "$pending" \
      '.[] | select(.name == $name) | .digest // ""' \
      "$assets_json"
  )"
  if [[ "$remote_size" != "$local_size" ||
        "$remote_digest" != "$local_digest" ]]; then
    echo "::error::Pending upload $pending does not match its local file."
    exit 1
  fi
done

for index in "${!replacement_assets[@]}"; do
  canonical="${replacement_assets[$index]}"
  pending="${pending_names[$index]}"
  old_id="$(
    jq -er \
      --arg name "$canonical" \
      '[.[] | select(.name == $name)] | if length == 1 then .[0].id else error("canonical asset is not unique") end' \
      "$assets_json"
  )"
  pending_id="$(
    jq -er \
      --arg name "$pending" \
      '[.[] | select(.name == $name)] | if length == 1 then .[0].id else error("pending asset is not unique") end' \
      "$assets_json"
  )"
  gh api \
    --method DELETE \
    "repos/${GH_REPO}/releases/assets/${old_id}"
  gh api \
    --method PATCH \
    "repos/${GH_REPO}/releases/assets/${pending_id}" \
    -f name="$canonical" >/dev/null
done

final_json="$workspace/release-after-assets.json"
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
    jq -er \
      --arg name "$asset" \
      '.assets[] | select(.name == $name) | .size' \
      "$final_json"
  )"
  remote_digest="$(
    jq -er \
      --arg name "$asset" \
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
python3 - "$notes_file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = (
    "Automated\nmacOS binaries are unsigned and not notarized; they rely only "
    "on system\nframeworks until project signing credentials exist."
)
new = (
    "macOS native hosts and setup apps are signed with the project Developer "
    "ID Application certificate and accepted by Apple's notarization service. "
    "Setup apps carry stapled tickets; standalone native hosts use Apple's "
    "online notarization ticket."
)
if old not in text:
    raise SystemExit("release notes do not contain the expected unsigned macOS notice")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
gh api \
  --method PATCH \
  "repos/${GH_REPO}/releases/${RELEASE_ID}" \
  -F "body=@$notes_file" >/dev/null

final_release="$BACKUP_DIR/release-after-macos-signing.json"
gh api "repos/${GH_REPO}/releases/${RELEASE_ID}" >"$final_release"
if [[ "$(jq -er '.tag_name' "$final_release")" != "$RELEASE_TAG" ||
      "$(jq -er '.name' "$final_release")" != "Shakescape $VERSION" ||
      "$(jq -er '.draft' "$final_release")" != false ]]; then
  echo "::error::Release identity changed during macOS asset replacement."
  exit 1
fi

printf 'Replaced and verified the signed macOS assets for %s.\n' "$RELEASE_TAG"
