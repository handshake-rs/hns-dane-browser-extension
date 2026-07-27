#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
icon_source="$root_dir/store/assets/source/hns-dane-browser-icon-512.png"
feature_source="$root_dir/store/assets/source/hns-dane-browser-feature-1024x500.png"
icon_output="$root_dir/extension/assets/icons"
listing_output="$root_dir/store/assets/chrome-edge"
screenshot_output="$listing_output/screenshots"
opera_output="$root_dir/store/assets/opera/screenshots"
chromium="${CHROMIUM:-$(command -v chromium || true)}"

command -v magick >/dev/null 2>&1 || {
  echo "ImageMagick 7 (magick) is required." >&2
  exit 2
}
[[ -x "$chromium" ]] || {
  echo "Chromium is required for deterministic HTML screenshots." >&2
  exit 2
}
[[ -s "$icon_source" && -s "$feature_source" ]] || {
  echo "Canonical brand sources are missing." >&2
  exit 2
}

mkdir -p "$icon_output" "$listing_output" "$screenshot_output" "$opera_output"
while read -r canvas artwork; do
  magick "$icon_source" -resize "${artwork}x${artwork}" -background none \
    -gravity center -extent "${canvas}x${canvas}" \
    "$icon_output/icon-${canvas}.png"
done <<'SIZES'
16 12
32 24
48 36
128 96
SIZES

magick "$icon_source" -resize 300x300 "$listing_output/icon-300.png"
magick -size 440x280 'gradient:#06171f-#0d6e5b' \
  \( "$icon_source" -resize 180x180 \) -gravity center -composite \
  -alpha off "PNG24:$listing_output/promo-small-440x280.png"
magick "$feature_source" -resize '1400x560^' -gravity center \
  -extent 1400x560 -alpha off \
  "PNG24:$listing_output/promo-marquee-1400x560.png"

profile_dir="$(mktemp -d)"
cleanup() {
  find "$profile_dir" -depth -mindepth 1 -delete 2>/dev/null || true
  rmdir "$profile_dir" 2>/dev/null || true
}
trap cleanup EXIT

capture() {
  local source_path="$1"
  local output_path="$2"
  "$chromium" \
    --headless=new \
    --disable-gpu \
    --disable-extensions \
    --hide-scrollbars \
    --no-first-run \
    --run-all-compositor-stages-before-draw \
    --user-data-dir="$profile_dir" \
    --window-size=1280,800 \
    --screenshot="$output_path" \
    "file://$source_path" >/dev/null 2>&1
}

capture "$root_dir/extension/src/setup.html" \
  "$screenshot_output/01-native-host-setup-1280x800.png"
capture "$root_dir/store/captures/security-status.html" \
  "$screenshot_output/02-security-path-1280x800.png"
capture "$root_dir/store/captures/settings.html" \
  "$screenshot_output/03-recovery-settings-1280x800.png"

for screenshot in "$screenshot_output"/*.png; do
  name="${screenshot##*/}"
  magick "$screenshot" -resize '612x408^' -gravity center -extent 612x408 \
    "$opera_output/${name%-1280x800.png}-612x408.png"
done

identify "$icon_output"/*.png "$listing_output"/*.png \
  "$screenshot_output"/*.png "$opera_output"/*.png
