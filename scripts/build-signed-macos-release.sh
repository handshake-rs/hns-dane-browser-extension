#!/usr/bin/env bash
set -euo pipefail

required_environment=(
  APPLE_CERTIFICATE_NAME
  APPLE_CERTIFICATE_P12_BASE64
  APPLE_CERTIFICATE_P12_PASSWORD
  APPLE_CERTIFICATE_SHA256
  APPLE_NOTARY_API_ISSUER_ID
  APPLE_NOTARY_API_KEY_ID
  APPLE_NOTARY_API_PRIVATE_KEY_P8_BASE64
  APPLE_TEAM_ID
  ARCHITECTURE
  EXTENSION_ID
  NATIVE_RUST_TARGET
  OUTPUT_DIR
  RELEASE_TAG
  SETUP_RUST_TARGET
  SOURCE_COMMIT
  SOURCE_DATE_EPOCH
  SOURCE_ROOT
  TOOLS_ROOT
  VERSION
)
for name in "${required_environment[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "::error::Required macOS release input $name is empty."
    exit 1
  fi
done

if [[ "$ARCHITECTURE" != x64 && "$ARCHITECTURE" != arm64 ]]; then
  echo "::error::Unsupported macOS architecture: $ARCHITECTURE"
  exit 1
fi
if [[ "$RELEASE_TAG" != "v$VERSION" ]]; then
  echo "::error::Release tag and version disagree."
  exit 1
fi
if [[ ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ||
      ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ||
      ! "$EXTENSION_ID" =~ ^[a-p]{32}$ ||
      ! "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ||
      ! "$APPLE_NOTARY_API_KEY_ID" =~ ^[A-Z0-9]{10}$ ||
      ! "$APPLE_NOTARY_API_ISSUER_ID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
  echo "::error::One or more macOS signing identifiers are malformed."
  exit 1
fi

SOURCE_ROOT="$(cd "$SOURCE_ROOT" && pwd)"
TOOLS_ROOT="$(cd "$TOOLS_ROOT" && pwd)"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"
temporary="$(mktemp -d "${RUNNER_TEMP:-/tmp}/hns-macos-signing.XXXXXX")"
keychain="$temporary/signing.keychain-db"
keychain_password="$(openssl rand -hex 32)"
umask 077

cleanup() {
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  if [[ "$temporary" == "${RUNNER_TEMP:-/tmp}"/hns-macos-signing.* ]]; then
    /bin/rm -rf -- "$temporary"
  fi
}
trap cleanup EXIT

p12_path="$temporary/developer-id-application.p12"
notary_key="$temporary/AuthKey_${APPLE_NOTARY_API_KEY_ID}.p8"
printf '%s' "$APPLE_CERTIFICATE_P12_BASE64" |
  openssl base64 -d -A -out "$p12_path"
printf '%s' "$APPLE_NOTARY_API_PRIVATE_KEY_P8_BASE64" |
  openssl base64 -d -A -out "$notary_key"
chmod 600 "$p12_path" "$notary_key"
if [[ ! -s "$p12_path" || ! -s "$notary_key" ]]; then
  echo "::error::A decoded Apple credential file is empty."
  exit 1
fi

openssl3="$(command -v openssl)"
if [[ "$("$openssl3" version)" != OpenSSL\ 3.* ]]; then
  openssl3="$(brew --prefix openssl@3)/bin/openssl"
fi
if [[ ! -x "$openssl3" ||
      "$("$openssl3" version)" != OpenSSL\ 3.* ]]; then
  echo "::error::OpenSSL 3 is required to normalize the PKCS#12 bundle."
  exit 1
fi

# macOS Security.framework can report a false bad-password error for modern
# OpenSSL 3 PBES2/AES PKCS#12 containers. Decode the approved bundle with
# OpenSSL, then rewrap it only inside this ephemeral runner using legacy
# algorithms and a random one-time import password.
extracted_identity="$temporary/developer-id-application.pem"
compatible_p12="$temporary/developer-id-application-compatible.p12"
import_password="$("$openssl3" rand -hex 32)"
"$openssl3" pkcs12 \
  -in "$p12_path" \
  -passin env:APPLE_CERTIFICATE_P12_PASSWORD \
  -nodes \
  -out "$extracted_identity"
HNS_PKCS12_IMPORT_PASSWORD="$import_password" \
  "$openssl3" pkcs12 \
    -export \
    -legacy \
    -in "$extracted_identity" \
    -out "$compatible_p12" \
    -passout env:HNS_PKCS12_IMPORT_PASSWORD
chmod 600 "$extracted_identity" "$compatible_p12"

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$compatible_p12" \
  -k "$keychain" \
  -P "$import_password" \
  -T /usr/bin/codesign \
  -T /usr/bin/security >/dev/null
security set-key-partition-list \
  -S apple-tool:,apple: \
  -s \
  -k "$keychain_password" \
  "$keychain" >/dev/null
unset APPLE_CERTIFICATE_P12_BASE64
unset APPLE_CERTIFICATE_P12_PASSWORD
unset APPLE_NOTARY_API_PRIVATE_KEY_P8_BASE64
unset import_password

certificate_pem="$temporary/developer-id-application.pem"
security find-certificate \
  -c "$APPLE_CERTIFICATE_NAME" \
  -p \
  "$keychain" >"$certificate_pem"
certificate_fingerprint="$(
  openssl x509 \
    -in "$certificate_pem" \
    -noout \
    -fingerprint \
    -sha256 |
    cut -d= -f2 |
    tr -d ':' |
    tr '[:lower:]' '[:upper:]'
)"
expected_fingerprint="$(
  tr -d ':' <<<"$APPLE_CERTIFICATE_SHA256" |
    tr '[:lower:]' '[:upper:]'
)"
certificate_subject="$(
  openssl x509 -in "$certificate_pem" -noout -subject -nameopt RFC2253
)"
if [[ "$certificate_fingerprint" != "$expected_fingerprint" ]]; then
  echo "::error::Imported Developer ID certificate fingerprint is not approved."
  exit 1
fi
if [[ "$certificate_subject" != *"UID=$APPLE_TEAM_ID"* ]]; then
  echo "::error::Imported Developer ID certificate subject is not approved."
  exit 1
fi
if ! security find-identity -v -p codesigning "$keychain" |
  grep -Fq "\"$APPLE_CERTIFICATE_NAME\""; then
  echo "::error::The imported certificate has no usable code-signing private key."
  exit 1
fi

rustup toolchain install 1.92.0 --profile minimal
rustup target add \
  --toolchain 1.92.0 \
  "$NATIVE_RUST_TARGET" \
  "$SETUP_RUST_TARGET"

cargo +1.92.0 build \
  --locked \
  --release \
  --manifest-path "$SOURCE_ROOT/rust/Cargo.toml" \
  -p hns-chromium-native-host \
  --target "$NATIVE_RUST_TARGET"
native_host="$SOURCE_ROOT/rust/target/$NATIVE_RUST_TARGET/release/hns-chromium-native-host"
codesign \
  --force \
  --keychain "$keychain" \
  --options runtime \
  --sign "$APPLE_CERTIFICATE_NAME" \
  --timestamp \
  "$native_host"
codesign --verify --strict --verbose=2 "$native_host"

HNS_NATIVE_HOST_PATH="$native_host" \
  cargo +1.92.0 build \
    --locked \
    --release \
    --manifest-path "$SOURCE_ROOT/rust/Cargo.toml" \
    -p hns-browser-setup \
    --bin hns-dane-browser-setup \
    --features embedded-host \
    --target "$SETUP_RUST_TARGET"
setup_executable="$SOURCE_ROOT/rust/target/$SETUP_RUST_TARGET/release/hns-dane-browser-setup"

for binary in "$native_host" "$setup_executable"; do
  while IFS= read -r dependency; do
    case "$dependency" in
      /System/Library/* | /usr/lib/*) ;;
      *)
        echo "::error::$binary has a non-system dependency: $dependency"
        exit 1
        ;;
    esac
  done < <(otool -L "$binary" | tail -n +2 | awk '{print $1}')
done
"$setup_executable" --status >/dev/null

package=(
  python3
  "$TOOLS_ROOT/scripts/package-release.py"
)
"${package[@]}" native \
  --repository-root "$SOURCE_ROOT" \
  --output-dir "$OUTPUT_DIR" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --source-commit "$SOURCE_COMMIT" \
  --source-tag "$RELEASE_TAG" \
  --extension-id "$EXTENSION_ID" \
  --platform macos \
  --architecture "$ARCHITECTURE" \
  --rust-target "$NATIVE_RUST_TARGET" \
  --native-host "$native_host" \
  --macos-signed-notarized
"${package[@]}" setup \
  --repository-root "$SOURCE_ROOT" \
  --output-dir "$OUTPUT_DIR" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --source-commit "$SOURCE_COMMIT" \
  --source-tag "$RELEASE_TAG" \
  --extension-id "$EXTENSION_ID" \
  --platform macos \
  --architecture "$ARCHITECTURE" \
  --native-rust-target "$NATIVE_RUST_TARGET" \
  --setup-rust-target "$SETUP_RUST_TARGET" \
  --setup-executable "$setup_executable" \
  --embedded-native-host "$native_host" \
  --macos-signed-notarized

native_stem="hns-dane-browser-native-host-v${VERSION}-macos-${ARCHITECTURE}"
native_archive="$OUTPUT_DIR/${native_stem}.tar.gz"
setup_stem="hns-dane-browser-setup-v${VERSION}-macos-${ARCHITECTURE}"
setup_archive="$OUTPUT_DIR/${setup_stem}.tar.gz"
setup_stage="$temporary/setup-stage"
mkdir "$setup_stage"
tar -xzf "$setup_archive" -C "$setup_stage"
app="$setup_stage/$setup_stem/HNS DANE Browser Setup.app"

codesign \
  --force \
  --keychain "$keychain" \
  --options runtime \
  --sign "$APPLE_CERTIFICATE_NAME" \
  --timestamp \
  "$app"
codesign --verify --deep --strict --verbose=2 "$app"

notary_reports="$OUTPUT_DIR/notary-reports"
mkdir "$notary_reports"
native_upload="$temporary/${native_stem}.zip"
setup_upload="$temporary/${setup_stem}.zip"
ditto -c -k --keepParent "$native_host" "$native_upload"
ditto -c -k --keepParent "$app" "$setup_upload"

submit_and_require_acceptance() {
  local upload="$1"
  local report="$2"
  local log="$3"
  xcrun notarytool submit "$upload" \
    --key "$notary_key" \
    --key-id "$APPLE_NOTARY_API_KEY_ID" \
    --issuer "$APPLE_NOTARY_API_ISSUER_ID" \
    --wait \
    --output-format json >"$report"
  local status
  local submission_id
  status="$(jq -er '.status' "$report")"
  submission_id="$(jq -er '.id' "$report")"
  if [[ "$status" != Accepted ]]; then
    echo "::error::Apple notarization did not accept $(basename "$upload")."
    xcrun notarytool log "$submission_id" \
      --key "$notary_key" \
      --key-id "$APPLE_NOTARY_API_KEY_ID" \
      --issuer "$APPLE_NOTARY_API_ISSUER_ID" \
      "$log" || true
    exit 1
  fi
  xcrun notarytool log "$submission_id" \
    --key "$notary_key" \
    --key-id "$APPLE_NOTARY_API_KEY_ID" \
    --issuer "$APPLE_NOTARY_API_ISSUER_ID" \
    "$log"
}

submit_and_require_acceptance \
  "$native_upload" \
  "$notary_reports/${native_stem}-submission.json" \
  "$notary_reports/${native_stem}-log.json"
submit_and_require_acceptance \
  "$setup_upload" \
  "$notary_reports/${setup_stem}-submission.json" \
  "$notary_reports/${setup_stem}-log.json"

xcrun stapler staple "$app"
xcrun stapler validate "$app"
codesign --verify --deep --strict --verbose=2 "$app"
spctl --assess --type execute --verbose=4 "$app"

/bin/rm -f -- "$setup_archive" "${setup_archive}.sha256"
COPYFILE_DISABLE=1 tar -czf "$setup_archive" -C "$setup_stage" "$setup_stem"
setup_digest="$(shasum -a 256 "$setup_archive" | awk '{print $1}')"
printf '%s  %s\n' \
  "$setup_digest" \
  "$(basename "$setup_archive")" >"${setup_archive}.sha256"

verification_stage="$temporary/verification-stage"
mkdir "$verification_stage"
tar -xzf "$setup_archive" -C "$verification_stage"
verified_app="$verification_stage/$setup_stem/HNS DANE Browser Setup.app"
codesign --verify --deep --strict --verbose=2 "$verified_app"
xcrun stapler validate "$verified_app"
spctl --assess --type execute --verbose=4 "$verified_app"

native_verification="$temporary/native-verification"
mkdir "$native_verification"
tar -xzf "$native_archive" -C "$native_verification"
verified_native="$native_verification/$native_stem/rust/target/release/hns-chromium-native-host"
codesign --verify --strict --verbose=2 "$verified_native"

for archive in "$native_archive" "$setup_archive"; do
  checksum="${archive}.sha256"
  expected="$(cut -d ' ' -f1 "$checksum")"
  actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "::error::Checksum mismatch for $(basename "$archive")."
    exit 1
  fi
done

jq -e \
  '.nativeHost.codeSigningStatus == "developerIdSigned" and
   .nativeHost.notarizationStatus == "acceptedOnlineTicket"' \
  "$native_verification/$native_stem/RELEASE-METADATA.json" >/dev/null
jq -e \
  '.setup.codeSigningStatus == "developerIdSigned" and
   .setup.notarizationStatus == "acceptedAndStapled"' \
  "$verification_stage/$setup_stem/RELEASE-METADATA.json" >/dev/null

printf 'Signed and notarized macOS release assets are ready for %s.\n' \
  "$ARCHITECTURE"
