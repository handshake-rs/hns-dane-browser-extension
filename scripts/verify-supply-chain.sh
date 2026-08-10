#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUST_TOOLCHAIN="1.92.0"
CARGO=(cargo "+$RUST_TOOLCHAIN")

required_supply_chain_files=(
  "rust/Cargo.lock"
  "rust/fuzz/Cargo.lock"
  "tools/hns-header-snapshot-exporter/Cargo.lock"
  "extension/manifest.json"
  "package.json"
)
for file in "${required_supply_chain_files[@]}"; do
  if [[ ! -s "$file" ]]; then
    echo "Required dependency lock or verification file is missing: $file" >&2
    exit 1
  fi
done

while IFS= read -r -d '' tracked_file; do
  base_name="${tracked_file##*/}"
  case "$base_name" in
    .env|.env.*|.envrc|local.properties|keystore.properties|signing.properties|release.properties|google-services.json|*.keystore|*.jks|*.p12|*.pfx|*.pkcs12|*.kdbx|*.pem|*.key|*.asc|service-account*.json|credentials*.json|firebase-adminsdk*.json)
      echo "Potential secret-bearing file must not be tracked: $tracked_file" >&2
      exit 1
      ;;
  esac
done < <(git ls-files -z)

if git grep -IEn \
  '(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-(proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})' \
  -- . ':!scripts/verify-supply-chain.sh'; then
  echo "Potential high-confidence secret found in a tracked file." >&2
  exit 1
fi

shopt -s nullglob
workflow_files=(.github/workflows/*.yml .github/workflows/*.yaml)
shopt -u nullglob
if [[ ${#workflow_files[@]} -eq 0 ]]; then
  echo "No GitHub Actions workflows were found." >&2
  exit 1
fi

while IFS= read -r action_reference; do
  action_reference="${action_reference#\"}"
  action_reference="${action_reference%\"}"
  action_reference="${action_reference#\'}"
  action_reference="${action_reference%\'}"
  if [[ "$action_reference" == ./* ]]; then
    continue
  fi
  if [[ ! "$action_reference" =~ ^[-A-Za-z0-9_.]+/[-A-Za-z0-9_.]+(/[-A-Za-z0-9_.]+)*@[0-9a-fA-F]{40}$ ]]; then
    echo "GitHub Action is not pinned to a full commit SHA: $action_reference" >&2
    exit 1
  fi
done < <(sed -nE 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*([^[:space:]#]+).*/\2/p' "${workflow_files[@]}")

for script in scripts/*.sh; do
  bash -n "$script"
done

python3 -m unittest -v \
  tests/test_cargo_git_policy.py \
  tests/test_browser_qualification_provenance.py
python3 scripts/verify_cargo_git_policy.py

"${CARGO[@]}" metadata --locked --manifest-path rust/Cargo.toml --no-deps --format-version 1 >/dev/null
"${CARGO[@]}" metadata --locked --manifest-path rust/fuzz/Cargo.toml --no-deps --format-version 1 >/dev/null
"${CARGO[@]}" metadata --locked --manifest-path tools/hns-header-snapshot-exporter/Cargo.toml --no-deps --format-version 1 >/dev/null

echo "Supply-chain inputs are pinned and tracked-secret checks passed."
