#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="LATTIX-IO"
REPO_NAME="sdk-rust-public"
VERSION=""
INSTALL_DIR=""
NO_ACTIVATE="false"
BASE_URL="${LATTIX_SDK_RUST_RELEASE_BASE_URL:-}"
GITHUB_TOKEN="${LATTIX_SDK_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --no-activate)
      NO_ACTIVATE="true"
      shift
      ;;
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

is_sourced() {
  [[ "${BASH_SOURCE[0]}" != "$0" ]]
}

latest_release_tag() {
  local -a curl_args=(
    -fsSL
    -H 'User-Agent: lattix-sdk-go-installer'
  )

  if [[ -n "$GITHUB_TOKEN" ]]; then
    curl_args+=( -H "Authorization: Bearer ${GITHUB_TOKEN}" )
  fi

  curl "${curl_args[@]}" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" | \
    python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])'
}

release_json_by_tag() {
  local version="$1"
  local -a curl_args=(
    -fsSL
    -H 'User-Agent: lattix-sdk-go-installer'
  )

  if [[ -n "$GITHUB_TOKEN" ]]; then
    curl_args+=( -H "Authorization: Bearer ${GITHUB_TOKEN}" )
  fi

  curl "${curl_args[@]}" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${version}"
}

resolve_asset_download_url() {
  local version="$1"
  local asset_name="$2"
  release_json_by_tag "$version" | python3 - "$asset_name" "$GITHUB_TOKEN" <<'PY'
import json
import sys

asset_name = sys.argv[1]
has_token = bool(sys.argv[2])
release = json.load(sys.stdin)

for asset in release.get("assets", []):
    if asset.get("name") == asset_name:
        print(asset["url"] if has_token else asset["browser_download_url"])
        break
else:
    raise SystemExit(f"Could not resolve asset {asset_name!r} for release {release.get('tag_name', '<unknown>')}")
PY
}

resolve_asset_name() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}:${arch}" in
    Linux:x86_64) echo 'sdk-rust-native-linux-x86_64.tar.gz' ;;
    Darwin:x86_64) echo 'sdk-rust-native-macos-x86_64.tar.gz' ;;
    Darwin:arm64) echo 'sdk-rust-native-macos-aarch64.tar.gz' ;;
    *)
      echo "Unsupported platform ${os}/${arch}" >&2
      exit 1
      ;;
  esac
}

if [[ -z "$VERSION" ]]; then
  VERSION="$(latest_release_tag)"
fi

if [[ -z "$INSTALL_DIR" ]]; then
  INSTALL_DIR="${HOME}/.lattix/sdk-go/${VERSION}"
fi

ASSET_NAME="$(resolve_asset_name)"
TMP_DIR="$(mktemp -d)"
ARCHIVE_PATH="${TMP_DIR}/${ASSET_NAME}"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ -n "$BASE_URL" ]]; then
  DOWNLOAD_URL="${BASE_URL%/}/${VERSION}/${ASSET_NAME}"
  curl -fsSL -H 'User-Agent: lattix-sdk-go-installer' "$DOWNLOAD_URL" -o "$ARCHIVE_PATH"
else
  DOWNLOAD_URL="$(resolve_asset_download_url "$VERSION" "$ASSET_NAME")"
  if [[ -n "$GITHUB_TOKEN" ]]; then
    curl -fsSL \
      -H 'User-Agent: lattix-sdk-go-installer' \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H 'Accept: application/octet-stream' \
      "$DOWNLOAD_URL" -o "$ARCHIVE_PATH"
  else
    curl -fsSL -H 'User-Agent: lattix-sdk-go-installer' "$DOWNLOAD_URL" -o "$ARCHIVE_PATH"
  fi
fi

echo "Installing sdk-go native dependency from ${DOWNLOAD_URL}"

mkdir -p "$INSTALL_DIR"
tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
cp -R "${TMP_DIR}/native/." "$INSTALL_DIR/"

ACTIVATE_SCRIPT="${INSTALL_DIR}/activate-native.sh"
python3 - "$ACTIVATE_SCRIPT" "$INSTALL_DIR" <<'PY'
from pathlib import Path
import sys

activate_path = Path(sys.argv[1])
install_dir = sys.argv[2]

activate_path.write_text(
    "#!/usr/bin/env bash\n"
    f'export LATTIX_SDK_GO_NATIVE_HOME="{install_dir}"\n'
    f'export CGO_CFLAGS="-I{install_dir}/include${{CGO_CFLAGS:+ $CGO_CFLAGS}}"\n'
    f'export CGO_LDFLAGS="-L{install_dir}${{CGO_LDFLAGS:+ $CGO_LDFLAGS}}"\n'
    'if [[ "$(uname -s)" == "Darwin" ]]; then\n'
    f'  export DYLD_LIBRARY_PATH="{install_dir}${{DYLD_LIBRARY_PATH:+:${{DYLD_LIBRARY_PATH}}}}"\n'
    'else\n'
    f'  export LD_LIBRARY_PATH="{install_dir}${{LD_LIBRARY_PATH:+:${{LD_LIBRARY_PATH}}}}"\n'
    'fi\n'
)
PY
chmod +x "$ACTIVATE_SCRIPT"

if [[ "$NO_ACTIVATE" == "false" && $(is_sourced && echo yes || echo no) == "yes" ]]; then
  # shellcheck source=/dev/null
  source "$ACTIVATE_SCRIPT"
  echo "Activated sdk-go native environment for ${VERSION}"
else
  echo "Installed native sdk-rust bundle to ${INSTALL_DIR}"
  echo "Run: source '${ACTIVATE_SCRIPT}'"
fi
