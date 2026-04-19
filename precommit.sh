#!/usr/bin/env bash
set -euo pipefail

FAST=false
BUILT_SDK_RUST=false

for arg in "$@"; do
  case "$arg" in
    --fast)
      FAST=true
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./precommit.sh [--fast]

  --fast   Skip the heavier native rustbindings path and deeper security scans.
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo "sdk-go local quality gate"

find_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    command -v "$cmd"
    return 0
  fi
  if command -v "${cmd}.exe" >/dev/null 2>&1; then
    command -v "${cmd}.exe"
    return 0
  fi
  return 1
}

run_if_available() {
  local cmd="$1"
  local desc="$2"
  shift 2
  local cmd_bin
  if cmd_bin="$(find_cmd "$cmd")"; then
    echo " - $desc"
    "$cmd_bin" "$@"
  else
    echo " - Skipping $desc (missing $cmd)"
  fi
}

cleanup() {
  if GO_BIN="$(find_cmd go)"; then
    echo "6) Cleanup"
    "$GO_BIN" clean -cache -testcache >/dev/null 2>&1 || true
  fi
  if [[ "$BUILT_SDK_RUST" == true ]]; then
    local cargo_bin
    if cargo_bin="$(find_cmd cargo)"; then
      (cd "$REPO_ROOT/../sdk-rust" && "$cargo_bin" clean >/dev/null 2>&1) || true
    fi
  fi
}

trap cleanup EXIT

if ! GO_BIN="$(find_cmd go)"; then
  echo "go is required for sdk-go quality checks." >&2
  exit 1
fi

mapfile -d '' GO_FILES < <(find . -type f -name '*.go' -not -path './.git/*' -print0)

prepare_native_rustbindings() {
  local rust_repo="$REPO_ROOT/../sdk-rust"
  if [[ -n "${LATTIX_SDK_RUST_LIB:-}" && -f "${LATTIX_SDK_RUST_LIB}" ]]; then
    return 0
  fi

  if [[ -n "${LATTIX_SDK_RUST_LIB:-}" ]]; then
    echo " - Ignoring stale LATTIX_SDK_RUST_LIB path: ${LATTIX_SDK_RUST_LIB}"
    unset LATTIX_SDK_RUST_LIB
  fi

  if [[ ! -d "$rust_repo" ]]; then
    return 1
  fi

  local cargo_bin
  if ! cargo_bin="$(find_cmd cargo)"; then
    return 1
  fi

  echo " - Building sibling sdk-rust native library for rustbindings checks"
  (cd "$rust_repo" && "$cargo_bin" build --release)
  BUILT_SDK_RUST=true

  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      export LATTIX_SDK_RUST_LIB="$rust_repo/target/release/sdk_rust.dll"
      ;;
    Darwin*)
      export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }-I$rust_repo/include"
      export CGO_LDFLAGS="${CGO_LDFLAGS:+$CGO_LDFLAGS }-L$rust_repo/target/release"
      export DYLD_LIBRARY_PATH="$rust_repo/target/release${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
      ;;
    *)
      export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }-I$rust_repo/include"
      export CGO_LDFLAGS="${CGO_LDFLAGS:+$CGO_LDFLAGS }-L$rust_repo/target/release"
      export LD_LIBRARY_PATH="$rust_repo/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
      ;;
  esac

  return 0
}

export PYTHONUTF8=1
export PYTHONIOENCODING=UTF-8

echo "1) Apply automated fixes"
if ((${#GO_FILES[@]} > 0)); then
  if GOIMPORTS_BIN="$(find_cmd goimports)"; then
    "$GOIMPORTS_BIN" -w "${GO_FILES[@]}"
  else
    gofmt -w "${GO_FILES[@]}"
  fi
fi
"$GO_BIN" mod tidy

echo "2) Lint and correctness"
gofmt -w "${GO_FILES[@]}"
if ((${#GO_FILES[@]} > 0)); then
  if [[ -n "$(gofmt -l "${GO_FILES[@]}")" ]]; then
    echo "gofmt reported unformatted files after fixes." >&2
    exit 1
  fi
fi
"$GO_BIN" vet ./...
run_if_available staticcheck "Static analysis via staticcheck" ./...

echo "3) Security scans"
run_if_available semgrep "SAST via Semgrep" --config=auto --exclude .git --exclude vendor --exclude dist --exclude .venv .
run_if_available gitleaks "Secret scanning via Gitleaks" detect --source . --no-git --redact
run_if_available govulncheck "Go vulnerability scan via govulncheck" ./...
if [[ "$FAST" == false ]]; then
  run_if_available gosec "Go SAST via gosec" ./...
  run_if_available trivy "Filesystem security scan via Trivy" fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --exit-code 1 .
else
  echo " - Fast mode: skipping gosec and Trivy"
fi

echo "4) Tests"
"$GO_BIN" test ./...
if [[ "$FAST" == false ]] && prepare_native_rustbindings; then
  "$GO_BIN" test ./... -tags rustbindings
else
  echo " - Skipping rustbindings tests (fast mode or native sdk-rust unavailable)"
fi

echo "5) Build"
"$GO_BIN" build ./...
if [[ "$FAST" == false ]] && { [[ -n "${LATTIX_SDK_RUST_LIB:-}" ]] || [[ "$BUILT_SDK_RUST" == true ]] || [[ -n "${CGO_CFLAGS:-}" ]]; }; then
  "$GO_BIN" build -tags rustbindings ./...
else
  echo " - Skipping rustbindings build (fast mode or native sdk-rust unavailable)"
fi

echo "All checks passed."