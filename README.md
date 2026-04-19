# sdk-go

`sdk-go` is the Go binding for the Lattix Rust SDK core. It targets the metadata-only `lattix-platform-api` control-plane endpoints used by embedded SDK and future MCP workflows.

The public Lattix docs at `https://lattix.io/docs` intentionally do not publish per-language API reference material. This repository's README and tagged releases are the supported Go reference surface.

## What it exposes

The Go package is a thin typed wrapper over the native Rust library and currently supports:

- `Capabilities()`
- `WhoAmI()`
- `Bootstrap()`
- `ProtectionPlan(...)`
- `PolicyResolve(...)`
- `KeyAccessPlan(...)`
- `ArtifactRegister(...)`
- `Evidence(...)`

These map directly to the `lattix-platform-api` SDK endpoints and intentionally operate on **metadata**, not plaintext payloads.

## Build and installation

The supported distribution strategy is:

- consume the Go module from the public mirror path `github.com/LATTIX-IO/sdk-go-public` and a tagged `sdk-go-public` release; and
- install the **matching** native `sdk-rust` release artifact for the same version from the public mirror repository `sdk-rust-public` using the provided installer flow.

The private `sdk-go` repository remains the canonical development repo, but the
supported public module path is the mirrored repository
`github.com/LATTIX-IO/sdk-go-public`.

### One-command native bootstrap

The supported short-term “one command” path is the repository installer flow,
which downloads the version-matched `sdk-rust` native bundle and prepares the
required environment variables.

#### Windows

- run `install-native.ps1`
- the script downloads the matching `sdk-rust` native archive from `LATTIX-IO/sdk-rust-public`
- it writes `LATTIX_SDK_RUST_LIB` for the current shell and, unless told not to,
  persists it for the current user

#### Linux and macOS

- run or source `install-native.sh`
- the script downloads the matching `sdk-rust` native archive from `LATTIX-IO/sdk-rust-public`
- it writes an `activate-native.sh` helper that exports `CGO_CFLAGS`,
  `CGO_LDFLAGS`, and the appropriate dynamic library path for the installed version

This installer flow is the supported bootstrap mechanism until dedicated package
manager feeds are operated and validated.

If you prefer manual installation, the older per-platform asset steps still work:

- Windows: install `sdk_rust.dll` and either place it next to your executable or set `LATTIX_SDK_RUST_LIB`
- Linux/macOS: install the matching `libsdk_rust.so` / `libsdk_rust.dylib`, expose `lattix_sdk.h`, and set `CGO_CFLAGS` / `CGO_LDFLAGS`
- build or test with `-tags rustbindings`

Example local development flow:

```bash
CGO_CFLAGS="-I/path/to/sdk-rust/include" \
CGO_LDFLAGS="-L/path/to/sdk-rust/lib" \
go test ./... -tags rustbindings
```

Without the `rustbindings` build tag, the package still compiles but `NewClient(...)` returns a runtime error explaining that the native library is not enabled.

## Usage

```go
package main

import (
	"fmt"

	sdk "github.com/LATTIX-IO/sdk-go-public"
)

func main() {
	client, err := sdk.NewClient(sdk.Options{
		BaseURL:     "https://api.lattix.io",
		BearerToken: "replace-me",
		TenantID:    "tenant-a",
		UserID:      "user-a",
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	bootstrap, err := client.Bootstrap()
	if err != nil {
		panic(err)
	}

	fmt.Println(bootstrap.EnforcementModel)
}
```

## Design notes

- Rust owns HTTP behavior, contract serialization, and platform semantics.
- Go stays thin and typed, so it does not reimplement policy/control-plane logic.
- The control-plane contract is aligned to the zero-trust model: protect locally, send metadata to the platform.
- Official support assumes version-matched native artifacts from `sdk-rust` releases rather than monorepo-relative paths.

## Testing

Default unit tests use a fake binding, so they run without native linkage:

```bash
go test ./...
```

To validate the real native path, install or build the matching Rust library and then run:

```bash
go test ./... -tags rustbindings
```

On Windows this validates the native DLL bridge instead of cgo, which avoids requiring `gcc` just to exercise the Rust SDK. Fancy that: fewer compilers, same binding.

The tagged test suite also includes a small native smoke test that creates a real Rust-backed client and calls a local in-memory HTTP server through the binding.

## Local quality gate

Run the full local quality gate before committing when you want automated fixes,
security scans, tests, builds, and artifact cleanup in one go:

```bash
./precommit.sh
```

On Windows:

```powershell
./precommit.ps1
```

The gate applies formatting fixes first, then runs linting, SAST, secret
scanning, default Go tests, and—when the matching Rust native library is
available—the `rustbindings` test/build path as well.

To wire these checks into local Git commits and pushes:

```bash
./install-hooks.sh
```

or:

```powershell
./install-hooks.ps1
```

The installed `pre-commit` hook runs a faster gate. The installed `pre-push`
hook runs the full gate so broken native bindings get caught before CI does.

## Release process

Release and tagging guidance is documented in `RELEASING.md`. Tagged releases also
attach `install-native.sh` and `install-native.ps1` so consumers can use the
installer flow without cloning the repository. The installer resolves native
assets from the public mirror repository `LATTIX-IO/sdk-rust-public` by default.
Use `LATTIX_SDK_RUST_RELEASE_BASE_URL` only when you need to override that
mirror with a different artifact host. Public Go consumers should use the
mirrored source and releases published to `LATTIX-IO/sdk-go-public`.

## License

Distributed under the proprietary Lattix SDK License in `LICENSE`.

