# TODO — SDK Go

## Completed foundation

- [x] Replace the legacy HTTP upload/session client with a Rust-core binding wrapper
- [x] Align the typed surface to the `lattix-platform-api` `/v1/sdk/*` control-plane contract
- [x] Support Windows DLL loading and non-Windows cgo builds
- [x] Point non-Windows cgo builds at the canonical header in `../sdk-rust/include/lattix_sdk.h`
- [x] Add fake-binding unit tests and a tagged native smoke test

## Next up

- [ ] Expand native smoke coverage beyond `Capabilities()` to one or two additional Rust-backed endpoints
- [ ] Add CI coverage for the native binding matrix:
  - Windows DLL bridge
  - Linux/macOS cgo bridge
- [ ] Decide how release artifacts should package or fetch the required `sdk-rust` native library for downstream consumers

## Product backlog

- **[MESH-912]** Chunked uploader (Go/Rust/Python + tdf-cli)
  > Start → stream → commit → verify with resume support and progress reporting.

- **[MESH-1292]** CLI/SDK: apply at encrypt & edit later
  > Add `set_attributes()` and `edit_attributes()` methods.

- **[MESH-1704]** Typed CAS-X SDK from OpenAPI/proto
  > Generate typed Go client coverage for compute/verify/link/recall/proof/search.

- **[MESH-1644]** PDP + PEP cache helper SDK
  > Add typed client coverage for `/policy/eval`, `/revoke`, `/jwks`, plus a built-in PEP cache helper.
