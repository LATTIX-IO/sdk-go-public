# Releasing `sdk-go`

`sdk-go` is a thin binding over the native `sdk-rust` core. A Go tag is only
supported when there is a matching `sdk-rust` tag and release artifact set.

## Supported distribution strategy

- Publish the Go module from the public mirror path `github.com/LATTIX-IO/sdk-go-public` using a versioned tag.
- Distribute the matching native `sdk-rust` artifacts for the same version.
- Publish the installer helpers `install-native.sh` and `install-native.ps1` in the release.
- Treat the installer flow as the supported one-command bootstrap path until managed package feeds exist.

The private `sdk-go` repository remains authoritative for development, while the
release workflow mirrors source, tags, and release assets to the public
repository `LATTIX-IO/sdk-go-public`. The workflow requires `GH_PAT` with push
access to that public repository.

## Before tagging

1. Verify the native Rust release for the same version exists or is being cut in
   the same release train.
2. Update `CHANGELOG.md` with the release date and compatibility notes.
3. Run:
   - `go test ./...`
   - `go test ./... -tags rustbindings`
   - `go vet ./...`
  - `go build ./...`
  - `go build ./... -tags rustbindings`
4. Confirm README instructions still match the native install strategy.
5. Refresh `.github/release.yml` and `.github/RELEASE_TEMPLATE.md` if the native asset/install story has changed.

## Release steps

1. Update release notes and any version-specific compatibility guidance.
2. Create and push a tag such as `v0.1.0`.
3. Let `.github/workflows/release.yml` verify the matching `sdk-rust-public` release exists.
4. Start the release notes from `.github/RELEASE_TEMPLATE.md` and keep the installer/native instructions version-matched.
5. Publish the release notes with a prominent note that the installer flow resolves the matching native asset set.
6. Link the corresponding `sdk-rust-public` mirror release in the notes.
7. Confirm the public `sdk-go-public` mirror release was created for the same tag.
8. If you override the default mirror host, document the
  `LATTIX_SDK_RUST_RELEASE_BASE_URL` override for consumers explicitly.

## Notes

- Public documentation at `https://lattix.io/docs` intentionally omits per-SDK
  API reference details; the README and tagged release notes are the canonical
  Go consumer guidance.
- Avoid monorepo-specific instructions in release notes. Consumers should not
  need a sibling checkout just to understand the supported install path.
- Homebrew, Chocolatey, apt, and rpm remain future enhancements, not the current
  support contract, because they do not by themselves guarantee Go module and
  native ABI version alignment.