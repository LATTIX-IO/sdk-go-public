# Changelog

All notable changes to `sdk-go` are documented in this file.

## [Unreleased]

## [0.1.1] - 2026-05-11

### Added
- Shared integration-full runner coverage for the Go binding, including composed-environment CI dispatch support.
- Local pre-commit and pre-push quality gates with automated fixes, security scans, tests, native Rust binding validation, and cleanup.
- Release-note scaffolding that calls out version-matched native Rust asset requirements.

### Changed
- Aligned the Go binding auth contract with the direct bearer plus proof-of-possession control-plane surface.
- Expanded the integration-full runner to use managed envelope key source references expected by the shared fixture path.

### Fixed
- Composed integration-full tests now skip cleanly when Rust bindings are unavailable, while native-binding CI builds against `sdk-rust` source and the pinned shared fixture branch.

## [0.1.0] - 2026-04-17

### Added
- Thin Go binding over the Rust-core Lattix SDK for `/v1/sdk/*` metadata-only control-plane operations.
- Typed request and response models matching the platform SDK contract.
- Windows DLL loading path and non-Windows cgo binding path.
- Native smoke test coverage for the real Rust-backed capability flow.
- Proprietary licensing and maintainer release documentation.

### Changed
- Replaced the legacy HTTP upload/session client surface with Rust-core bindings.
- Removed monorepo-specific runtime guidance from public-facing error messages.

### Removed
- Dead gomock/mock scaffolding and duplicated native header copy.