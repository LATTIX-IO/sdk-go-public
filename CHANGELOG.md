# Changelog

All notable changes to `sdk-go` are documented in this file.

## [Unreleased]

### Added
- Local pre-commit and pre-push quality gates with automated fixes, security scans, tests, native Rust binding validation, and cleanup.
- Release-note scaffolding that calls out version-matched native Rust asset requirements.

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