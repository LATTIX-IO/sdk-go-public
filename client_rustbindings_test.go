//go:build rustbindings

package sdk

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func rustLibraryAvailableForSmokeTest() bool {
	if envPath := os.Getenv("LATTIX_SDK_RUST_LIB"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return true
		}
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return false
	}

	releaseDir := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "sdk-rust", "target", "release"))
	var candidate string
	switch runtime.GOOS {
	case "windows":
		candidate = filepath.Join(releaseDir, "sdk_rust.dll")
	case "darwin":
		candidate = filepath.Join(releaseDir, "libsdk_rust.dylib")
	default:
		candidate = filepath.Join(releaseDir, "libsdk_rust.so")
	}

	_, err := os.Stat(candidate)
	return err == nil
}

func TestRustBindingsSmokeCapabilities(t *testing.T) {
	if !rustLibraryAvailableForSmokeTest() {
		t.Skip("native sdk-rust library not built; skipping rustbindings smoke test")
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sdk/capabilities" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"default_required_scopes":["platform-api.access"],"routes":[]}`)
	}))
	defer server.Close()

	client, err := NewClient(Options{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("expected rust-backed client to initialize, got %v", err)
	}
	defer client.Close()

	response, err := client.Capabilities()
	if err != nil {
		t.Fatalf("expected capabilities call to succeed, got %v", err)
	}

	if response.Caller.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", response.Caller.TenantID)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one HTTP request, got %d", calls.Load())
	}
}
