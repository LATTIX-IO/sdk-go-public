//go:build rustbindings

package sdk

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func commandProviderTestShim(t *testing.T, keyB64 string) (string, []string, map[string]string) {
	t.Helper()

	tempDir := t.TempDir()
	if runtime.GOOS == "windows" {
		scriptPath := filepath.Join(tempDir, "provider.cmd")
		script := "@echo off\r\n" +
			"echo {\"key_b64\":\"%LATTIX_TEST_KEY_B64%\"}\r\n"
		if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
			t.Fatalf("expected command shim to be written, got %v", err)
		}
		return "cmd", []string{"/C", scriptPath}, map[string]string{"LATTIX_TEST_KEY_B64": keyB64}
	}

	scriptPath := filepath.Join(tempDir, "provider.sh")
	script := "#!/usr/bin/env sh\n" +
		"printf '{\"key_b64\":\"%s\"}\\n' \"$LATTIX_TEST_KEY_B64\"\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("expected command shim to be written, got %v", err)
	}

	return scriptPath, nil, map[string]string{"LATTIX_TEST_KEY_B64": keyB64}
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
		_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","auth_configuration":{"mode":"oauth_client_credentials","proof_of_possession":"mtls","oidc_issuer":"https://issuer.example","oidc_audience":"lattix-platform-api","oidc_issuer_ready":true,"mtls_ready":true},"caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"default_required_scopes":["platform-api.access"],"routes":[]}`)
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
	if response.AuthConfiguration.Mode != SdkAuthConfigurationModeOAuthClientCredentials {
		t.Fatalf("expected oauth client credentials mode, got %q", response.AuthConfiguration.Mode)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected exactly one HTTP request, got %d", calls.Load())
	}
}

func TestRustBindingsSmokeGenerateCIDBinding(t *testing.T) {
	if !rustLibraryAvailableForSmokeTest() {
		t.Skip("native sdk-rust library not built; skipping rustbindings smoke test")
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v1/sdk/bootstrap":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"enforcement_model":"embedded_local_library","plaintext_to_platform":false,"policy_resolution_mode":"metadata_only_control_plane","supported_operations":["protect"],"supported_artifact_profiles":["envelope"],"platform_domains":[]}`)
		case "/v1/sdk/policy-resolve":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":[]},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/protection-plan":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}`)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(Options{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("expected rust-backed client to initialize, got %v", err)
	}
	defer client.Close()

	response, err := client.GenerateCIDBinding([]byte("hello world"), LocalProtectionRequest{
		Workload:                 WorkloadDescriptor{Application: "example-app"},
		Resource:                 ResourceDescriptor{Kind: "document"},
		PreferredArtifactProfile: ArtifactProfileEnvelope,
		Labels:                   []string{"confidential"},
		Attributes:               map[string]string{"region": "us"},
	})
	if err != nil {
		t.Fatalf("expected generate cid binding call to succeed, got %v", err)
	}

	if response.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", response.TenantID)
	}
	if response.RawCID != "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Fatalf("expected hello-world CID, got %q", response.RawCID)
	}
	if response.BindingHash == "" {
		t.Fatalf("expected binding hash to be populated")
	}
	if len(response.BindingTargets) != 2 {
		t.Fatalf("expected binding targets to round-trip, got %#v", response.BindingTargets)
	}

	if calls.Load() != 3 {
		t.Fatalf("expected three HTTP requests, got %d", calls.Load())
	}
}

func TestRustBindingsSmokeManagedTDFRoundTrip(t *testing.T) {
	if !rustLibraryAvailableForSmokeTest() {
		t.Skip("native sdk-rust library not built; skipping rustbindings smoke test")
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")

		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)

		switch r.URL.Path {
		case "/v1/sdk/bootstrap":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"enforcement_model":"embedded_local_library","plaintext_to_platform":false,"policy_resolution_mode":"metadata_only_control_plane","supported_operations":["protect","access"],"supported_artifact_profiles":["tdf"],"platform_domains":[]}`)
		case "/v1/sdk/policy-resolve":
			operation := "protect"
			if strings.Contains(body, `"operation":"access"`) {
				operation = "access"
			}
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"`+operation+`","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":[]},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/protection-plan":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"tdf","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","key_strategy":"local","policy_resolution":"metadata_only","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true}},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/key-access-plan":
			operation := "wrap"
			if strings.Contains(body, `"operation":"unwrap"`) {
				operation = "unwrap"
			}
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"`+operation+`","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"operation":"`+operation+`","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true}},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/artifact-register":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":1},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/evidence":
			eventType := "protect"
			if strings.Contains(body, `"event_type":"access"`) {
				eventType = "access"
			}
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"`+eventType+`","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}`)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(Options{
		BaseURL: server.URL,
		ManagedSymmetricKeyProviders: []InMemoryManagedKeyProviderConfig{{
			Name: "memory",
			Keys: map[string][]byte{
				"tenant-key-go": []byte("01234567890123456789012345678901"),
			},
		}},
	})
	if err != nil {
		t.Fatalf("expected rust-backed client to initialize, got %v", err)
	}
	defer client.Close()

	protected, err := client.ProtectBytesWithTDFUsingKeySource(
		ManagedReferenceKeySourceWithProvider("memory", "tenant-key-go"),
		[]byte("hello world"),
		LocalProtectionRequest{
			Workload:                 WorkloadDescriptor{Application: "example-app"},
			Resource:                 ResourceDescriptor{Kind: "document"},
			PreferredArtifactProfile: ArtifactProfileTDF,
			Purpose:                  "store",
			Labels:                   []string{"confidential"},
			Attributes:               map[string]string{"region": "us"},
		},
	)
	if err != nil {
		t.Fatalf("expected protect call to succeed, got %v", err)
	}
	if protected.Artifact.TDF.PolicyContext == nil || protected.Artifact.TDF.PolicyContext.Workload.Application != "example-app" {
		t.Fatalf("expected policy context to round-trip in protected TDF artifact")
	}

	artifactBytes, err := protected.Artifact.ArtifactBytes()
	if err != nil {
		t.Fatalf("expected artifact bytes to decode, got %v", err)
	}
	accessed, err := client.AccessBytesWithTDFUsingKeySource(
		ManagedReferenceKeySourceWithProvider("memory", "tenant-key-go"),
		artifactBytes,
	)
	if err != nil {
		t.Fatalf("expected access call to succeed, got %v", err)
	}
	plaintext, err := accessed.Plaintext()
	if err != nil {
		t.Fatalf("expected plaintext to decode, got %v", err)
	}
	if string(plaintext) != "hello world" {
		t.Fatalf("expected hello world plaintext, got %q", string(plaintext))
	}

	if calls.Load() != 9 {
		t.Fatalf("expected nine HTTP requests, got %d", calls.Load())
	}

	payload, err := json.Marshal(protected.Artifact.TDF.PolicyContext)
	if err != nil || !strings.Contains(string(payload), "example-app") {
		t.Fatalf("expected policy context to marshal cleanly, got %q / %v", string(payload), err)
	}
}

func TestRustBindingsSmokeManagedTDFRoundTripWithCommandProvider(t *testing.T) {
	if !rustLibraryAvailableForSmokeTest() {
		t.Skip("native sdk-rust library not built; skipping rustbindings smoke test")
	}

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")

		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)

		switch r.URL.Path {
		case "/v1/sdk/bootstrap":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"enforcement_model":"embedded_local_library","plaintext_to_platform":false,"policy_resolution_mode":"metadata_only_control_plane","supported_operations":["protect","access"],"supported_artifact_profiles":["tdf"],"platform_domains":[]}`)
		case "/v1/sdk/policy-resolve":
			operation := "protect"
			if strings.Contains(body, `"operation":"access"`) {
				operation = "access"
			}
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"`+operation+`","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":["artifact_digest","content_digest"],"evidence_expected":[]},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/protection-plan":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"tdf","content_digest_present":true,"content_size_bytes":11,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","key_strategy":"local","policy_resolution":"metadata_only","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true}},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/key-access-plan":
			operation := "wrap"
			if strings.Contains(body, `"operation":"unwrap"`) {
				operation = "unwrap"
			}
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"`+operation+`","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"operation":"`+operation+`","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only","key_transport":{"mode":"wrapped_key_reference","key_material_origin":"kms","stable_key_reference_preferred":true,"raw_key_delivery_forbidden":true}},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/artifact-register":
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest":"sha256:any","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":1,"attribute_count":1},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]}`)
		case "/v1/sdk/evidence":
			eventType := "protect"
			if strings.Contains(body, `"event_type":"access"`) {
				eventType = "access"
			}
			_, _ = io.WriteString(w, `{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"`+eventType+`","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":1,"attribute_count":1},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}`)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	keyBytes := []byte("01234567890123456789012345678901")
	keyB64 := base64.StdEncoding.EncodeToString(keyBytes)
	command, args, providerEnv := commandProviderTestShim(t, keyB64)

	client, err := NewClient(Options{
		BaseURL: server.URL,
		ManagedSymmetricKeyProviders: []ManagedSymmetricKeyProviderConfig{
			NewCommandManagedKeyProviderConfig(
				"command-kms",
				command,
				args,
				providerEnv,
			),
		},
	})
	if err != nil {
		t.Fatalf("expected rust-backed client to initialize, got %v", err)
	}
	defer client.Close()

	protected, err := client.ProtectBytesWithTDFUsingKeySource(
		ManagedReferenceKeySourceWithProvider("command-kms", "tenant-key-go"),
		[]byte("hello world"),
		LocalProtectionRequest{
			Workload:                 WorkloadDescriptor{Application: "example-app"},
			Resource:                 ResourceDescriptor{Kind: "document"},
			PreferredArtifactProfile: ArtifactProfileTDF,
			Purpose:                  "store",
			Labels:                   []string{"confidential"},
			Attributes:               map[string]string{"region": "us"},
		},
	)
	if err != nil {
		t.Fatalf("expected protect call to succeed, got %v", err)
	}
	artifactBytes, err := protected.Artifact.ArtifactBytes()
	if err != nil {
		t.Fatalf("expected artifact bytes to decode, got %v", err)
	}

	accessed, err := client.AccessBytesWithTDFUsingKeySource(
		ManagedReferenceKeySourceWithProvider("command-kms", "tenant-key-go"),
		artifactBytes,
	)
	if err != nil {
		t.Fatalf("expected access call to succeed, got %v", err)
	}
	plaintext, err := accessed.Plaintext()
	if err != nil {
		t.Fatalf("expected plaintext to decode, got %v", err)
	}
	if string(plaintext) != "hello world" {
		t.Fatalf("expected hello world plaintext, got %q", string(plaintext))
	}

	if calls.Load() != 9 {
		t.Fatalf("expected nine HTTP requests, got %d", calls.Load())
	}
}
