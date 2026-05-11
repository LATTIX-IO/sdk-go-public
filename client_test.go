package sdk

import (
	"encoding/json"
	"testing"
)

func TestCommandManagedKeyProviderConfigMarshalsForRustBinding(t *testing.T) {
	options := Options{
		BaseURL: "https://api.example.com",
		ManagedSymmetricKeyProviders: []ManagedSymmetricKeyProviderConfig{
			NewCommandManagedKeyProviderConfig(
				"command-kms",
				"provider.exe",
				[]string{"--stdio"},
				map[string]string{"LATTIX_PROFILE": "test"},
				KeyTransportModeWrappedKeyReference,
			),
		},
	}

	encoded, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("expected command provider config to marshal, got %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	providers, ok := payload["managed_symmetric_key_providers"].([]any)
	if !ok || len(providers) != 1 {
		t.Fatalf("expected one managed provider in payload, got %#v", payload["managed_symmetric_key_providers"])
	}
	provider, ok := providers[0].(map[string]any)
	if !ok {
		t.Fatalf("expected provider object payload, got %#v", providers[0])
	}
	if provider["kind"] != "command" || provider["name"] != "command-kms" || provider["command"] != "provider.exe" {
		t.Fatalf("expected command provider fields to round-trip, got %#v", provider)
	}
	args, ok := provider["args"].([]any)
	if !ok || len(args) != 1 || args[0] != "--stdio" {
		t.Fatalf("expected command args to round-trip, got %#v", provider["args"])
	}
	env, ok := provider["env"].(map[string]any)
	if !ok || env["LATTIX_PROFILE"] != "test" {
		t.Fatalf("expected command env to round-trip, got %#v", provider["env"])
	}
}

type fakeBinding struct {
	closed   bool
	lastCall string
	payloads map[string][]byte
	results  map[string][]byte
	err      error
}

func (f *fakeBinding) Call(method string, payload []byte) ([]byte, error) {
	f.lastCall = method
	if f.payloads == nil {
		f.payloads = map[string][]byte{}
	}
	f.payloads[method] = payload
	if f.err != nil {
		return nil, f.err
	}
	return f.results[method], nil
}

func (f *fakeBinding) Close() error {
	f.closed = true
	return nil
}

func TestCapabilitiesUsesRustBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"capabilities": []byte(`{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","auth_configuration":{"mode":"oauth_client_credentials","proof_of_possession":"mtls","oidc_issuer":"https://issuer.example","oidc_audience":"lattix-platform-api","oidc_issuer_ready":true,"mtls_ready":true},"caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"default_required_scopes":["platform-api.access"],"routes":[]}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.Capabilities()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if binding.lastCall != "capabilities" {
		t.Fatalf("expected capabilities call, got %q", binding.lastCall)
	}
	if response.Caller.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", response.Caller.TenantID)
	}
	if response.AuthConfiguration.Mode != SdkAuthConfigurationModeOAuthClientCredentials {
		t.Fatalf("expected oauth client credentials mode, got %q", response.AuthConfiguration.Mode)
	}
}

func TestProtectionPlanMarshalsRequestForRustBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"protection_plan": []byte(`{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"tdf","content_digest_present":true,"label_count":1,"attribute_count":1},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library_or_local_sidecar","send_plaintext_to_platform":false,"send_only":["content digest"],"artifact_profile":"tdf","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}`),
	}}

	client := newClientWithBinding(binding)
	_, err := client.ProtectionPlan(SdkProtectionPlanRequest{
		Operation:                ProtectionOperationProtect,
		Workload:                 WorkloadDescriptor{Application: "example-app"},
		Resource:                 ResourceDescriptor{Kind: "document"},
		PreferredArtifactProfile: ArtifactProfileTDF,
		ContentDigest:            "sha256:abc123",
		Labels:                   []string{"confidential"},
		Attributes:               map[string]string{"region": "us"},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["protection_plan"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["operation"] != "protect" {
		t.Fatalf("expected protect operation, got %#v", payload["operation"])
	}
	if payload["content_digest"] != "sha256:abc123" {
		t.Fatalf("expected digest to round-trip")
	}
}

func TestCloseDelegatesToBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{}}
	client := newClientWithBinding(binding)

	if err := client.Close(); err != nil {
		t.Fatalf("expected close success, got %v", err)
	}
	if !binding.closed {
		t.Fatalf("expected binding to be closed")
	}
}

func TestPrepareLocalProtectionUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"prepare_local_protection": []byte(`{
			"caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},
			"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},
			"artifact_binding":{"version":1,"tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"workload":{"application":"example-app"},"resource":{"kind":"document"},"binding_targets":["artifact_digest","content_digest"],"binding_hash":"sha256:binding"},
			"bootstrap":{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","auth_configuration":{"mode":"oauth_client_credentials","proof_of_possession":"mtls","oidc_issuer":"https://issuer.example","oidc_audience":"lattix-platform-api","oidc_issuer_ready":true,"mtls_ready":true},"caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"enforcement_model":"embedded_local_library","plaintext_to_platform":false,"policy_resolution_mode":"metadata_only_control_plane","supported_operations":["protect"],"supported_artifact_profiles":["envelope"],"platform_domains":[]},
			"policy_resolution":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]},
			"protection_plan":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"envelope","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"envelope","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}
		}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.PrepareLocalProtection([]byte("hello world"), LocalProtectionRequest{
		Workload: WorkloadDescriptor{Application: "example-app"},
		Resource: ResourceDescriptor{Kind: "document"},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if binding.lastCall != "prepare_local_protection" {
		t.Fatalf("expected prepare_local_protection call, got %q", binding.lastCall)
	}
	if response.ContentBinding.ContentDigest != "sha256:abc123" {
		t.Fatalf("expected digest to round-trip, got %q", response.ContentBinding.ContentDigest)
	}
	if response.ArtifactBinding.BindingHash != "sha256:binding" {
		t.Fatalf("expected binding hash to round-trip, got %q", response.ArtifactBinding.BindingHash)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["prepare_local_protection"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["content_b64"] == "" {
		t.Fatalf("expected content to be base64 encoded")
	}
}

func TestGenerateCIDBindingUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"generate_cid_binding": []byte(`{"version":1,"tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"workload":{"application":"example-app"},"resource":{"kind":"document"},"binding_targets":["artifact_digest","content_digest"],"binding_hash":"sha256:binding"}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.GenerateCIDBinding([]byte("hello world"), LocalProtectionRequest{
		Workload: WorkloadDescriptor{Application: "example-app"},
		Resource: ResourceDescriptor{Kind: "document"},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if binding.lastCall != "generate_cid_binding" {
		t.Fatalf("expected generate_cid_binding call, got %q", binding.lastCall)
	}
	if response.BindingHash != "sha256:binding" {
		t.Fatalf("expected binding hash, got %q", response.BindingHash)
	}
	if len(response.BindingTargets) != 2 {
		t.Fatalf("expected binding targets to round-trip, got %#v", response.BindingTargets)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["generate_cid_binding"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["content_b64"] == "" {
		t.Fatalf("expected content to be base64 encoded")
	}
}

func TestSignBytesWithDetachedSignatureUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"sign_bytes_with_detached_signature": []byte(`{"prepared":{"caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"bootstrap":{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"enforcement_model":"embedded_local_library","plaintext_to_platform":false,"policy_resolution_mode":"metadata_only_control_plane","supported_operations":["protect"],"supported_artifact_profiles":["detached_signature"],"platform_domains":[]},"policy_resolution":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]},"protection_plan":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"detached_signature","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"detached_signature","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}},"key_access_plan":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"detached_signature","key_reference_present":true,"content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"operation":"wrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"detached_signature","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]},"artifact":{"detached_signature":{"version":1,"artifact_profile":"detached_signature","algorithm":"ed25519","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"workload":{"application":"example-app"},"resource":{"kind":"document"},"signer_key_id":"sha256:key","signer_public_key_b64":"cHVia2V5","binding_hash":"sha256:binding","signature_b64":"c2ln"},"artifact_bytes_b64":"eyJzaWduYXR1cmUiOiJ0ZXN0In0=","artifact_digest":"sha256:artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.SignBytesWithDetachedSignature([]byte("01234567890123456789012345678901"), []byte("hello world"), LocalProtectionRequest{Workload: WorkloadDescriptor{Application: "example-app"}, Resource: ResourceDescriptor{Kind: "document"}})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if binding.lastCall != "sign_bytes_with_detached_signature" {
		t.Fatalf("expected sign_bytes_with_detached_signature call, got %q", binding.lastCall)
	}
	if response.Artifact.ArtifactDigest != "sha256:artifact" {
		t.Fatalf("expected artifact digest, got %q", response.Artifact.ArtifactDigest)
	}
	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["sign_bytes_with_detached_signature"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["signing_key_b64"] == "" || payload["content_b64"] == "" {
		t.Fatalf("expected signing key and content to be base64 encoded")
	}
}

func TestVerifyBytesWithDetachedSignatureUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"verify_bytes_with_detached_signature": []byte(`{"artifact":{"version":1,"artifact_profile":"detached_signature","algorithm":"ed25519","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"workload":{"application":"example-app"},"resource":{"kind":"document"},"signer_key_id":"sha256:key","signer_public_key_b64":"cHVia2V5","binding_hash":"sha256:binding","signature_b64":"c2ln"},"artifact_digest":"sha256:artifact","policy_resolution":{},"key_access_plan":{},"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.VerifyBytesWithDetachedSignature([]byte("01234567890123456789012345678901"), []byte("hello world"), []byte(`{"artifact":"bytes"}`))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if binding.lastCall != "verify_bytes_with_detached_signature" {
		t.Fatalf("expected verify_bytes_with_detached_signature call, got %q", binding.lastCall)
	}
	if response.ArtifactDigest != "sha256:artifact" {
		t.Fatalf("expected artifact digest, got %q", response.ArtifactDigest)
	}
	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["verify_bytes_with_detached_signature"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["verifying_key_b64"] == "" || payload["content_b64"] == "" || payload["artifact_bytes_b64"] == "" {
		t.Fatalf("expected verifying key, content, and artifact bytes to be base64 encoded")
	}
}

func TestProtectBytesWithTDFUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"protect_bytes_with_tdf": []byte(`{"prepared":{"caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"bootstrap":{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"enforcement_model":"embedded_local_library","plaintext_to_platform":false,"policy_resolution_mode":"metadata_only_control_plane","supported_operations":["protect"],"supported_artifact_profiles":["tdf"],"platform_domains":[]},"policy_resolution":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"enforcement_mode":"local_embedded_enforcement","required_scopes":[],"policy_inputs":[],"required_actions":[]},"handling":{"protect_locally":true,"plaintext_transport":"forbidden_by_default","bind_policy_to":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]},"protection_plan":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","preferred_artifact_profile":"tdf","content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"handling_mode":"local_embedded_enforcement","plaintext_transport":"forbidden_by_default"},"execution":{"protect_locally":true,"local_enforcement_library":"sdk_embedded_library","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","key_strategy":"local","policy_resolution":"metadata_only"},"platform_domains":[],"warnings":[]}},"key_access_plan":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"wrap","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","key_reference_present":true,"content_digest_present":true,"label_count":0,"attribute_count":0},"decision":{"allow":true,"required_scopes":[],"operation":"wrap","key_reference_present":true},"execution":{"local_cryptographic_operation":true,"platform_role":"authorize_only","send_plaintext_to_platform":false,"send_only":[],"artifact_profile":"tdf","authorization_strategy":"metadata_only"},"platform_domains":[],"warnings":[]},"artifact":{"tdf":{"version":1,"artifact_profile":"tdf","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"manifest_digest":"sha256:manifest","manifest_nonce_b64":"bm9uY2UxMjM0NTY3OA==","manifest_ciphertext_b64":"bWFuaWZlc3QtY3Q=","payload_nonce_b64":"bm9uY2UxMjM0NTY3OA==","payload_ciphertext_b64":"cGF5bG9hZC1jdA==","aad_hash":"sha256:aad"},"artifact_bytes_b64":"eyJ0ZGYiOiJ0ZXN0In0=","artifact_digest":"sha256:artifact"},"artifact_registration":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"operation":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest":"sha256:artifact","artifact_locator_present":false,"decision_id_present":false,"key_reference_present":true,"label_count":0,"attribute_count":0},"registration":{"accepted":true,"required_scopes":[],"artifact_transport":"metadata_only","send_plaintext_to_platform":false,"catalog_actions":[],"evidence_expected":[]},"platform_domains":[],"warnings":[]},"evidence":{"service":"lattix-platform-api","status":"ready","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":[]},"request_summary":{"event_type":"protect","workload_application":"example-app","resource_kind":"document","artifact_profile":"tdf","artifact_digest_present":true,"decision_id_present":false,"label_count":0,"attribute_count":0},"ingestion":{"accepted":true,"required_scopes":[],"plaintext_transport":"forbidden_by_default","send_only":[],"correlate_by":[]},"platform_domains":[],"warnings":[]}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.ProtectBytesWithTDF([]byte("01234567890123456789012345678901"), []byte("hello world"), LocalProtectionRequest{Workload: WorkloadDescriptor{Application: "example-app"}, Resource: ResourceDescriptor{Kind: "document"}})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if binding.lastCall != "protect_bytes_with_tdf" {
		t.Fatalf("expected protect_bytes_with_tdf call, got %q", binding.lastCall)
	}
	if response.Artifact.ArtifactDigest != "sha256:artifact" {
		t.Fatalf("expected artifact digest, got %q", response.Artifact.ArtifactDigest)
	}
	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["protect_bytes_with_tdf"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["plaintext_b64"] == "" || payload["key_b64"] == "" {
		t.Fatalf("expected plaintext and key to be base64 encoded")
	}
}

func TestProtectBytesWithEnvelopeUsingKeySourceUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"protect_bytes_with_envelope": []byte(`{"prepared":{},"key_access_plan":{},"artifact":{"envelope":{"version":1,"artifact_profile":"envelope","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"workload":{"application":"example-app"},"resource":{"kind":"document"},"nonce_b64":"bm9uY2UxMjM0NTY3OA==","aad_hash":"sha256:aad","ciphertext_b64":"Y3Q="},"artifact_bytes_b64":"eyJlbnZlbG9wZSI6InRlc3QifQ==","artifact_digest":"sha256:new-artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.ProtectBytesWithEnvelopeUsingKeySource(
		ManagedReferenceKeySourceWithProvider("memory", "tenant-key-01"),
		[]byte("hello world"),
		LocalProtectionRequest{Workload: WorkloadDescriptor{Application: "example-app"}, Resource: ResourceDescriptor{Kind: "document"}},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if response.Artifact.ArtifactDigest != "sha256:new-artifact" {
		t.Fatalf("expected artifact digest, got %q", response.Artifact.ArtifactDigest)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["protect_bytes_with_envelope"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	keySource, ok := payload["key_source"].(map[string]any)
	if !ok {
		t.Fatalf("expected key_source payload, got %#v", payload["key_source"])
	}
	if keySource["kind"] != "managed_reference" || keySource["provider_name"] != "memory" || keySource["key_reference"] != "tenant-key-01" {
		t.Fatalf("expected managed key source fields to round-trip, got %#v", keySource)
	}
	if _, exists := payload["key_b64"]; exists {
		t.Fatalf("expected structured key_source payload, not legacy key_b64")
	}
}

func TestRewrapBytesWithEnvelopeUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"rewrap_bytes_with_envelope": []byte(`{"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"policy_resolution":{},"protection_plan":{},"key_access_plan":{},"original_artifact_digest":"sha256:old-artifact","artifact":{"envelope":{"version":1,"artifact_profile":"envelope","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"workload":{"application":"example-app"},"resource":{"kind":"document"},"nonce_b64":"bm9uY2UxMjM0NTY3OA==","aad_hash":"sha256:aad","ciphertext_b64":"Y3Q="},"artifact_bytes_b64":"eyJlbnZlbG9wZSI6InRlc3QifQ==","artifact_digest":"sha256:new-artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.RewrapBytesWithEnvelope([]byte("01234567890123456789012345678901"), []byte("12345678901234567890123456789012"), []byte(`{"artifact":"bytes"}`))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if binding.lastCall != "rewrap_bytes_with_envelope" {
		t.Fatalf("expected rewrap_bytes_with_envelope call, got %q", binding.lastCall)
	}
	if response.Artifact.ArtifactDigest != "sha256:new-artifact" {
		t.Fatalf("expected artifact digest, got %q", response.Artifact.ArtifactDigest)
	}
	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["rewrap_bytes_with_envelope"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["current_key_b64"] == "" || payload["new_key_b64"] == "" || payload["artifact_bytes_b64"] == "" {
		t.Fatalf("expected keys and artifact bytes to be base64 encoded")
	}
}

func TestRewrapBytesWithEnvelopeUsingKeySourcesUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"rewrap_bytes_with_envelope": []byte(`{"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"policy_resolution":{},"protection_plan":{},"key_access_plan":{},"original_artifact_digest":"sha256:old-artifact","artifact":{"envelope":{"version":1,"artifact_profile":"envelope","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"workload":{"application":"example-app"},"resource":{"kind":"document"},"nonce_b64":"bm9uY2UxMjM0NTY3OA==","aad_hash":"sha256:aad","ciphertext_b64":"Y3Q="},"artifact_bytes_b64":"eyJlbnZlbG9wZSI6InRlc3QifQ==","artifact_digest":"sha256:new-artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	_, err := client.RewrapBytesWithEnvelopeUsingKeySources(
		ManagedReferenceKeySourceWithProvider("memory", "tenant-key-01"),
		ManagedReferenceKeySourceWithProvider("memory", "tenant-key-02"),
		[]byte(`{"artifact":"bytes"}`),
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["rewrap_bytes_with_envelope"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	currentSource, ok := payload["current_key_source"].(map[string]any)
	if !ok || currentSource["key_reference"] != "tenant-key-01" {
		t.Fatalf("expected current key source to round-trip, got %#v", payload["current_key_source"])
	}
	newSource, ok := payload["new_key_source"].(map[string]any)
	if !ok || newSource["key_reference"] != "tenant-key-02" {
		t.Fatalf("expected new key source to round-trip, got %#v", payload["new_key_source"])
	}
}

func TestProtectBytesWithTDFUsingKeySourceUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"protect_bytes_with_tdf": []byte(`{"prepared":{},"key_access_plan":{},"artifact":{"tdf":{"version":1,"meta_version":1,"artifact_profile":"tdf","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"manifest_digest":"sha256:manifest","manifest_nonce_b64":"bm9uY2UxMjM0NTY3OA==","manifest_ciphertext_b64":"bWFuaWZlc3QtY3Q=","payload_nonce_b64":"bm9uY2UxMjM0NTY3OA==","payload_ciphertext_b64":"cGF5bG9hZC1jdA==","aad_hash":"sha256:aad"},"artifact_bytes_b64":"eyJ0ZGYiOiJ0ZXN0In0=","artifact_digest":"sha256:artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	_, err := client.ProtectBytesWithTDFUsingKeySource(
		ManagedReferenceKeySource("tenant-key-tdf"),
		[]byte("hello world"),
		LocalProtectionRequest{Workload: WorkloadDescriptor{Application: "example-app"}, Resource: ResourceDescriptor{Kind: "document"}},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["protect_bytes_with_tdf"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	keySource, ok := payload["key_source"].(map[string]any)
	if !ok || keySource["kind"] != "managed_reference" || keySource["key_reference"] != "tenant-key-tdf" {
		t.Fatalf("expected managed TDF key source payload, got %#v", payload["key_source"])
	}
}

func TestRewrapBytesWithTDFUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"rewrap_bytes_with_tdf": []byte(`{"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"manifest":{"workload":{"application":"example-app"},"resource":{"kind":"document"}},"policy_resolution":{},"protection_plan":{},"key_access_plan":{},"original_artifact_digest":"sha256:old-artifact","artifact":{"tdf":{"version":1,"meta_version":1,"artifact_profile":"tdf","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"manifest_digest":"sha256:manifest","manifest_nonce_b64":"bm9uY2UxMjM0NTY3OA==","manifest_ciphertext_b64":"bWFuaWZlc3QtY3Q=","payload_nonce_b64":"bm9uY2UxMjM0NTY3OA==","payload_ciphertext_b64":"cGF5bG9hZC1jdA==","aad_hash":"sha256:aad"},"artifact_bytes_b64":"eyJ0ZGYiOiJ0ZXN0In0=","artifact_digest":"sha256:new-artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.RewrapBytesWithTDF([]byte("01234567890123456789012345678901"), []byte("12345678901234567890123456789012"), []byte(`{"artifact":"bytes"}`))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if binding.lastCall != "rewrap_bytes_with_tdf" {
		t.Fatalf("expected rewrap_bytes_with_tdf call, got %q", binding.lastCall)
	}
	if response.Artifact.ArtifactDigest != "sha256:new-artifact" {
		t.Fatalf("expected artifact digest, got %q", response.Artifact.ArtifactDigest)
	}
	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["rewrap_bytes_with_tdf"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["current_key_b64"] == "" || payload["new_key_b64"] == "" || payload["artifact_bytes_b64"] == "" {
		t.Fatalf("expected keys and artifact bytes to be base64 encoded")
	}
}

func TestSetTDFAttributesUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"set_tdf_attributes": []byte(`{"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"manifest":{"workload":{"application":"example-app"},"resource":{"kind":"document"},"attributes":{"project":"atlas","region":"eu"}},"policy_resolution":{},"protection_plan":{},"key_access_plan":{},"original_artifact_digest":"sha256:old-artifact","artifact":{"tdf":{"version":1,"meta_version":2,"artifact_profile":"tdf","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"manifest_digest":"sha256:manifest","manifest_nonce_b64":"bm9uY2UxMjM0NTY3OA==","manifest_ciphertext_b64":"bWFuaWZlc3QtY3Q=","payload_nonce_b64":"bm9uY2UxMjM0NTY3OA==","payload_ciphertext_b64":"cGF5bG9hZC1jdA==","aad_hash":"sha256:aad"},"artifact_bytes_b64":"eyJ0ZGYiOiJ0ZXN0In0=","artifact_digest":"sha256:new-artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.SetTDFAttributes(
		[]byte("01234567890123456789012345678901"),
		[]byte(`{"artifact":"bytes"}`),
		map[string]string{"project": "atlas", "region": "eu"},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if binding.lastCall != "set_tdf_attributes" {
		t.Fatalf("expected set_tdf_attributes call, got %q", binding.lastCall)
	}
	if response.Artifact.TDF.MetaVersion != 2 {
		t.Fatalf("expected meta version 2, got %d", response.Artifact.TDF.MetaVersion)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["set_tdf_attributes"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	if payload["key_b64"] == "" || payload["artifact_bytes_b64"] == "" {
		t.Fatalf("expected key and artifact bytes to be base64 encoded")
	}
	attributes, ok := payload["attributes"].(map[string]any)
	if !ok || attributes["project"] != "atlas" || attributes["region"] != "eu" {
		t.Fatalf("expected attributes to round-trip, got %#v", payload["attributes"])
	}
}

func TestEditTDFAttributesUsesBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"edit_tdf_attributes": []byte(`{"content_binding":{"tenant_id":"tenant-a","content_digest":"sha256:abc123","content_size_bytes":11,"raw_cid":"sha256:abc123"},"manifest":{"workload":{"application":"example-app"},"resource":{"kind":"document"},"attributes":{"region":"eu"}},"policy_resolution":{},"protection_plan":{},"key_access_plan":{},"original_artifact_digest":"sha256:old-artifact","artifact":{"tdf":{"version":1,"meta_version":3,"artifact_profile":"tdf","algorithm":"aes256_gcm","tenant_id":"tenant-a","raw_cid":"sha256:abc123","content_digest":"sha256:abc123","content_size_bytes":11,"manifest_digest":"sha256:manifest","manifest_nonce_b64":"bm9uY2UxMjM0NTY3OA==","manifest_ciphertext_b64":"bWFuaWZlc3QtY3Q=","payload_nonce_b64":"bm9uY2UxMjM0NTY3OA==","payload_ciphertext_b64":"cGF5bG9hZC1jdA==","aad_hash":"sha256:aad"},"artifact_bytes_b64":"eyJ0ZGYiOiJ0ZXN0In0=","artifact_digest":"sha256:newer-artifact"},"artifact_registration":{},"evidence":{}}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.EditTDFAttributes(
		[]byte("01234567890123456789012345678901"),
		[]byte(`{"artifact":"bytes"}`),
		LocalAttributeEdit{Set: map[string]string{"region": "eu"}, Remove: []string{"legacy"}},
	)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if binding.lastCall != "edit_tdf_attributes" {
		t.Fatalf("expected edit_tdf_attributes call, got %q", binding.lastCall)
	}
	if response.Artifact.TDF.MetaVersion != 3 {
		t.Fatalf("expected meta version 3, got %d", response.Artifact.TDF.MetaVersion)
	}

	var payload map[string]any
	if err := json.Unmarshal(binding.payloads["edit_tdf_attributes"], &payload); err != nil {
		t.Fatalf("expected JSON payload, got %v", err)
	}
	edit, ok := payload["edit"].(map[string]any)
	if !ok {
		t.Fatalf("expected edit payload, got %#v", payload["edit"])
	}
	set, ok := edit["set"].(map[string]any)
	if !ok || set["region"] != "eu" {
		t.Fatalf("expected set map to round-trip, got %#v", edit["set"])
	}
	remove, ok := edit["remove"].([]any)
	if !ok || len(remove) != 1 || remove[0] != "legacy" {
		t.Fatalf("expected remove list to round-trip, got %#v", edit["remove"])
	}
}
