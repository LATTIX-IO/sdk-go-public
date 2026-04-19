package sdk

import (
	"encoding/json"
	"testing"
)

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
		"capabilities": []byte(`{"service":"lattix-platform-api","status":"ready","auth_mode":"bearer_token","caller":{"tenant_id":"tenant-a","principal_id":"user-a","subject":"user-a","auth_source":"bearer_token","scopes":["platform-api.access"]},"default_required_scopes":["platform-api.access"],"routes":[]}`),
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

func TestExchangeSessionUsesRustBinding(t *testing.T) {
	binding := &fakeBinding{results: map[string][]byte{
		"exchange_session": []byte(`{"access_token":"session-token","token_type":"Bearer","expires_in":900,"scope":"platform-api.access","tenant_id":"tenant-a","client_id":"sdk-client","subject":"tenant:tenant-a:sdk-app:sdk-client"}`),
	}}

	client := newClientWithBinding(binding)
	response, err := client.ExchangeSession()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if binding.lastCall != "exchange_session" {
		t.Fatalf("expected exchange_session call, got %q", binding.lastCall)
	}
	if response.AccessToken != "session-token" {
		t.Fatalf("expected exchanged access token, got %q", response.AccessToken)
	}
	if response.ClientID != "sdk-client" {
		t.Fatalf("expected sdk-client, got %q", response.ClientID)
	}
}
