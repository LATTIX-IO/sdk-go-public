package sdk

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const integrationFullManifestPathEnv = "SDK_API_E2E_INTEGRATION_FULL_MANIFEST_PATH"

type integrationFullBinding struct {
	manifest *IntegrationFullManifest
	calls    []string
	payloads map[string][]map[string]any
}

func (b *integrationFullBinding) Call(method string, payload []byte) ([]byte, error) {
	b.calls = append(b.calls, method)
	if len(payload) != 0 {
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err == nil {
			if b.payloads == nil {
				b.payloads = make(map[string][]map[string]any)
			}
			b.payloads[method] = append(b.payloads[method], decoded)
		}
	}
	return b.response(method, payload), nil
}

func (b *integrationFullBinding) Close() error {
	b.calls = append(b.calls, "close")
	return nil
}

func (b *integrationFullBinding) response(method string, payload []byte) []byte {
	switch method {
	case "capabilities":
		return mustJSON(map[string]any{
			"service":                 "lattix-platform-api",
			"status":                  "ready",
			"auth_mode":               "bearer_token",
			"auth_configuration":      b.authConfiguration(),
			"caller":                  b.caller(),
			"default_required_scopes": b.manifest.DefaultRequiredScopes,
			"routes":                  []any{},
		})
	case "bootstrap":
		return mustJSON(map[string]any{
			"service":                     "lattix-platform-api",
			"status":                      "ready",
			"auth_mode":                   "bearer_token",
			"auth_configuration":          b.authConfiguration(),
			"caller":                      b.caller(),
			"enforcement_model":           "embedded_local_library",
			"plaintext_to_platform":       false,
			"policy_resolution_mode":      "metadata_only_control_plane",
			"supported_operations":        []string{"protect", "access", "rewrap"},
			"supported_artifact_profiles": []string{"tdf", "envelope", "detached_signature"},
			"platform_domains":            []map[string]any{{"domain": "policy", "configured": true, "reason": "metadata-only"}},
		})
	case "whoami":
		return mustJSON(map[string]any{
			"service": "lattix-platform-api",
			"status":  "ok",
			"caller":  b.caller(),
		})
	case "prepare_local_protection":
		request := requestProfile(payload)
		return mustJSON(map[string]any{
			"caller":            b.caller(),
			"content_binding":   b.contentBinding(),
			"artifact_binding":  b.artifactBinding(),
			"bootstrap":         b.bootstrapResponse(),
			"policy_resolution": b.policyResponse("protect"),
			"protection_plan":   b.protectionPlan(request),
		})
	case "generate_cid_binding":
		return mustJSON(b.artifactBinding())
	case "protection_plan":
		return mustJSON(b.protectionPlan(requestProfile(payload)))
	case "policy_resolve":
		return mustJSON(b.policyResponse(requestOperation(payload)))
	case "key_access_plan":
		return mustJSON(b.keyAccessPlan(requestOperation(payload), requestProfile(payload)))
	case "sign_bytes_with_detached_signature":
		artifactDigest := "sha256:artifact-detached"
		return mustJSON(map[string]any{
			"prepared": map[string]any{
				"caller":            b.caller(),
				"content_binding":   b.contentBinding(),
				"artifact_binding":  b.artifactBinding(),
				"bootstrap":         b.bootstrapResponse(),
				"policy_resolution": b.policyResponse("protect"),
				"protection_plan":   b.protectionPlan("detached_signature"),
			},
			"key_access_plan": b.keyAccessPlan("wrap", "detached_signature"),
			"artifact": map[string]any{
				"detached_signature": b.detachedSignatureArtifact(),
				"artifact_bytes_b64": base64.StdEncoding.EncodeToString([]byte(`{"artifact":"detached"}`)),
				"artifact_digest":    artifactDigest,
			},
			"artifact_registration": b.artifactRegister("detached_signature", artifactDigest),
			"evidence":              b.evidence("protect", "detached_signature"),
		})
	case "verify_bytes_with_detached_signature":
		return mustJSON(map[string]any{
			"artifact":          b.detachedSignatureArtifact(),
			"artifact_digest":   "sha256:artifact-detached",
			"policy_resolution": b.policyResponse("access"),
			"key_access_plan":   b.keyAccessPlan("unwrap", "detached_signature"),
			"content_binding":   b.contentBinding(),
			"evidence":          b.evidence("access", "detached_signature"),
		})
	case "protect_bytes_with_envelope":
		artifactDigest := "sha256:artifact-envelope"
		return mustJSON(map[string]any{
			"prepared": map[string]any{
				"caller":            b.caller(),
				"content_binding":   b.contentBinding(),
				"artifact_binding":  b.artifactBinding(),
				"bootstrap":         b.bootstrapResponse(),
				"policy_resolution": b.policyResponse("protect"),
				"protection_plan":   b.protectionPlan("envelope"),
			},
			"key_access_plan": b.keyAccessPlan("wrap", "envelope"),
			"artifact": map[string]any{
				"envelope":           b.envelopeArtifact(),
				"artifact_bytes_b64": base64.StdEncoding.EncodeToString([]byte(`{"artifact":"envelope"}`)),
				"artifact_digest":    artifactDigest,
			},
			"artifact_registration": b.artifactRegister("envelope", artifactDigest),
			"evidence":              b.evidence("protect", "envelope"),
		})
	case "access_bytes_with_envelope":
		return mustJSON(map[string]any{
			"artifact":          b.envelopeArtifact(),
			"artifact_digest":   "sha256:artifact-envelope",
			"policy_resolution": b.policyResponse("access"),
			"key_access_plan":   b.keyAccessPlan("unwrap", "envelope"),
			"plaintext_b64":     base64.StdEncoding.EncodeToString([]byte(b.manifest.PlaintextUTF8)),
			"evidence":          b.evidence("access", "envelope"),
		})
	case "rewrap_bytes_with_envelope":
		artifactDigest := "sha256:artifact-envelope-rewrapped"
		return mustJSON(map[string]any{
			"content_binding":          b.contentBinding(),
			"policy_resolution":        b.policyResponse("rewrap"),
			"protection_plan":          b.protectionPlan("envelope"),
			"key_access_plan":          b.keyAccessPlan("rewrap", "envelope"),
			"original_artifact_digest": "sha256:artifact-envelope",
			"artifact": map[string]any{
				"envelope":           b.envelopeArtifact(),
				"artifact_bytes_b64": base64.StdEncoding.EncodeToString([]byte(`{"artifact":"envelope-rewrapped"}`)),
				"artifact_digest":    artifactDigest,
			},
			"artifact_registration": b.artifactRegister("envelope", artifactDigest),
			"evidence":              b.evidence("rewrap", "envelope"),
		})
	case "protect_bytes_with_tdf":
		artifactDigest := "sha256:artifact-tdf"
		return mustJSON(map[string]any{
			"prepared": map[string]any{
				"caller":            b.caller(),
				"content_binding":   b.contentBinding(),
				"artifact_binding":  b.artifactBinding(),
				"bootstrap":         b.bootstrapResponse(),
				"policy_resolution": b.policyResponse("protect"),
				"protection_plan":   b.protectionPlan("tdf"),
			},
			"key_access_plan": b.keyAccessPlan("wrap", "tdf"),
			"artifact": map[string]any{
				"tdf":                b.tdfArtifact(),
				"artifact_bytes_b64": base64.StdEncoding.EncodeToString([]byte(`{"artifact":"tdf"}`)),
				"artifact_digest":    artifactDigest,
			},
			"artifact_registration": b.artifactRegister("tdf", artifactDigest),
			"evidence":              b.evidence("protect", "tdf"),
		})
	case "access_bytes_with_tdf":
		return mustJSON(map[string]any{
			"artifact": b.tdfArtifact(),
			"manifest": map[string]any{
				"workload":   b.manifest.Workload,
				"resource":   b.manifest.Resource,
				"purpose":    b.manifest.Purpose,
				"labels":     b.manifest.Labels,
				"attributes": b.manifest.Attributes,
			},
			"artifact_digest":   "sha256:artifact-tdf",
			"policy_resolution": b.policyResponse("access"),
			"key_access_plan":   b.keyAccessPlan("unwrap", "tdf"),
			"plaintext_b64":     base64.StdEncoding.EncodeToString([]byte(b.manifest.PlaintextUTF8)),
			"evidence":          b.evidence("access", "tdf"),
		})
	case "rewrap_bytes_with_tdf":
		artifactDigest := "sha256:artifact-tdf-rewrapped"
		return mustJSON(map[string]any{
			"content_binding": b.contentBinding(),
			"manifest": map[string]any{
				"workload":   b.manifest.Workload,
				"resource":   b.manifest.Resource,
				"purpose":    b.manifest.Purpose,
				"labels":     b.manifest.Labels,
				"attributes": b.manifest.Attributes,
			},
			"policy_resolution":        b.policyResponse("rewrap"),
			"protection_plan":          b.protectionPlan("tdf"),
			"key_access_plan":          b.keyAccessPlan("rewrap", "tdf"),
			"original_artifact_digest": "sha256:artifact-tdf",
			"artifact": map[string]any{
				"tdf":                b.tdfArtifact(),
				"artifact_bytes_b64": base64.StdEncoding.EncodeToString([]byte(`{"artifact":"tdf-rewrapped"}`)),
				"artifact_digest":    artifactDigest,
			},
			"artifact_registration": b.artifactRegister("tdf", artifactDigest),
			"evidence":              b.evidence("rewrap", "tdf"),
		})
	case "artifact_register":
		return mustJSON(b.artifactRegister(requestProfile(payload), requestArtifactDigest(payload)))
	case "evidence":
		return mustJSON(b.evidence(requestEventType(payload), requestProfile(payload)))
	default:
		return mustJSON(map[string]any{"status": "unexpected", "method": method})
	}
}

func (b *integrationFullBinding) authConfiguration() map[string]any {
	return map[string]any{
		"mode":                "oauth_client_credentials",
		"proof_of_possession": "mtls",
		"oidc_issuer":         "https://issuer.example",
		"oidc_audience":       "lattix-platform-api",
		"oidc_issuer_ready":   true,
		"mtls_ready":          true,
	}
}

func (b *integrationFullBinding) caller() map[string]any {
	return map[string]any{
		"tenant_id":    b.manifest.TenantID,
		"principal_id": b.manifest.PrincipalID,
		"subject":      b.manifest.Subject,
		"auth_source":  "bearer_token",
		"scopes":       b.manifest.DefaultRequiredScopes,
	}
}

func (b *integrationFullBinding) contentBinding() map[string]any {
	return map[string]any{
		"tenant_id":          b.manifest.TenantID,
		"content_digest":     b.manifest.ContentDigest,
		"content_size_bytes": len(b.manifest.PlaintextUTF8),
		"raw_cid":            b.manifest.ContentDigest,
	}
}

func (b *integrationFullBinding) artifactBinding() map[string]any {
	return map[string]any{
		"version":            1,
		"tenant_id":          b.manifest.TenantID,
		"raw_cid":            b.manifest.ContentDigest,
		"content_digest":     b.manifest.ContentDigest,
		"content_size_bytes": len(b.manifest.PlaintextUTF8),
		"workload":           b.manifest.Workload,
		"resource":           b.manifest.Resource,
		"purpose":            b.manifest.Purpose,
		"labels":             b.manifest.Labels,
		"attributes":         b.manifest.Attributes,
		"binding_targets":    []string{"artifact_digest", "content_digest"},
		"binding_hash":       "sha256:binding",
	}
}

func (b *integrationFullBinding) bootstrapResponse() map[string]any {
	return map[string]any{
		"service":                     "lattix-platform-api",
		"status":                      "ready",
		"auth_mode":                   "bearer_token",
		"auth_configuration":          b.authConfiguration(),
		"caller":                      b.caller(),
		"enforcement_model":           "embedded_local_library",
		"plaintext_to_platform":       false,
		"policy_resolution_mode":      "metadata_only_control_plane",
		"supported_operations":        []string{"protect", "access", "rewrap"},
		"supported_artifact_profiles": []string{"tdf", "envelope", "detached_signature"},
		"platform_domains":            []map[string]any{{"domain": "policy", "configured": true, "reason": "metadata-only"}},
	}
}

func (b *integrationFullBinding) policyResponse(operation string) map[string]any {
	return map[string]any{
		"service": "lattix-platform-api",
		"status":  "ready",
		"caller":  b.caller(),
		"request_summary": map[string]any{
			"operation":              operation,
			"workload_application":   b.manifest.Workload.Application,
			"workload_environment":   b.manifest.Workload.Environment,
			"workload_component":     b.manifest.Workload.Component,
			"resource_kind":          b.manifest.Resource.Kind,
			"resource_id":            b.manifest.Resource.ID,
			"mime_type":              b.manifest.Resource.MimeType,
			"content_digest_present": true,
			"content_size_bytes":     len(b.manifest.PlaintextUTF8),
			"purpose":                b.manifest.Purpose,
			"label_count":            len(b.manifest.Labels),
			"attribute_count":        len(b.manifest.Attributes),
		},
		"decision": map[string]any{
			"allow":            true,
			"enforcement_mode": "local_embedded_enforcement",
			"required_scopes":  []string{},
			"policy_inputs":    []string{},
			"required_actions": []string{},
		},
		"handling": map[string]any{
			"protect_locally":     true,
			"plaintext_transport": "forbidden_by_default",
			"bind_policy_to":      []string{"artifact_digest", "content_digest"},
			"evidence_expected":   []string{},
		},
		"platform_domains": []any{},
		"warnings":         []string{},
	}
}

func (b *integrationFullBinding) protectionPlan(artifactProfile string) map[string]any {
	return map[string]any{
		"service": "lattix-platform-api",
		"status":  "ready",
		"caller":  b.caller(),
		"request_summary": map[string]any{
			"operation":                  "protect",
			"workload_application":       b.manifest.Workload.Application,
			"workload_environment":       b.manifest.Workload.Environment,
			"workload_component":         b.manifest.Workload.Component,
			"resource_kind":              b.manifest.Resource.Kind,
			"resource_id":                b.manifest.Resource.ID,
			"mime_type":                  b.manifest.Resource.MimeType,
			"preferred_artifact_profile": artifactProfile,
			"content_digest_present":     true,
			"content_size_bytes":         len(b.manifest.PlaintextUTF8),
			"label_count":                len(b.manifest.Labels),
			"attribute_count":            len(b.manifest.Attributes),
			"purpose":                    b.manifest.Purpose,
		},
		"decision": map[string]any{
			"allow":               true,
			"required_scopes":     []string{},
			"handling_mode":       "local_embedded_enforcement",
			"plaintext_transport": "forbidden_by_default",
		},
		"execution": map[string]any{
			"protect_locally":            true,
			"local_enforcement_library":  "sdk_embedded_library",
			"send_plaintext_to_platform": false,
			"send_only":                  []string{"content digest"},
			"artifact_profile":           artifactProfile,
			"key_strategy":               "local",
			"policy_resolution":          "metadata_only",
		},
		"platform_domains": []any{},
		"warnings":         []string{},
	}
}

func (b *integrationFullBinding) keyAccessPlan(operation string, artifactProfile string) map[string]any {
	keyReferencePresent := artifactProfile == "tdf" || artifactProfile == "detached_signature" || artifactProfile == "envelope"
	var keyTransport any
	if artifactProfile == "tdf" || artifactProfile == "envelope" {
		keyTransport = map[string]any{
			"mode":                           "wrapped_key_reference",
			"key_material_origin":            "kms",
			"stable_key_reference_preferred": true,
			"raw_key_delivery_forbidden":     true,
		}
	}
	return map[string]any{
		"service": "lattix-platform-api",
		"status":  "ready",
		"caller":  b.caller(),
		"request_summary": map[string]any{
			"operation":              operation,
			"workload_application":   b.manifest.Workload.Application,
			"workload_environment":   b.manifest.Workload.Environment,
			"workload_component":     b.manifest.Workload.Component,
			"resource_kind":          b.manifest.Resource.Kind,
			"resource_id":            b.manifest.Resource.ID,
			"mime_type":              b.manifest.Resource.MimeType,
			"artifact_profile":       artifactProfile,
			"key_reference_present":  keyReferencePresent,
			"content_digest_present": true,
			"purpose":                b.manifest.Purpose,
			"label_count":            len(b.manifest.Labels),
			"attribute_count":        len(b.manifest.Attributes),
		},
		"decision": map[string]any{
			"allow":                 true,
			"required_scopes":       []string{},
			"operation":             operation,
			"key_reference_present": keyReferencePresent,
		},
		"execution": map[string]any{
			"local_cryptographic_operation": true,
			"platform_role":                 "authorize only",
			"send_plaintext_to_platform":    false,
			"send_only":                     []string{"content digest"},
			"artifact_profile":              artifactProfile,
			"authorization_strategy":        "metadata_only",
			"key_transport":                 keyTransport,
		},
		"platform_domains": []any{},
		"warnings":         []string{},
	}
}

func (b *integrationFullBinding) detachedSignatureArtifact() map[string]any {
	return map[string]any{
		"version":               1,
		"artifact_profile":      "detached_signature",
		"algorithm":             "ed25519",
		"tenant_id":             b.manifest.TenantID,
		"raw_cid":               b.manifest.ContentDigest,
		"content_digest":        b.manifest.ContentDigest,
		"content_size_bytes":    len(b.manifest.PlaintextUTF8),
		"workload":              b.manifest.Workload,
		"resource":              b.manifest.Resource,
		"signer_key_id":         "sha256:signing-key",
		"signer_public_key_b64": base64.StdEncoding.EncodeToString([]byte("public-key")),
		"binding_hash":          "sha256:binding",
		"signature_b64":         base64.StdEncoding.EncodeToString([]byte("signature")),
	}
}

func (b *integrationFullBinding) envelopeArtifact() map[string]any {
	return map[string]any{
		"version":            1,
		"artifact_profile":   "envelope",
		"algorithm":          "aes256_gcm",
		"tenant_id":          b.manifest.TenantID,
		"raw_cid":            b.manifest.ContentDigest,
		"content_digest":     b.manifest.ContentDigest,
		"content_size_bytes": len(b.manifest.PlaintextUTF8),
		"workload":           b.manifest.Workload,
		"resource":           b.manifest.Resource,
		"purpose":            b.manifest.Purpose,
		"labels":             b.manifest.Labels,
		"attributes":         b.manifest.Attributes,
		"binding_targets":    []string{"artifact_digest", "content_digest"},
		"binding_hash":       "sha256:binding",
		"nonce_b64":          base64.StdEncoding.EncodeToString([]byte("nonce")),
		"aad_hash":           "sha256:aad",
		"ciphertext_b64":     base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}
}

func (b *integrationFullBinding) tdfArtifact() map[string]any {
	return map[string]any{
		"version":            1,
		"meta_version":       1,
		"artifact_profile":   "tdf",
		"algorithm":          "aes256_gcm",
		"tenant_id":          b.manifest.TenantID,
		"raw_cid":            b.manifest.ContentDigest,
		"content_digest":     b.manifest.ContentDigest,
		"content_size_bytes": len(b.manifest.PlaintextUTF8),
		"manifest_digest":    "sha256:manifest",
		"binding_targets":    []string{"artifact_digest", "content_digest"},
		"binding_hash":       "sha256:binding",
		"policy_context": map[string]any{
			"workload":   b.manifest.Workload,
			"resource":   b.manifest.Resource,
			"purpose":    b.manifest.Purpose,
			"labels":     b.manifest.Labels,
			"attributes": b.manifest.Attributes,
		},
		"manifest_nonce_b64":      base64.StdEncoding.EncodeToString([]byte("nonce")),
		"manifest_ciphertext_b64": base64.StdEncoding.EncodeToString([]byte("manifest")),
		"payload_nonce_b64":       base64.StdEncoding.EncodeToString([]byte("nonce")),
		"payload_ciphertext_b64":  base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		"aad_hash":                "sha256:aad",
	}
}

func (b *integrationFullBinding) artifactRegister(artifactProfile string, artifactDigest string) map[string]any {
	return map[string]any{
		"service": "lattix-platform-api",
		"status":  "ready",
		"caller":  b.caller(),
		"request_summary": map[string]any{
			"operation":                "rewrap",
			"workload_application":     b.manifest.Workload.Application,
			"workload_environment":     b.manifest.Workload.Environment,
			"workload_component":       b.manifest.Workload.Component,
			"resource_kind":            b.manifest.Resource.Kind,
			"resource_id":              b.manifest.Resource.ID,
			"mime_type":                b.manifest.Resource.MimeType,
			"artifact_profile":         artifactProfile,
			"artifact_digest":          artifactDigest,
			"artifact_locator_present": false,
			"decision_id_present":      false,
			"key_reference_present":    artifactProfile == "tdf",
			"purpose":                  b.manifest.Purpose,
			"label_count":              len(b.manifest.Labels),
			"attribute_count":          len(b.manifest.Attributes),
		},
		"registration": map[string]any{
			"accepted":                   true,
			"required_scopes":            []string{},
			"artifact_transport":         "metadata_only",
			"send_plaintext_to_platform": false,
			"catalog_actions":            []string{},
			"evidence_expected":          []string{},
		},
		"platform_domains": []any{},
		"warnings":         []string{},
	}
}

func (b *integrationFullBinding) evidence(eventType string, artifactProfile string) map[string]any {
	return map[string]any{
		"service": "lattix-platform-api",
		"status":  "ready",
		"caller":  b.caller(),
		"request_summary": map[string]any{
			"event_type":              eventType,
			"workload_application":    b.manifest.Workload.Application,
			"workload_environment":    b.manifest.Workload.Environment,
			"workload_component":      b.manifest.Workload.Component,
			"resource_kind":           b.manifest.Resource.Kind,
			"resource_id":             b.manifest.Resource.ID,
			"mime_type":               b.manifest.Resource.MimeType,
			"artifact_profile":        artifactProfile,
			"artifact_digest_present": true,
			"decision_id_present":     false,
			"outcome":                 "success",
			"occurred_at":             nil,
			"purpose":                 b.manifest.Purpose,
			"label_count":             len(b.manifest.Labels),
			"attribute_count":         len(b.manifest.Attributes),
		},
		"ingestion": map[string]any{
			"accepted":            true,
			"required_scopes":     []string{},
			"plaintext_transport": "forbidden_by_default",
			"send_only":           []string{},
			"correlate_by":        []string{},
		},
		"platform_domains": []any{},
		"warnings":         []string{},
	}
}

func requestOperation(payload []byte) string {
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "protect"
	}
	if value, ok := decoded["operation"].(string); ok && value != "" {
		return value
	}
	return "protect"
}

func requestProfile(payload []byte) string {
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "tdf"
	}
	if value, ok := decoded["preferred_artifact_profile"].(string); ok && value != "" {
		return value
	}
	if value, ok := decoded["artifact_profile"].(string); ok && value != "" {
		return value
	}
	return "tdf"
}

func requestArtifactDigest(payload []byte) string {
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "sha256:artifact-tdf-rewrapped"
	}
	if value, ok := decoded["artifact_digest"].(string); ok && value != "" {
		return value
	}
	return "sha256:artifact-tdf-rewrapped"
}

func requestEventType(payload []byte) string {
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "rewrap"
	}
	if value, ok := decoded["event_type"].(string); ok && value != "" {
		return value
	}
	return "rewrap"
}

func mustJSON(value any) []byte {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return body
}

func TestLoadIntegrationFullManifest(t *testing.T) {
	manifestPath := integrationFullManifestPath(t)
	manifest, err := LoadIntegrationFullManifest(manifestPath)
	if err != nil {
		t.Fatalf("expected manifest to load, got %v", err)
	}
	if manifest.Name != "integration-full" {
		t.Fatalf("expected integration-full manifest, got %q", manifest.Name)
	}
	if len(manifest.Steps) != 15 {
		t.Fatalf("expected 15 manifest steps, got %d", len(manifest.Steps))
	}
}

func TestRunIntegrationFullScenarioWithClient(t *testing.T) {
	manifestPath := integrationFullManifestPath(t)
	manifest, err := LoadIntegrationFullManifest(manifestPath)
	if err != nil {
		t.Fatalf("expected manifest to load, got %v", err)
	}
	binding := &integrationFullBinding{manifest: manifest}
	client := newClientWithBinding(binding)
	summary, err := RunIntegrationFullScenarioWithClient(client, manifest)
	if err != nil {
		t.Fatalf("expected scenario runner success, got %v", err)
	}

	if summary.Runner != "sdk-go" {
		t.Fatalf("expected sdk-go runner, got %q", summary.Runner)
	}
	if len(summary.Steps) != 15 {
		t.Fatalf("expected 15 steps, got %d", len(summary.Steps))
	}
	if got := summary.Steps[8]["name"]; got != "detached_signature_round_trip" {
		t.Fatalf("expected detached signature step at index 8, got %v", got)
	}
	if got := summary.Steps[12]["name"]; got != "tdf_rewrap" {
		t.Fatalf("expected tdf_rewrap step at index 12, got %v", got)
	}
	if accepted, ok := summary.Steps[13]["accepted"].(bool); !ok || !accepted {
		t.Fatalf("expected direct artifact register acceptance, got %#v", summary.Steps[13]["accepted"])
	}
	if accepted, ok := summary.Steps[14]["accepted"].(bool); !ok || !accepted {
		t.Fatalf("expected direct evidence acceptance, got %#v", summary.Steps[14]["accepted"])
	}
	if binding.calls[0] != "capabilities" {
		t.Fatalf("expected first call to be capabilities, got %q", binding.calls[0])
	}
	if binding.calls[len(binding.calls)-1] == "close" {
		t.Fatalf("runner should not close external client")
	}

	protectEnvelopePayload := binding.payloads["protect_bytes_with_envelope"][0]
	if _, ok := protectEnvelopePayload["key_b64"]; ok {
		t.Fatalf("expected managed envelope protect payload, got inline key payload %#v", protectEnvelopePayload)
	}
	protectKeySource, ok := protectEnvelopePayload["key_source"].(map[string]any)
	if !ok {
		t.Fatalf("expected managed envelope protect key_source payload, got %#v", protectEnvelopePayload)
	}
	if got := protectKeySource["kind"]; got != string(LocalSymmetricKeySourceKindManagedReference) {
		t.Fatalf("expected managed envelope protect key source, got %#v", protectKeySource)
	}
	if got := protectKeySource["key_reference"]; got != manifest.ManagedKeyReference {
		t.Fatalf("expected managed envelope protect key reference %q, got %#v", manifest.ManagedKeyReference, got)
	}

	accessEnvelopePayload := binding.payloads["access_bytes_with_envelope"][0]
	if _, ok := accessEnvelopePayload["key_b64"]; ok {
		t.Fatalf("expected managed envelope access payload, got inline key payload %#v", accessEnvelopePayload)
	}
	accessKeySource, ok := accessEnvelopePayload["key_source"].(map[string]any)
	if !ok {
		t.Fatalf("expected managed envelope access key_source payload, got %#v", accessEnvelopePayload)
	}
	if got := accessKeySource["key_reference"]; got != manifest.ManagedKeyReference {
		t.Fatalf("expected managed envelope access key reference %q, got %#v", manifest.ManagedKeyReference, got)
	}

	rewrapEnvelopePayload := binding.payloads["rewrap_bytes_with_envelope"][0]
	if _, ok := rewrapEnvelopePayload["current_key_b64"]; ok {
		t.Fatalf("expected managed envelope rewrap payload, got inline key payload %#v", rewrapEnvelopePayload)
	}
	currentKeySource, ok := rewrapEnvelopePayload["current_key_source"].(map[string]any)
	if !ok {
		t.Fatalf("expected managed envelope current_key_source payload, got %#v", rewrapEnvelopePayload)
	}
	if got := currentKeySource["key_reference"]; got != manifest.ManagedKeyReference {
		t.Fatalf("expected managed envelope current key reference %q, got %#v", manifest.ManagedKeyReference, got)
	}
	newKeySource, ok := rewrapEnvelopePayload["new_key_source"].(map[string]any)
	if !ok {
		t.Fatalf("expected managed envelope new_key_source payload, got %#v", rewrapEnvelopePayload)
	}
	if got := newKeySource["key_reference"]; got != manifest.ManagedRewrapKeyReference {
		t.Fatalf("expected managed envelope rewrap key reference %q, got %#v", manifest.ManagedRewrapKeyReference, got)
	}
}

func integrationFullManifestPath(t *testing.T) string {
	t.Helper()

	if configured := strings.TrimSpace(os.Getenv(integrationFullManifestPathEnv)); configured != "" {
		return configured
	}

	candidates := []string{
		filepath.Join("..", "prop-system-tests", "fixtures", "sdk_api_e2e", "integration_full_manifest.json"),
		filepath.Join("prop-system-tests", "fixtures", "sdk_api_e2e", "integration_full_manifest.json"),
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	t.Fatalf("integration-full manifest not found; set %s", integrationFullManifestPathEnv)
	return ""
}
