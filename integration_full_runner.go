package sdk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type IntegrationFullScenarioStep struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	SDKMethods  []string `json:"sdk_methods"`
}

type IntegrationFullManifest struct {
	Name                      string                        `json:"name"`
	Version                   int                           `json:"version"`
	Description               string                        `json:"description"`
	TenantID                  string                        `json:"tenant_id"`
	PrincipalID               string                        `json:"principal_id"`
	Subject                   string                        `json:"subject"`
	DefaultRequiredScopes     []string                      `json:"default_required_scopes"`
	PolicyScope               string                        `json:"policy_scope"`
	Workload                  WorkloadDescriptor            `json:"workload"`
	Resource                  ResourceDescriptor            `json:"resource"`
	Purpose                   string                        `json:"purpose"`
	PlaintextUTF8             string                        `json:"plaintext_utf8"`
	ContentDigest             string                        `json:"content_digest"`
	Labels                    []string                      `json:"labels"`
	Attributes                map[string]string             `json:"attributes"`
	InlineKeyB64              string                        `json:"inline_key_b64"`
	RewrapKeyB64              string                        `json:"rewrap_key_b64"`
	ManagedKeyProviderName    string                        `json:"managed_key_provider_name"`
	ManagedKeyReference       string                        `json:"managed_key_reference"`
	ManagedKeyB64             string                        `json:"managed_key_b64"`
	ManagedRewrapKeyReference string                        `json:"managed_rewrap_key_reference"`
	ManagedRewrapKeyB64       string                        `json:"managed_rewrap_key_b64"`
	SigningKeyB64             string                        `json:"signing_key_b64"`
	VerifyingKeyB64           string                        `json:"verifying_key_b64"`
	Steps                     []IntegrationFullScenarioStep `json:"steps"`
}

type IntegrationFullRunSummary struct {
	Runner   string           `json:"runner"`
	Scenario string           `json:"scenario"`
	Version  int              `json:"version"`
	TenantID string           `json:"tenant_id"`
	Steps    []map[string]any `json:"steps"`
}

func LoadIntegrationFullManifest(path string) (*IntegrationFullManifest, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest IntegrationFullManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	return &manifest, nil
}

func integrationFullUsesManagedKeyTransport(guidance *KeyTransportGuidance) bool {
	if guidance == nil {
		return false
	}

	return guidance.Mode != "" && guidance.Mode != KeyTransportModeLocalProvided
}

func integrationFullRequiresManagedEnvelopeKey(err error) bool {
	return err != nil && strings.Contains(
		err.Error(),
		"local envelope protection requires a managed key reference when key_transport.mode is wrapped_key_reference",
	)
}

func RunIntegrationFullScenario(options Options, manifestPath string) (*IntegrationFullRunSummary, error) {
	manifest, err := LoadIntegrationFullManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	managedRewrapKey, err := decodeIntegrationFullFixtureBytes(
		"managed_rewrap_key_b64",
		manifest.ManagedRewrapKeyB64,
	)
	if err != nil {
		return nil, err
	}
	if len(options.ManagedSymmetricKeyProviders) == 0 {
		managedKey, err := decodeIntegrationFullFixtureBytes("managed_key_b64", manifest.ManagedKeyB64)
		if err != nil {
			return nil, err
		}
		options.ManagedSymmetricKeyProviders = []ManagedSymmetricKeyProviderConfig{
			NewInMemoryManagedKeyProviderConfig(
				manifest.ManagedKeyProviderName,
				map[string][]byte{
					manifest.ManagedKeyReference:       managedKey,
					manifest.ManagedRewrapKeyReference: managedRewrapKey,
				},
			),
		}
	}
	client, err := NewClient(options)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = client.Close()
	}()
	return RunIntegrationFullScenarioWithClient(client, manifest)
}

func RunIntegrationFullScenarioWithClient(client *Client, manifest *IntegrationFullManifest) (*IntegrationFullRunSummary, error) {
	plaintext := []byte(manifest.PlaintextUTF8)
	inlineKey, err := decodeIntegrationFullFixtureBytes("inline_key_b64", manifest.InlineKeyB64)
	if err != nil {
		return nil, err
	}
	rewrapKey, err := decodeIntegrationFullFixtureBytes("rewrap_key_b64", manifest.RewrapKeyB64)
	if err != nil {
		return nil, err
	}
	signingKey, err := decodeIntegrationFullFixtureBytes("signing_key_b64", manifest.SigningKeyB64)
	if err != nil {
		return nil, err
	}
	verifyingKey, err := decodeIntegrationFullFixtureBytes("verifying_key_b64", manifest.VerifyingKeyB64)
	if err != nil {
		return nil, err
	}

	workload := manifest.Workload
	resource := manifest.Resource
	labels := append([]string(nil), manifest.Labels...)
	attributes := cloneStringMap(manifest.Attributes)

	envelopeRequest := LocalProtectionRequest{
		Workload:                 workload,
		Resource:                 resource,
		PreferredArtifactProfile: ArtifactProfileEnvelope,
		Purpose:                  manifest.Purpose,
		Labels:                   append([]string(nil), labels...),
		Attributes:               cloneStringMap(attributes),
	}
	tdfRequest := LocalProtectionRequest{
		Workload:                 workload,
		Resource:                 resource,
		PreferredArtifactProfile: ArtifactProfileTDF,
		Purpose:                  manifest.Purpose,
		Labels:                   append([]string(nil), labels...),
		Attributes:               cloneStringMap(attributes),
	}
	detachedSignatureRequest := LocalProtectionRequest{
		Workload:                 workload,
		Resource:                 resource,
		PreferredArtifactProfile: ArtifactProfileDetachedSignature,
		Purpose:                  manifest.Purpose,
		Labels:                   append([]string(nil), labels...),
		Attributes:               cloneStringMap(attributes),
	}

	capabilities, err := client.Capabilities()
	if err != nil {
		return nil, fmt.Errorf("capabilities: %w", err)
	}
	bootstrap, err := client.Bootstrap()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	whoami, err := client.WhoAmI()
	if err != nil {
		return nil, fmt.Errorf("whoami: %w", err)
	}
	prepared, err := client.PrepareLocalProtection(plaintext, envelopeRequest)
	if err != nil {
		return nil, fmt.Errorf("prepare_local_protection: %w", err)
	}
	cidBinding, err := client.GenerateCIDBinding(plaintext, envelopeRequest)
	if err != nil {
		return nil, fmt.Errorf("generate_cid_binding: %w", err)
	}
	protectionPlan, err := client.ProtectionPlan(SdkProtectionPlanRequest{
		Operation:                ProtectionOperationProtect,
		Workload:                 workload,
		Resource:                 resource,
		PreferredArtifactProfile: ArtifactProfileTDF,
		ContentDigest:            manifest.ContentDigest,
		ContentSizeBytes:         uint64(len(plaintext)),
		Purpose:                  manifest.Purpose,
		Labels:                   append([]string(nil), labels...),
		Attributes:               cloneStringMap(attributes),
	})
	if err != nil {
		return nil, fmt.Errorf("protection_plan: %w", err)
	}
	policyResolution, err := client.PolicyResolve(SdkPolicyResolveRequest{
		Operation:        ProtectionOperationProtect,
		Workload:         workload,
		Resource:         resource,
		ContentDigest:    manifest.ContentDigest,
		ContentSizeBytes: uint64(len(plaintext)),
		Purpose:          manifest.Purpose,
		Labels:           append([]string(nil), labels...),
		Attributes:       cloneStringMap(attributes),
	})
	if err != nil {
		return nil, fmt.Errorf("policy_resolve: %w", err)
	}
	keyAccessPlan, err := client.KeyAccessPlan(SdkKeyAccessPlanRequest{
		Operation:       KeyAccessOperationWrap,
		Workload:        workload,
		Resource:        resource,
		ArtifactProfile: ArtifactProfileTDF,
		KeyReference:    manifest.ManagedKeyReference,
		ContentDigest:   manifest.ContentDigest,
		Purpose:         manifest.Purpose,
		Labels:          append([]string(nil), labels...),
		Attributes:      cloneStringMap(attributes),
	})
	if err != nil {
		return nil, fmt.Errorf("key_access_plan: %w", err)
	}
	envelopeKeyAccessPlan, err := client.KeyAccessPlan(SdkKeyAccessPlanRequest{
		Operation:       KeyAccessOperationWrap,
		Workload:        workload,
		Resource:        resource,
		ArtifactProfile: ArtifactProfileEnvelope,
		KeyReference:    manifest.ManagedKeyReference,
		ContentDigest:   manifest.ContentDigest,
		Purpose:         manifest.Purpose,
		Labels:          append([]string(nil), labels...),
		Attributes:      cloneStringMap(attributes),
	})
	if err != nil {
		return nil, fmt.Errorf("envelope_key_access_plan: %w", err)
	}
	useManagedEnvelopeKeys := integrationFullUsesManagedKeyTransport(envelopeKeyAccessPlan.Execution.KeyTransport)

	signedDetached, err := client.SignBytesWithDetachedSignature(signingKey, plaintext, detachedSignatureRequest)
	if err != nil {
		return nil, fmt.Errorf("sign_bytes_with_detached_signature: %w", err)
	}
	detachedArtifactBytes, err := signedDetached.Artifact.ArtifactBytes()
	if err != nil {
		return nil, fmt.Errorf("decode detached signature artifact bytes: %w", err)
	}
	verifiedDetached, err := client.VerifyBytesWithDetachedSignature(verifyingKey, plaintext, detachedArtifactBytes)
	if err != nil {
		return nil, fmt.Errorf("verify_bytes_with_detached_signature: %w", err)
	}
	managedKeySource := ManagedReferenceKeySourceWithProvider(
		manifest.ManagedKeyProviderName,
		manifest.ManagedKeyReference,
	)
	managedRewrapKeySource := ManagedReferenceKeySourceWithProvider(
		manifest.ManagedKeyProviderName,
		manifest.ManagedRewrapKeyReference,
	)

	var protectedEnvelope *EnvelopeProtectionResult
	if useManagedEnvelopeKeys {
		protectedEnvelope, err = client.ProtectBytesWithEnvelopeUsingKeySource(
			managedKeySource,
			plaintext,
			envelopeRequest,
		)
	} else {
		protectedEnvelope, err = client.ProtectBytesWithEnvelope(inlineKey, plaintext, envelopeRequest)
		if integrationFullRequiresManagedEnvelopeKey(err) {
			useManagedEnvelopeKeys = true
			protectedEnvelope, err = client.ProtectBytesWithEnvelopeUsingKeySource(
				managedKeySource,
				plaintext,
				envelopeRequest,
			)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("protect_bytes_with_envelope: %w", err)
	}
	envelopeArtifactBytes, err := protectedEnvelope.Artifact.ArtifactBytes()
	if err != nil {
		return nil, fmt.Errorf("decode envelope artifact bytes: %w", err)
	}
	var accessedEnvelope *EnvelopeAccessResult
	if useManagedEnvelopeKeys {
		accessedEnvelope, err = client.AccessBytesWithEnvelopeUsingKeySource(
			managedKeySource,
			envelopeArtifactBytes,
		)
	} else {
		accessedEnvelope, err = client.AccessBytesWithEnvelope(inlineKey, envelopeArtifactBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("access_bytes_with_envelope: %w", err)
	}
	envelopePlaintext, err := accessedEnvelope.Plaintext()
	if err != nil {
		return nil, fmt.Errorf("decode envelope plaintext: %w", err)
	}
	var rewrappedEnvelope *EnvelopeRewrapResult
	if useManagedEnvelopeKeys {
		rewrappedEnvelope, err = client.RewrapBytesWithEnvelopeUsingKeySources(
			managedKeySource,
			managedRewrapKeySource,
			envelopeArtifactBytes,
		)
	} else {
		rewrappedEnvelope, err = client.RewrapBytesWithEnvelope(inlineKey, rewrapKey, envelopeArtifactBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("rewrap_bytes_with_envelope: %w", err)
	}
	protectedTDF, err := client.ProtectBytesWithTDFUsingKeySource(managedKeySource, plaintext, tdfRequest)
	if err != nil {
		return nil, fmt.Errorf("protect_bytes_with_tdf_using_key_source: %w", err)
	}
	tdfArtifactBytes, err := protectedTDF.Artifact.ArtifactBytes()
	if err != nil {
		return nil, fmt.Errorf("decode tdf artifact bytes: %w", err)
	}
	accessedTDF, err := client.AccessBytesWithTDFUsingKeySource(managedKeySource, tdfArtifactBytes)
	if err != nil {
		return nil, fmt.Errorf("access_bytes_with_tdf_using_key_source: %w", err)
	}
	tdfPlaintext, err := accessedTDF.Plaintext()
	if err != nil {
		return nil, fmt.Errorf("decode tdf plaintext: %w", err)
	}
	rewrappedTDF, err := client.RewrapBytesWithTDFUsingKeySources(managedKeySource, managedRewrapKeySource, tdfArtifactBytes)
	if err != nil {
		return nil, fmt.Errorf("rewrap_bytes_with_tdf: %w", err)
	}
	directArtifactRegistration, err := client.ArtifactRegister(SdkArtifactRegisterRequest{
		Operation:       ProtectionOperationRewrap,
		Workload:        workload,
		Resource:        resource,
		ArtifactProfile: ArtifactProfileTDF,
		ArtifactDigest:  rewrappedTDF.Artifact.ArtifactDigest,
		KeyReference:    manifest.ManagedRewrapKeyReference,
		Purpose:         manifest.Purpose,
		Labels:          append([]string(nil), labels...),
		Attributes:      cloneStringMap(attributes),
	})
	if err != nil {
		return nil, fmt.Errorf("artifact_register: %w", err)
	}
	directEvidence, err := client.Evidence(SdkEvidenceIngestRequest{
		EventType:       EvidenceEventTypeRewrap,
		Workload:        workload,
		Resource:        resource,
		ArtifactProfile: ArtifactProfileTDF,
		ArtifactDigest:  rewrappedTDF.Artifact.ArtifactDigest,
		Outcome:         "success",
		Purpose:         manifest.Purpose,
		Labels:          append([]string(nil), labels...),
		Attributes:      cloneStringMap(attributes),
	})
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}

	return &IntegrationFullRunSummary{
		Runner:   "sdk-go",
		Scenario: manifest.Name,
		Version:  manifest.Version,
		TenantID: manifest.TenantID,
		Steps: []map[string]any{
			integrationFullStep("capabilities", map[string]any{
				"tenant_id": capabilities.Caller.TenantID,
				"auth_mode": capabilities.AuthConfiguration.Mode,
			}),
			integrationFullStep("bootstrap", map[string]any{
				"supported_operations": bootstrap.SupportedOperations,
			}),
			integrationFullStep("whoami", map[string]any{
				"principal_id": whoami.Caller.PrincipalID,
			}),
			integrationFullStep("prepare_local_protection", map[string]any{
				"content_digest": prepared.ContentBinding.ContentDigest,
			}),
			integrationFullStep("generate_cid_binding", map[string]any{
				"binding_hash": cidBinding.BindingHash,
			}),
			integrationFullStep("protection_plan", map[string]any{
				"protect_locally": protectionPlan.Execution.ProtectLocally,
			}),
			integrationFullStep("policy_resolve", map[string]any{
				"allow": policyResolution.Decision.Allow,
			}),
			integrationFullStep("key_access_plan", map[string]any{
				"local_cryptographic_operation": keyAccessPlan.Execution.LocalCryptographicOperation,
			}),
			integrationFullStep("detached_signature_round_trip", map[string]any{
				"artifact_digest":         signedDetached.Artifact.ArtifactDigest,
				"signer_key_id":           signedDetached.Artifact.DetachedSignature.SignerKeyID,
				"verified_content_digest": verifiedDetached.ContentBinding.ContentDigest,
			}),
			integrationFullStep("envelope_round_trip", map[string]any{
				"artifact_digest": protectedEnvelope.Artifact.ArtifactDigest,
				"plaintext_utf8":  string(envelopePlaintext),
			}),
			integrationFullStep("envelope_rewrap", map[string]any{
				"original_artifact_digest": rewrappedEnvelope.OriginalArtifactDigest,
				"artifact_digest":          rewrappedEnvelope.Artifact.ArtifactDigest,
			}),
			integrationFullStep("tdf_round_trip", map[string]any{
				"artifact_digest": protectedTDF.Artifact.ArtifactDigest,
				"plaintext_utf8":  string(tdfPlaintext),
			}),
			integrationFullStep("tdf_rewrap", map[string]any{
				"original_artifact_digest": rewrappedTDF.OriginalArtifactDigest,
				"artifact_digest":          rewrappedTDF.Artifact.ArtifactDigest,
			}),
			integrationFullStep("artifact_register_direct", map[string]any{
				"artifact_digest": directArtifactRegistration.RequestSummary.ArtifactDigest,
				"accepted":        directArtifactRegistration.Registration.Accepted,
			}),
			integrationFullStep("evidence_direct", map[string]any{
				"event_type": directEvidence.RequestSummary.EventType,
				"accepted":   directEvidence.Ingestion.Accepted,
			}),
		},
	}, nil
}

func integrationFullStep(name string, fields map[string]any) map[string]any {
	step := map[string]any{
		"name":   name,
		"status": "ok",
	}
	for key, value := range fields {
		step[key] = value
	}
	return step
}

func decodeIntegrationFullFixtureBytes(label string, value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return decoded, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}
