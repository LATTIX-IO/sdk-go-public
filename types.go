package sdk

import (
	"encoding/base64"
	"time"
)

type Options struct {
	BaseURL                      string                              `json:"base_url"`
	BearerToken                  string                              `json:"bearer_token,omitempty"`
	TenantID                     string                              `json:"tenant_id,omitempty"`
	UserID                       string                              `json:"user_id,omitempty"`
	TimeoutSecs                  uint64                              `json:"timeout_secs,omitempty"`
	Headers                      map[string]string                   `json:"headers,omitempty"`
	ManagedSymmetricKeyProviders []ManagedSymmetricKeyProviderConfig `json:"managed_symmetric_key_providers,omitempty"`
}

type ManagedSymmetricKeyProviderKind string

const (
	ManagedSymmetricKeyProviderKindInMemory ManagedSymmetricKeyProviderKind = "in_memory"
	ManagedSymmetricKeyProviderKindCommand  ManagedSymmetricKeyProviderKind = "command"
)

type ManagedSymmetricKeyProviderConfig struct {
	Kind                    ManagedSymmetricKeyProviderKind `json:"kind,omitempty"`
	Name                    string                          `json:"name"`
	SupportedTransportModes []KeyTransportMode              `json:"supported_transport_modes,omitempty"`
	Keys                    map[string][]byte               `json:"keys,omitempty"`
	Command                 string                          `json:"command,omitempty"`
	Args                    []string                        `json:"args,omitempty"`
	Env                     map[string]string               `json:"env,omitempty"`
}

type InMemoryManagedKeyProviderConfig = ManagedSymmetricKeyProviderConfig
type CommandManagedKeyProviderConfig = ManagedSymmetricKeyProviderConfig

func NewInMemoryManagedKeyProviderConfig(name string, keys map[string][]byte, supportedTransportModes ...KeyTransportMode) ManagedSymmetricKeyProviderConfig {
	clonedKeys := make(map[string][]byte, len(keys))
	for keyReference, keyBytes := range keys {
		clonedKeys[keyReference] = append([]byte(nil), keyBytes...)
	}

	return ManagedSymmetricKeyProviderConfig{
		Kind:                    ManagedSymmetricKeyProviderKindInMemory,
		Name:                    name,
		SupportedTransportModes: append([]KeyTransportMode(nil), supportedTransportModes...),
		Keys:                    clonedKeys,
	}
}

func NewCommandManagedKeyProviderConfig(
	name string,
	command string,
	args []string,
	env map[string]string,
	supportedTransportModes ...KeyTransportMode,
) ManagedSymmetricKeyProviderConfig {
	clonedEnv := make(map[string]string, len(env))
	for key, value := range env {
		clonedEnv[key] = value
	}

	return ManagedSymmetricKeyProviderConfig{
		Kind:                    ManagedSymmetricKeyProviderKindCommand,
		Name:                    name,
		SupportedTransportModes: append([]KeyTransportMode(nil), supportedTransportModes...),
		Command:                 command,
		Args:                    append([]string(nil), args...),
		Env:                     clonedEnv,
	}
}

type AuthMode string

const (
	AuthModeTrustedHeaders             AuthMode = "trusted_headers"
	AuthModeBearerToken                AuthMode = "bearer_token"
	AuthModeBearerTokenOrTrustedHeader AuthMode = "bearer_token_or_trusted_headers"
)

type SdkAuthConfigurationMode string

const (
	SdkAuthConfigurationModeBearerTokenValidation  SdkAuthConfigurationMode = "bearer_token_validation"
	SdkAuthConfigurationModeOAuthClientCredentials SdkAuthConfigurationMode = "oauth_client_credentials"
)

type SdkProofOfPossession string

const (
	SdkProofOfPossessionMTLS SdkProofOfPossession = "mtls"
	SdkProofOfPossessionDPOP SdkProofOfPossession = "dpop"
)

type ProtectionOperation string

const (
	ProtectionOperationProtect ProtectionOperation = "protect"
	ProtectionOperationAccess  ProtectionOperation = "access"
	ProtectionOperationRewrap  ProtectionOperation = "rewrap"
)

type ArtifactProfile string

const (
	ArtifactProfileTDF               ArtifactProfile = "tdf"
	ArtifactProfileEnvelope          ArtifactProfile = "envelope"
	ArtifactProfileDetachedSignature ArtifactProfile = "detached_signature"
)

type KeyAccessOperation string

const (
	KeyAccessOperationWrap   KeyAccessOperation = "wrap"
	KeyAccessOperationUnwrap KeyAccessOperation = "unwrap"
	KeyAccessOperationRewrap KeyAccessOperation = "rewrap"
)

type KeyTransportMode string

const (
	KeyTransportModeLocalProvided        KeyTransportMode = "local_provided"
	KeyTransportModeWrappedKeyReference  KeyTransportMode = "wrapped_key_reference"
	KeyTransportModeAuthorizedKeyRelease KeyTransportMode = "authorized_key_release"
	KeyTransportModeKemEncapsulatedCEK   KeyTransportMode = "kem_encapsulated_cek"
)

type LocalSymmetricKeySourceKind string

const (
	LocalSymmetricKeySourceKindInline           LocalSymmetricKeySourceKind = "inline"
	LocalSymmetricKeySourceKindManagedReference LocalSymmetricKeySourceKind = "managed_reference"
)

type LocalSymmetricKeySource struct {
	Kind         LocalSymmetricKeySourceKind `json:"kind"`
	KeyB64       []byte                      `json:"key_b64,omitempty"`
	KeyReference string                      `json:"key_reference,omitempty"`
	ProviderName string                      `json:"provider_name,omitempty"`
}

func InlineSymmetricKeySource(key []byte) LocalSymmetricKeySource {
	return LocalSymmetricKeySource{
		Kind:   LocalSymmetricKeySourceKindInline,
		KeyB64: append([]byte(nil), key...),
	}
}

func ManagedReferenceKeySource(keyReference string) LocalSymmetricKeySource {
	return LocalSymmetricKeySource{
		Kind:         LocalSymmetricKeySourceKindManagedReference,
		KeyReference: keyReference,
	}
}

func ManagedReferenceKeySourceWithProvider(providerName string, keyReference string) LocalSymmetricKeySource {
	return LocalSymmetricKeySource{
		Kind:         LocalSymmetricKeySourceKindManagedReference,
		KeyReference: keyReference,
		ProviderName: providerName,
	}
}

type EvidenceEventType string

const (
	EvidenceEventTypeProtect EvidenceEventType = "protect"
	EvidenceEventTypeAccess  EvidenceEventType = "access"
	EvidenceEventTypeRewrap  EvidenceEventType = "rewrap"
	EvidenceEventTypeDeny    EvidenceEventType = "deny"
)

type RequestContext struct {
	TenantID    string   `json:"tenant_id"`
	PrincipalID string   `json:"principal_id"`
	Subject     string   `json:"subject"`
	AuthSource  string   `json:"auth_source"`
	Scopes      []string `json:"scopes,omitempty"`
}

type SdkAuthConfiguration struct {
	Mode              SdkAuthConfigurationMode `json:"mode"`
	ProofOfPossession SdkProofOfPossession     `json:"proof_of_possession"`
	OIDCIssuer        string                   `json:"oidc_issuer,omitempty"`
	OIDCAudience      string                   `json:"oidc_audience,omitempty"`
	OIDCIssuerReady   bool                     `json:"oidc_issuer_ready"`
	MTLSReady         bool                     `json:"mtls_ready"`
}

type SdkRouteCapability struct {
	Route          string   `json:"route"`
	Domain         string   `json:"domain"`
	Configured     bool     `json:"configured"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
}

type SdkCapabilitiesResponse struct {
	Service               string               `json:"service"`
	Status                string               `json:"status"`
	AuthMode              AuthMode             `json:"auth_mode"`
	AuthConfiguration     SdkAuthConfiguration `json:"auth_configuration"`
	Caller                RequestContext       `json:"caller"`
	DefaultRequiredScopes []string             `json:"default_required_scopes,omitempty"`
	Routes                []SdkRouteCapability `json:"routes,omitempty"`
}

type CallerIdentityResponse struct {
	Service string         `json:"service"`
	Status  string         `json:"status"`
	Caller  RequestContext `json:"caller"`
}

type PlatformDomainPlan struct {
	Domain     string `json:"domain"`
	Configured bool   `json:"configured"`
	Reason     string `json:"reason"`
}

type SdkBootstrapResponse struct {
	Service                   string                `json:"service"`
	Status                    string                `json:"status"`
	AuthMode                  AuthMode              `json:"auth_mode"`
	AuthConfiguration         SdkAuthConfiguration  `json:"auth_configuration"`
	Caller                    RequestContext        `json:"caller"`
	EnforcementModel          string                `json:"enforcement_model"`
	PlaintextToPlatform       bool                  `json:"plaintext_to_platform"`
	PolicyResolutionMode      string                `json:"policy_resolution_mode"`
	SupportedOperations       []ProtectionOperation `json:"supported_operations,omitempty"`
	SupportedArtifactProfiles []ArtifactProfile     `json:"supported_artifact_profiles,omitempty"`
	PlatformDomains           []PlatformDomainPlan  `json:"platform_domains,omitempty"`
}

type WorkloadDescriptor struct {
	Application string `json:"application"`
	Environment string `json:"environment,omitempty"`
	Component   string `json:"component,omitempty"`
}

type ResourceDescriptor struct {
	Kind     string `json:"kind"`
	ID       string `json:"id,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
}

type LocalProtectionRequest struct {
	Workload                 WorkloadDescriptor `json:"workload"`
	Resource                 ResourceDescriptor `json:"resource"`
	PreferredArtifactProfile ArtifactProfile    `json:"preferred_artifact_profile,omitempty"`
	Purpose                  string             `json:"purpose,omitempty"`
	Labels                   []string           `json:"labels,omitempty"`
	Attributes               map[string]string  `json:"attributes,omitempty"`
}

type LocalAttributeEdit struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

type LocalContentBinding struct {
	TenantID         string `json:"tenant_id"`
	ContentDigest    string `json:"content_digest"`
	ContentSizeBytes uint64 `json:"content_size_bytes"`
	RawCID           string `json:"raw_cid"`
}

type LocalArtifactBinding struct {
	Version          uint8              `json:"version"`
	TenantID         string             `json:"tenant_id"`
	RawCID           string             `json:"raw_cid"`
	ContentDigest    string             `json:"content_digest"`
	ContentSizeBytes uint64             `json:"content_size_bytes"`
	Workload         WorkloadDescriptor `json:"workload"`
	Resource         ResourceDescriptor `json:"resource"`
	Purpose          string             `json:"purpose,omitempty"`
	Labels           []string           `json:"labels,omitempty"`
	Attributes       map[string]string  `json:"attributes,omitempty"`
	BindingTargets   []string           `json:"binding_targets,omitempty"`
	BindingHash      string             `json:"binding_hash,omitempty"`
}

type PreparedLocalProtection struct {
	Caller           RequestContext            `json:"caller"`
	ContentBinding   LocalContentBinding       `json:"content_binding"`
	ArtifactBinding  LocalArtifactBinding      `json:"artifact_binding,omitempty"`
	Bootstrap        SdkBootstrapResponse      `json:"bootstrap"`
	PolicyResolution SdkPolicyResolveResponse  `json:"policy_resolution"`
	ProtectionPlan   SdkProtectionPlanResponse `json:"protection_plan"`
}

type LocalDetachedSignatureAlgorithm string

const (
	LocalDetachedSignatureAlgorithmEd25519 LocalDetachedSignatureAlgorithm = "ed25519"
)

type LocalDetachedSignatureArtifact struct {
	Version            uint8                           `json:"version"`
	ArtifactProfile    ArtifactProfile                 `json:"artifact_profile"`
	Algorithm          LocalDetachedSignatureAlgorithm `json:"algorithm"`
	TenantID           string                          `json:"tenant_id"`
	RawCID             string                          `json:"raw_cid"`
	ContentDigest      string                          `json:"content_digest"`
	ContentSizeBytes   uint64                          `json:"content_size_bytes"`
	Workload           WorkloadDescriptor              `json:"workload"`
	Resource           ResourceDescriptor              `json:"resource"`
	Purpose            string                          `json:"purpose,omitempty"`
	Labels             []string                        `json:"labels,omitempty"`
	Attributes         map[string]string               `json:"attributes,omitempty"`
	BindingTargets     []string                        `json:"binding_targets,omitempty"`
	SignerKeyID        string                          `json:"signer_key_id"`
	SignerPublicKeyB64 string                          `json:"signer_public_key_b64"`
	BindingHash        string                          `json:"binding_hash"`
	SignatureB64       string                          `json:"signature_b64"`
}

type ProtectedDetachedSignatureArtifact struct {
	DetachedSignature LocalDetachedSignatureArtifact `json:"detached_signature"`
	ArtifactBytesB64  string                         `json:"artifact_bytes_b64"`
	ArtifactDigest    string                         `json:"artifact_digest"`
}

func (p ProtectedDetachedSignatureArtifact) ArtifactBytes() ([]byte, error) {
	if p.ArtifactBytesB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(p.ArtifactBytesB64)
}

type DetachedSignatureSignResult struct {
	Prepared             PreparedLocalProtection            `json:"prepared"`
	KeyAccessPlan        SdkKeyAccessPlanResponse           `json:"key_access_plan"`
	Artifact             ProtectedDetachedSignatureArtifact `json:"artifact"`
	ArtifactRegistration SdkArtifactRegisterResponse        `json:"artifact_registration"`
	Evidence             SdkEvidenceIngestResponse          `json:"evidence"`
}

type DetachedSignatureVerifyResult struct {
	Artifact         LocalDetachedSignatureArtifact `json:"artifact"`
	ArtifactDigest   string                         `json:"artifact_digest"`
	PolicyResolution SdkPolicyResolveResponse       `json:"policy_resolution"`
	KeyAccessPlan    SdkKeyAccessPlanResponse       `json:"key_access_plan"`
	ContentBinding   LocalContentBinding            `json:"content_binding"`
	Evidence         SdkEvidenceIngestResponse      `json:"evidence"`
}

type LocalTDFAlgorithm string

const (
	LocalTDFAlgorithmAES256GCM LocalTDFAlgorithm = "aes256_gcm"
)

type LocalTDFManifest struct {
	Workload   WorkloadDescriptor `json:"workload"`
	Resource   ResourceDescriptor `json:"resource"`
	Purpose    string             `json:"purpose,omitempty"`
	Labels     []string           `json:"labels,omitempty"`
	Attributes map[string]string  `json:"attributes,omitempty"`
}

type LocalTDFArtifact struct {
	Version               uint8             `json:"version"`
	MetaVersion           uint64            `json:"meta_version"`
	ArtifactProfile       ArtifactProfile   `json:"artifact_profile"`
	Algorithm             LocalTDFAlgorithm `json:"algorithm"`
	TenantID              string            `json:"tenant_id"`
	RawCID                string            `json:"raw_cid"`
	ContentDigest         string            `json:"content_digest"`
	ContentSizeBytes      uint64            `json:"content_size_bytes"`
	ManifestDigest        string            `json:"manifest_digest"`
	BindingTargets        []string          `json:"binding_targets,omitempty"`
	BindingHash           string            `json:"binding_hash,omitempty"`
	PolicyContext         *LocalTDFManifest `json:"policy_context,omitempty"`
	ManifestNonceB64      string            `json:"manifest_nonce_b64"`
	ManifestCiphertextB64 string            `json:"manifest_ciphertext_b64"`
	PayloadNonceB64       string            `json:"payload_nonce_b64"`
	PayloadCiphertextB64  string            `json:"payload_ciphertext_b64"`
	AADHash               string            `json:"aad_hash"`
}

type ProtectedTDFArtifact struct {
	TDF              LocalTDFArtifact `json:"tdf"`
	ArtifactBytesB64 string           `json:"artifact_bytes_b64"`
	ArtifactDigest   string           `json:"artifact_digest"`
}

func (p ProtectedTDFArtifact) ArtifactBytes() ([]byte, error) {
	if p.ArtifactBytesB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(p.ArtifactBytesB64)
}

type TDFProtectionResult struct {
	Prepared             PreparedLocalProtection     `json:"prepared"`
	KeyAccessPlan        SdkKeyAccessPlanResponse    `json:"key_access_plan"`
	Artifact             ProtectedTDFArtifact        `json:"artifact"`
	ArtifactRegistration SdkArtifactRegisterResponse `json:"artifact_registration"`
	Evidence             SdkEvidenceIngestResponse   `json:"evidence"`
}

type TDFRewrapResult struct {
	ContentBinding         LocalContentBinding         `json:"content_binding"`
	Manifest               LocalTDFManifest            `json:"manifest"`
	PolicyResolution       SdkPolicyResolveResponse    `json:"policy_resolution"`
	ProtectionPlan         SdkProtectionPlanResponse   `json:"protection_plan"`
	KeyAccessPlan          SdkKeyAccessPlanResponse    `json:"key_access_plan"`
	OriginalArtifactDigest string                      `json:"original_artifact_digest"`
	Artifact               ProtectedTDFArtifact        `json:"artifact"`
	ArtifactRegistration   SdkArtifactRegisterResponse `json:"artifact_registration"`
	Evidence               SdkEvidenceIngestResponse   `json:"evidence"`
}

type TDFAccessResult struct {
	Artifact         LocalTDFArtifact          `json:"artifact"`
	Manifest         LocalTDFManifest          `json:"manifest"`
	ArtifactDigest   string                    `json:"artifact_digest"`
	PolicyResolution SdkPolicyResolveResponse  `json:"policy_resolution"`
	KeyAccessPlan    SdkKeyAccessPlanResponse  `json:"key_access_plan"`
	PlaintextB64     string                    `json:"plaintext_b64"`
	Evidence         SdkEvidenceIngestResponse `json:"evidence"`
}

func (e TDFAccessResult) Plaintext() ([]byte, error) {
	if e.PlaintextB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(e.PlaintextB64)
}

type LocalEnvelopeAlgorithm string

const (
	LocalEnvelopeAlgorithmAES256GCM LocalEnvelopeAlgorithm = "aes256_gcm"
)

type LocalEnvelopeArtifact struct {
	Version          uint8                  `json:"version"`
	ArtifactProfile  ArtifactProfile        `json:"artifact_profile"`
	Algorithm        LocalEnvelopeAlgorithm `json:"algorithm"`
	TenantID         string                 `json:"tenant_id"`
	RawCID           string                 `json:"raw_cid"`
	ContentDigest    string                 `json:"content_digest"`
	ContentSizeBytes uint64                 `json:"content_size_bytes"`
	Workload         WorkloadDescriptor     `json:"workload"`
	Resource         ResourceDescriptor     `json:"resource"`
	Purpose          string                 `json:"purpose,omitempty"`
	Labels           []string               `json:"labels,omitempty"`
	Attributes       map[string]string      `json:"attributes,omitempty"`
	BindingTargets   []string               `json:"binding_targets,omitempty"`
	BindingHash      string                 `json:"binding_hash,omitempty"`
	NonceB64         string                 `json:"nonce_b64"`
	AADHash          string                 `json:"aad_hash"`
	CiphertextB64    string                 `json:"ciphertext_b64"`
}

type ProtectedEnvelopeArtifact struct {
	Envelope         LocalEnvelopeArtifact `json:"envelope"`
	ArtifactBytesB64 string                `json:"artifact_bytes_b64"`
	ArtifactDigest   string                `json:"artifact_digest"`
}

func (p ProtectedEnvelopeArtifact) ArtifactBytes() ([]byte, error) {
	if p.ArtifactBytesB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(p.ArtifactBytesB64)
}

type EnvelopeProtectionResult struct {
	Prepared             PreparedLocalProtection     `json:"prepared"`
	KeyAccessPlan        SdkKeyAccessPlanResponse    `json:"key_access_plan"`
	Artifact             ProtectedEnvelopeArtifact   `json:"artifact"`
	ArtifactRegistration SdkArtifactRegisterResponse `json:"artifact_registration"`
	Evidence             SdkEvidenceIngestResponse   `json:"evidence"`
}

type EnvelopeRewrapResult struct {
	ContentBinding         LocalContentBinding         `json:"content_binding"`
	PolicyResolution       SdkPolicyResolveResponse    `json:"policy_resolution"`
	ProtectionPlan         SdkProtectionPlanResponse   `json:"protection_plan"`
	KeyAccessPlan          SdkKeyAccessPlanResponse    `json:"key_access_plan"`
	OriginalArtifactDigest string                      `json:"original_artifact_digest"`
	Artifact               ProtectedEnvelopeArtifact   `json:"artifact"`
	ArtifactRegistration   SdkArtifactRegisterResponse `json:"artifact_registration"`
	Evidence               SdkEvidenceIngestResponse   `json:"evidence"`
}

type EnvelopeAccessResult struct {
	Artifact         LocalEnvelopeArtifact     `json:"artifact"`
	ArtifactDigest   string                    `json:"artifact_digest"`
	PolicyResolution SdkPolicyResolveResponse  `json:"policy_resolution"`
	KeyAccessPlan    SdkKeyAccessPlanResponse  `json:"key_access_plan"`
	PlaintextB64     string                    `json:"plaintext_b64"`
	Evidence         SdkEvidenceIngestResponse `json:"evidence"`
}

func (e EnvelopeAccessResult) Plaintext() ([]byte, error) {
	if e.PlaintextB64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(e.PlaintextB64)
}

type SdkProtectionPlanRequest struct {
	Operation                ProtectionOperation `json:"operation"`
	Workload                 WorkloadDescriptor  `json:"workload"`
	Resource                 ResourceDescriptor  `json:"resource"`
	PreferredArtifactProfile ArtifactProfile     `json:"preferred_artifact_profile,omitempty"`
	ContentDigest            string              `json:"content_digest,omitempty"`
	ContentSizeBytes         uint64              `json:"content_size_bytes,omitempty"`
	Purpose                  string              `json:"purpose,omitempty"`
	Labels                   []string            `json:"labels,omitempty"`
	Attributes               map[string]string   `json:"attributes,omitempty"`
}

type ProtectionPlanSummary struct {
	Operation                ProtectionOperation `json:"operation"`
	WorkloadApplication      string              `json:"workload_application"`
	WorkloadEnvironment      string              `json:"workload_environment,omitempty"`
	WorkloadComponent        string              `json:"workload_component,omitempty"`
	ResourceKind             string              `json:"resource_kind"`
	ResourceID               string              `json:"resource_id,omitempty"`
	MimeType                 string              `json:"mime_type,omitempty"`
	PreferredArtifactProfile ArtifactProfile     `json:"preferred_artifact_profile"`
	ContentDigestPresent     bool                `json:"content_digest_present"`
	ContentSizeBytes         uint64              `json:"content_size_bytes,omitempty"`
	LabelCount               int                 `json:"label_count"`
	AttributeCount           int                 `json:"attribute_count"`
	Purpose                  string              `json:"purpose,omitempty"`
}

type ProtectionPlanDecision struct {
	Allow              bool     `json:"allow"`
	RequiredScopes     []string `json:"required_scopes,omitempty"`
	HandlingMode       string   `json:"handling_mode"`
	PlaintextTransport string   `json:"plaintext_transport"`
}

type ProtectionExecutionPlan struct {
	ProtectLocally          bool                  `json:"protect_locally"`
	LocalEnforcementLibrary string                `json:"local_enforcement_library"`
	SendPlaintextToPlatform bool                  `json:"send_plaintext_to_platform"`
	SendOnly                []string              `json:"send_only,omitempty"`
	ArtifactProfile         ArtifactProfile       `json:"artifact_profile"`
	KeyStrategy             string                `json:"key_strategy"`
	PolicyResolution        string                `json:"policy_resolution"`
	KeyTransport            *KeyTransportGuidance `json:"key_transport,omitempty"`
}

type KeyTransportGuidance struct {
	Mode                        KeyTransportMode `json:"mode"`
	KeyMaterialOrigin           string           `json:"key_material_origin"`
	StableKeyReferencePreferred bool             `json:"stable_key_reference_preferred"`
	RawKeyDeliveryForbidden     bool             `json:"raw_key_delivery_forbidden"`
	PublicKeyDistribution       string           `json:"public_key_distribution,omitempty"`
	ExchangeAlgorithm           string           `json:"exchange_algorithm,omitempty"`
}

type SdkProtectionPlanResponse struct {
	Service         string                  `json:"service"`
	Status          string                  `json:"status"`
	Caller          RequestContext          `json:"caller"`
	RequestSummary  ProtectionPlanSummary   `json:"request_summary"`
	Decision        ProtectionPlanDecision  `json:"decision"`
	Execution       ProtectionExecutionPlan `json:"execution"`
	PlatformDomains []PlatformDomainPlan    `json:"platform_domains,omitempty"`
	Warnings        []string                `json:"warnings,omitempty"`
}

type SdkPolicyResolveRequest struct {
	Operation        ProtectionOperation `json:"operation"`
	Workload         WorkloadDescriptor  `json:"workload"`
	Resource         ResourceDescriptor  `json:"resource"`
	ContentDigest    string              `json:"content_digest,omitempty"`
	ContentSizeBytes uint64              `json:"content_size_bytes,omitempty"`
	Purpose          string              `json:"purpose,omitempty"`
	Labels           []string            `json:"labels,omitempty"`
	Attributes       map[string]string   `json:"attributes,omitempty"`
}

type PolicyRequestSummary struct {
	Operation            ProtectionOperation `json:"operation"`
	WorkloadApplication  string              `json:"workload_application"`
	WorkloadEnvironment  string              `json:"workload_environment,omitempty"`
	WorkloadComponent    string              `json:"workload_component,omitempty"`
	ResourceKind         string              `json:"resource_kind"`
	ResourceID           string              `json:"resource_id,omitempty"`
	MimeType             string              `json:"mime_type,omitempty"`
	ContentDigestPresent bool                `json:"content_digest_present"`
	ContentSizeBytes     uint64              `json:"content_size_bytes,omitempty"`
	Purpose              string              `json:"purpose,omitempty"`
	LabelCount           int                 `json:"label_count"`
	AttributeCount       int                 `json:"attribute_count"`
}

type PolicyResolutionDecision struct {
	Allow           bool     `json:"allow"`
	EnforcementMode string   `json:"enforcement_mode"`
	RequiredScopes  []string `json:"required_scopes,omitempty"`
	PolicyInputs    []string `json:"policy_inputs,omitempty"`
	RequiredActions []string `json:"required_actions,omitempty"`
}

type PolicyHandlingGuidance struct {
	ProtectLocally     bool     `json:"protect_locally"`
	PlaintextTransport string   `json:"plaintext_transport"`
	BindPolicyTo       []string `json:"bind_policy_to,omitempty"`
	EvidenceExpected   []string `json:"evidence_expected,omitempty"`
}

type SdkPolicyResolveResponse struct {
	Service         string                   `json:"service"`
	Status          string                   `json:"status"`
	Caller          RequestContext           `json:"caller"`
	RequestSummary  PolicyRequestSummary     `json:"request_summary"`
	Decision        PolicyResolutionDecision `json:"decision"`
	Handling        PolicyHandlingGuidance   `json:"handling"`
	PlatformDomains []PlatformDomainPlan     `json:"platform_domains,omitempty"`
	Warnings        []string                 `json:"warnings,omitempty"`
}

type SdkKeyAccessPlanRequest struct {
	Operation       KeyAccessOperation `json:"operation"`
	Workload        WorkloadDescriptor `json:"workload"`
	Resource        ResourceDescriptor `json:"resource"`
	ArtifactProfile ArtifactProfile    `json:"artifact_profile,omitempty"`
	KeyReference    string             `json:"key_reference,omitempty"`
	ContentDigest   string             `json:"content_digest,omitempty"`
	Purpose         string             `json:"purpose,omitempty"`
	Labels          []string           `json:"labels,omitempty"`
	Attributes      map[string]string  `json:"attributes,omitempty"`
}

type KeyAccessRequestSummary struct {
	Operation            KeyAccessOperation `json:"operation"`
	WorkloadApplication  string             `json:"workload_application"`
	WorkloadEnvironment  string             `json:"workload_environment,omitempty"`
	WorkloadComponent    string             `json:"workload_component,omitempty"`
	ResourceKind         string             `json:"resource_kind"`
	ResourceID           string             `json:"resource_id,omitempty"`
	MimeType             string             `json:"mime_type,omitempty"`
	ArtifactProfile      ArtifactProfile    `json:"artifact_profile"`
	KeyReferencePresent  bool               `json:"key_reference_present"`
	ContentDigestPresent bool               `json:"content_digest_present"`
	Purpose              string             `json:"purpose,omitempty"`
	LabelCount           int                `json:"label_count"`
	AttributeCount       int                `json:"attribute_count"`
}

type KeyAccessDecision struct {
	Allow               bool               `json:"allow"`
	RequiredScopes      []string           `json:"required_scopes,omitempty"`
	Operation           KeyAccessOperation `json:"operation"`
	KeyReferencePresent bool               `json:"key_reference_present"`
}

type KeyAccessExecutionPlan struct {
	LocalCryptographicOperation bool                  `json:"local_cryptographic_operation"`
	PlatformRole                string                `json:"platform_role"`
	SendPlaintextToPlatform     bool                  `json:"send_plaintext_to_platform"`
	SendOnly                    []string              `json:"send_only,omitempty"`
	ArtifactProfile             ArtifactProfile       `json:"artifact_profile"`
	AuthorizationStrategy       string                `json:"authorization_strategy"`
	KeyTransport                *KeyTransportGuidance `json:"key_transport,omitempty"`
}

type SdkKeyAccessPlanResponse struct {
	Service         string                  `json:"service"`
	Status          string                  `json:"status"`
	Caller          RequestContext          `json:"caller"`
	RequestSummary  KeyAccessRequestSummary `json:"request_summary"`
	Decision        KeyAccessDecision       `json:"decision"`
	Execution       KeyAccessExecutionPlan  `json:"execution"`
	PlatformDomains []PlatformDomainPlan    `json:"platform_domains,omitempty"`
	Warnings        []string                `json:"warnings,omitempty"`
}

type SdkArtifactRegisterRequest struct {
	Operation       ProtectionOperation `json:"operation"`
	Workload        WorkloadDescriptor  `json:"workload"`
	Resource        ResourceDescriptor  `json:"resource"`
	ArtifactProfile ArtifactProfile     `json:"artifact_profile"`
	ArtifactDigest  string              `json:"artifact_digest"`
	ArtifactLocator string              `json:"artifact_locator,omitempty"`
	DecisionID      string              `json:"decision_id,omitempty"`
	KeyReference    string              `json:"key_reference,omitempty"`
	Purpose         string              `json:"purpose,omitempty"`
	Labels          []string            `json:"labels,omitempty"`
	Attributes      map[string]string   `json:"attributes,omitempty"`
}

type ArtifactRegistrationSummary struct {
	Operation              ProtectionOperation `json:"operation"`
	WorkloadApplication    string              `json:"workload_application"`
	WorkloadEnvironment    string              `json:"workload_environment,omitempty"`
	WorkloadComponent      string              `json:"workload_component,omitempty"`
	ResourceKind           string              `json:"resource_kind"`
	ResourceID             string              `json:"resource_id,omitempty"`
	MimeType               string              `json:"mime_type,omitempty"`
	ArtifactProfile        ArtifactProfile     `json:"artifact_profile"`
	ArtifactDigest         string              `json:"artifact_digest"`
	ArtifactLocatorPresent bool                `json:"artifact_locator_present"`
	DecisionIDPresent      bool                `json:"decision_id_present"`
	KeyReferencePresent    bool                `json:"key_reference_present"`
	Purpose                string              `json:"purpose,omitempty"`
	LabelCount             int                 `json:"label_count"`
	AttributeCount         int                 `json:"attribute_count"`
}

type ArtifactRegistrationPlan struct {
	Accepted                bool     `json:"accepted"`
	RequiredScopes          []string `json:"required_scopes,omitempty"`
	ArtifactTransport       string   `json:"artifact_transport"`
	SendPlaintextToPlatform bool     `json:"send_plaintext_to_platform"`
	CatalogActions          []string `json:"catalog_actions,omitempty"`
	EvidenceExpected        []string `json:"evidence_expected,omitempty"`
}

type SdkArtifactRegisterResponse struct {
	Service         string                      `json:"service"`
	Status          string                      `json:"status"`
	Caller          RequestContext              `json:"caller"`
	RequestSummary  ArtifactRegistrationSummary `json:"request_summary"`
	Registration    ArtifactRegistrationPlan    `json:"registration"`
	PlatformDomains []PlatformDomainPlan        `json:"platform_domains,omitempty"`
	Warnings        []string                    `json:"warnings,omitempty"`
}

type SdkEvidenceIngestRequest struct {
	EventType       EvidenceEventType  `json:"event_type"`
	Workload        WorkloadDescriptor `json:"workload"`
	Resource        ResourceDescriptor `json:"resource"`
	ArtifactProfile ArtifactProfile    `json:"artifact_profile,omitempty"`
	ArtifactDigest  string             `json:"artifact_digest,omitempty"`
	DecisionID      string             `json:"decision_id,omitempty"`
	Outcome         string             `json:"outcome,omitempty"`
	OccurredAt      time.Time          `json:"occurred_at,omitempty"`
	Purpose         string             `json:"purpose,omitempty"`
	Labels          []string           `json:"labels,omitempty"`
	Attributes      map[string]string  `json:"attributes,omitempty"`
}

type EvidenceIngestSummary struct {
	EventType             EvidenceEventType `json:"event_type"`
	WorkloadApplication   string            `json:"workload_application"`
	WorkloadEnvironment   string            `json:"workload_environment,omitempty"`
	WorkloadComponent     string            `json:"workload_component,omitempty"`
	ResourceKind          string            `json:"resource_kind"`
	ResourceID            string            `json:"resource_id,omitempty"`
	MimeType              string            `json:"mime_type,omitempty"`
	ArtifactProfile       ArtifactProfile   `json:"artifact_profile,omitempty"`
	ArtifactDigestPresent bool              `json:"artifact_digest_present"`
	DecisionIDPresent     bool              `json:"decision_id_present"`
	Outcome               string            `json:"outcome,omitempty"`
	OccurredAt            time.Time         `json:"occurred_at,omitempty"`
	Purpose               string            `json:"purpose,omitempty"`
	LabelCount            int               `json:"label_count"`
	AttributeCount        int               `json:"attribute_count"`
}

type EvidenceIngestionPlan struct {
	Accepted           bool     `json:"accepted"`
	RequiredScopes     []string `json:"required_scopes,omitempty"`
	PlaintextTransport string   `json:"plaintext_transport"`
	SendOnly           []string `json:"send_only,omitempty"`
	CorrelateBy        []string `json:"correlate_by,omitempty"`
}

type SdkEvidenceIngestResponse struct {
	Service         string                `json:"service"`
	Status          string                `json:"status"`
	Caller          RequestContext        `json:"caller"`
	RequestSummary  EvidenceIngestSummary `json:"request_summary"`
	Ingestion       EvidenceIngestionPlan `json:"ingestion"`
	PlatformDomains []PlatformDomainPlan  `json:"platform_domains,omitempty"`
	Warnings        []string              `json:"warnings,omitempty"`
}
