package sdk

import "time"

type Options struct {
	BaseURL           string            `json:"base_url"`
	BearerToken       string            `json:"bearer_token,omitempty"`
	ClientID          string            `json:"client_id,omitempty"`
	ClientSecret      string            `json:"client_secret,omitempty"`
	TenantID          string            `json:"tenant_id,omitempty"`
	UserID            string            `json:"user_id,omitempty"`
	TimeoutSecs       uint64            `json:"timeout_secs,omitempty"`
	TokenExchangePath string            `json:"token_exchange_path,omitempty"`
	RequestedScopes   []string          `json:"requested_scopes,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
}

type AuthMode string

const (
	AuthModeTrustedHeaders             AuthMode = "trusted_headers"
	AuthModeBearerToken                AuthMode = "bearer_token"
	AuthModeBearerTokenOrTrustedHeader AuthMode = "bearer_token_or_trusted_headers"
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
	Caller                    RequestContext        `json:"caller"`
	EnforcementModel          string                `json:"enforcement_model"`
	PlaintextToPlatform       bool                  `json:"plaintext_to_platform"`
	PolicyResolutionMode      string                `json:"policy_resolution_mode"`
	SupportedOperations       []ProtectionOperation `json:"supported_operations,omitempty"`
	SupportedArtifactProfiles []ArtifactProfile     `json:"supported_artifact_profiles,omitempty"`
	PlatformDomains           []PlatformDomainPlan  `json:"platform_domains,omitempty"`
}

type SdkSessionExchangeResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   uint64 `json:"expires_in"`
	Scope       string `json:"scope"`
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	Subject     string `json:"subject"`
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
	ProtectLocally          bool            `json:"protect_locally"`
	LocalEnforcementLibrary string          `json:"local_enforcement_library"`
	SendPlaintextToPlatform bool            `json:"send_plaintext_to_platform"`
	SendOnly                []string        `json:"send_only,omitempty"`
	ArtifactProfile         ArtifactProfile `json:"artifact_profile"`
	KeyStrategy             string          `json:"key_strategy"`
	PolicyResolution        string          `json:"policy_resolution"`
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
	LocalCryptographicOperation bool            `json:"local_cryptographic_operation"`
	PlatformRole                string          `json:"platform_role"`
	SendPlaintextToPlatform     bool            `json:"send_plaintext_to_platform"`
	SendOnly                    []string        `json:"send_only,omitempty"`
	ArtifactProfile             ArtifactProfile `json:"artifact_profile"`
	AuthorizationStrategy       string          `json:"authorization_strategy"`
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
