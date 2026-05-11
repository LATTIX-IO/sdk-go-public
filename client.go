package sdk

import (
	"encoding/base64"
	"encoding/json"
)

type binding interface {
	Call(method string, payload []byte) ([]byte, error)
	Close() error
}

type Client struct {
	binding binding
}

func NewClient(options Options) (*Client, error) {
	b, err := newBinding(options)
	if err != nil {
		return nil, err
	}
	return &Client{binding: b}, nil
}

func newClientWithBinding(b binding) *Client {
	return &Client{binding: b}
}

func (c *Client) Close() error {
	if c == nil || c.binding == nil {
		return nil
	}
	return c.binding.Close()
}

func (c *Client) Capabilities() (*SdkCapabilitiesResponse, error) {
	var out SdkCapabilitiesResponse
	if err := c.callJSON("capabilities", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) WhoAmI() (*CallerIdentityResponse, error) {
	var out CallerIdentityResponse
	if err := c.callJSON("whoami", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Bootstrap() (*SdkBootstrapResponse, error) {
	var out SdkBootstrapResponse
	if err := c.callJSON("bootstrap", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PrepareLocalProtection(content []byte, request LocalProtectionRequest) (*PreparedLocalProtection, error) {
	var out PreparedLocalProtection
	payload := map[string]any{
		"content_b64": base64.StdEncoding.EncodeToString(content),
		"request":     request,
	}
	if err := c.callJSON("prepare_local_protection", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GenerateCIDBinding(content []byte, request LocalProtectionRequest) (*LocalArtifactBinding, error) {
	var out LocalArtifactBinding
	payload := map[string]any{
		"content_b64": base64.StdEncoding.EncodeToString(content),
		"request":     request,
	}
	if err := c.callJSON("generate_cid_binding", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SignBytesWithDetachedSignature(signingKey []byte, content []byte, request LocalProtectionRequest) (*DetachedSignatureSignResult, error) {
	var out DetachedSignatureSignResult
	payload := map[string]any{
		"signing_key_b64": base64.StdEncoding.EncodeToString(signingKey),
		"content_b64":     base64.StdEncoding.EncodeToString(content),
		"request":         request,
	}
	if err := c.callJSON("sign_bytes_with_detached_signature", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) VerifyBytesWithDetachedSignature(verifyingKey []byte, content []byte, artifactBytes []byte) (*DetachedSignatureVerifyResult, error) {
	var out DetachedSignatureVerifyResult
	payload := map[string]any{
		"verifying_key_b64":  base64.StdEncoding.EncodeToString(verifyingKey),
		"content_b64":        base64.StdEncoding.EncodeToString(content),
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("verify_bytes_with_detached_signature", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ProtectionPlan(request SdkProtectionPlanRequest) (*SdkProtectionPlanResponse, error) {
	var out SdkProtectionPlanResponse
	if err := c.callJSON("protection_plan", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ProtectBytesWithTDF(key []byte, plaintext []byte, request LocalProtectionRequest) (*TDFProtectionResult, error) {
	var out TDFProtectionResult
	payload := map[string]any{
		"key_b64":       base64.StdEncoding.EncodeToString(key),
		"plaintext_b64": base64.StdEncoding.EncodeToString(plaintext),
		"request":       request,
	}
	if err := c.callJSON("protect_bytes_with_tdf", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ProtectBytesWithTDFUsingKeySource(keySource LocalSymmetricKeySource, plaintext []byte, request LocalProtectionRequest) (*TDFProtectionResult, error) {
	var out TDFProtectionResult
	payload := map[string]any{
		"key_source":    keySource,
		"plaintext_b64": base64.StdEncoding.EncodeToString(plaintext),
		"request":       request,
	}
	if err := c.callJSON("protect_bytes_with_tdf", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AccessBytesWithTDF(key []byte, artifactBytes []byte) (*TDFAccessResult, error) {
	var out TDFAccessResult
	payload := map[string]any{
		"key_b64":            base64.StdEncoding.EncodeToString(key),
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("access_bytes_with_tdf", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AccessBytesWithTDFUsingKeySource(keySource LocalSymmetricKeySource, artifactBytes []byte) (*TDFAccessResult, error) {
	var out TDFAccessResult
	payload := map[string]any{
		"key_source":         keySource,
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("access_bytes_with_tdf", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RewrapBytesWithTDF(currentKey []byte, newKey []byte, artifactBytes []byte) (*TDFRewrapResult, error) {
	var out TDFRewrapResult
	payload := map[string]any{
		"current_key_b64":    base64.StdEncoding.EncodeToString(currentKey),
		"new_key_b64":        base64.StdEncoding.EncodeToString(newKey),
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("rewrap_bytes_with_tdf", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil

}

func (c *Client) RewrapBytesWithTDFUsingKeySources(currentKeySource LocalSymmetricKeySource, newKeySource LocalSymmetricKeySource, artifactBytes []byte) (*TDFRewrapResult, error) {
	var out TDFRewrapResult
	payload := map[string]any{
		"current_key_source": currentKeySource,
		"new_key_source":     newKeySource,
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("rewrap_bytes_with_tdf", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SetTDFAttributes(key []byte, artifactBytes []byte, attributes map[string]string) (*TDFRewrapResult, error) {
	var out TDFRewrapResult
	payload := map[string]any{
		"key_b64":            base64.StdEncoding.EncodeToString(key),
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
		"attributes":         attributes,
	}
	if err := c.callJSON("set_tdf_attributes", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SetTDFAttributesUsingKeySource(keySource LocalSymmetricKeySource, artifactBytes []byte, attributes map[string]string) (*TDFRewrapResult, error) {
	var out TDFRewrapResult
	payload := map[string]any{
		"key_source":         keySource,
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
		"attributes":         attributes,
	}
	if err := c.callJSON("set_tdf_attributes", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) EditTDFAttributes(key []byte, artifactBytes []byte, edit LocalAttributeEdit) (*TDFRewrapResult, error) {
	var out TDFRewrapResult
	payload := map[string]any{
		"key_b64":            base64.StdEncoding.EncodeToString(key),
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
		"edit":               edit,
	}
	if err := c.callJSON("edit_tdf_attributes", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) EditTDFAttributesUsingKeySource(keySource LocalSymmetricKeySource, artifactBytes []byte, edit LocalAttributeEdit) (*TDFRewrapResult, error) {
	var out TDFRewrapResult
	payload := map[string]any{
		"key_source":         keySource,
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
		"edit":               edit,
	}
	if err := c.callJSON("edit_tdf_attributes", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ProtectBytesWithEnvelope(key []byte, plaintext []byte, request LocalProtectionRequest) (*EnvelopeProtectionResult, error) {
	var out EnvelopeProtectionResult
	payload := map[string]any{
		"key_b64":       base64.StdEncoding.EncodeToString(key),
		"plaintext_b64": base64.StdEncoding.EncodeToString(plaintext),
		"request":       request,
	}
	if err := c.callJSON("protect_bytes_with_envelope", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ProtectBytesWithEnvelopeUsingKeySource(keySource LocalSymmetricKeySource, plaintext []byte, request LocalProtectionRequest) (*EnvelopeProtectionResult, error) {
	var out EnvelopeProtectionResult
	payload := map[string]any{
		"key_source":    keySource,
		"plaintext_b64": base64.StdEncoding.EncodeToString(plaintext),
		"request":       request,
	}
	if err := c.callJSON("protect_bytes_with_envelope", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AccessBytesWithEnvelope(key []byte, artifactBytes []byte) (*EnvelopeAccessResult, error) {
	var out EnvelopeAccessResult
	payload := map[string]any{
		"key_b64":            base64.StdEncoding.EncodeToString(key),
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("access_bytes_with_envelope", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AccessBytesWithEnvelopeUsingKeySource(keySource LocalSymmetricKeySource, artifactBytes []byte) (*EnvelopeAccessResult, error) {
	var out EnvelopeAccessResult
	payload := map[string]any{
		"key_source":         keySource,
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("access_bytes_with_envelope", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RewrapBytesWithEnvelope(currentKey []byte, newKey []byte, artifactBytes []byte) (*EnvelopeRewrapResult, error) {
	var out EnvelopeRewrapResult
	payload := map[string]any{
		"current_key_b64":    base64.StdEncoding.EncodeToString(currentKey),
		"new_key_b64":        base64.StdEncoding.EncodeToString(newKey),
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("rewrap_bytes_with_envelope", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RewrapBytesWithEnvelopeUsingKeySources(currentKeySource LocalSymmetricKeySource, newKeySource LocalSymmetricKeySource, artifactBytes []byte) (*EnvelopeRewrapResult, error) {
	var out EnvelopeRewrapResult
	payload := map[string]any{
		"current_key_source": currentKeySource,
		"new_key_source":     newKeySource,
		"artifact_bytes_b64": base64.StdEncoding.EncodeToString(artifactBytes),
	}
	if err := c.callJSON("rewrap_bytes_with_envelope", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PolicyResolve(request SdkPolicyResolveRequest) (*SdkPolicyResolveResponse, error) {
	var out SdkPolicyResolveResponse
	if err := c.callJSON("policy_resolve", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) KeyAccessPlan(request SdkKeyAccessPlanRequest) (*SdkKeyAccessPlanResponse, error) {
	var out SdkKeyAccessPlanResponse
	if err := c.callJSON("key_access_plan", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ArtifactRegister(request SdkArtifactRegisterRequest) (*SdkArtifactRegisterResponse, error) {
	var out SdkArtifactRegisterResponse
	if err := c.callJSON("artifact_register", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Evidence(request SdkEvidenceIngestRequest) (*SdkEvidenceIngestResponse, error) {
	var out SdkEvidenceIngestResponse
	if err := c.callJSON("evidence", request, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) callJSON(method string, payload any, out any) error {
	if c == nil || c.binding == nil {
		return newBindingUnavailableError()
	}

	var requestBody []byte
	var err error
	if payload != nil {
		requestBody, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}

	responseBody, err := c.binding.Call(method, requestBody)
	if err != nil {
		return err
	}

	if out == nil {
		return nil
	}

	return json.Unmarshal(responseBody, out)
}
