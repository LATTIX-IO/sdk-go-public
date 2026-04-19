package sdk

import "encoding/json"

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

func (c *Client) ExchangeSession() (*SdkSessionExchangeResponse, error) {
	var out SdkSessionExchangeResponse
	if err := c.callJSON("exchange_session", nil, &out); err != nil {
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
