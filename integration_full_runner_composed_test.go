package sdk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	integrationFullBaseURLEnv     = "SDK_API_E2E_INTEGRATION_FULL_BASE_URL"
	integrationFullBearerTokenEnv = "SDK_API_E2E_INTEGRATION_FULL_BEARER_TOKEN"
	integrationFullTenantIDEnv    = "SDK_API_E2E_INTEGRATION_FULL_TENANT_ID"
	integrationFullUserIDEnv      = "SDK_API_E2E_INTEGRATION_FULL_USER_ID"
	integrationFullArtifactDirEnv = "SDK_API_E2E_INTEGRATION_FULL_ARTIFACT_DIR"
)

func TestRunIntegrationFullScenarioAgainstComposedEnvironment(t *testing.T) {
	baseURL := strings.TrimSpace(os.Getenv(integrationFullBaseURLEnv))
	if baseURL == "" {
		t.Skipf("set %s to run the composed integration-full scenario", integrationFullBaseURLEnv)
	}

	summary, err := RunIntegrationFullScenario(
		Options{
			BaseURL:     baseURL,
			BearerToken: strings.TrimSpace(os.Getenv(integrationFullBearerTokenEnv)),
			TenantID:    strings.TrimSpace(os.Getenv(integrationFullTenantIDEnv)),
			UserID:      strings.TrimSpace(os.Getenv(integrationFullUserIDEnv)),
		},
		integrationFullManifestPath(t),
	)
	if err != nil {
		if strings.Contains(err.Error(), "Rust bindings are not enabled") {
			t.Skip("rustbindings are required for the composed integration-full scenario")
		}
		t.Fatalf("expected composed integration-full scenario success, got %v", err)
	}
	if summary.Runner != "sdk-go" {
		t.Fatalf("expected sdk-go runner, got %q", summary.Runner)
	}
	if len(summary.Steps) != 15 {
		t.Fatalf("expected 15 steps, got %d", len(summary.Steps))
	}

	artifactDir := strings.TrimSpace(os.Getenv(integrationFullArtifactDirEnv))
	if artifactDir == "" {
		artifactDir = filepath.Join("output", "sdk_go_integration_full")
	}
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Fatalf("expected artifact dir creation, got %v", err)
	}
	body, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("expected summary serialization, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "summary.json"), body, 0o644); err != nil {
		t.Fatalf("expected summary artifact write, got %v", err)
	}
}
