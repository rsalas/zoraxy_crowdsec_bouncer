package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPostProcessDefaultsStreamUpdateFrequency(t *testing.T) {
	pluginConfig := PluginConfig{LogLevelString: "warning"}

	if err := pluginConfig.PostProcess(); err != nil {
		t.Fatalf("PostProcess() error = %v", err)
	}
	if pluginConfig.StreamUpdateFrequency != DefaultStreamUpdateFrequency {
		t.Fatalf("StreamUpdateFrequency = %q, want %q", pluginConfig.StreamUpdateFrequency, DefaultStreamUpdateFrequency)
	}
}

func TestLoadConfigCreatesDefaultOnMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir(%q) error = %v", tmpDir, err)
	}

	pluginConfig := PluginConfig{}
	err = pluginConfig.LoadConfig()
	if !errors.Is(err, ErrConfigCreated) {
		t.Fatalf("LoadConfig() error = %v, want ErrConfigCreated", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, "config.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(config.yaml) error = %v", err)
	}
	if len(content) == 0 {
		t.Fatal("config.yaml should not be empty")
	}
}

func TestMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name       string
		cfg        PluginConfig
		wantFields []string
	}{
		{
			name: "missing both api key and agent url",
			cfg: PluginConfig{
				APIKey:   "",
				AgentUrl: "",
			},
			wantFields: []string{"api_key", "agent_url"},
		},
		{
			name: "placeholder api key",
			cfg: PluginConfig{
				APIKey:   PlaceholderAPIKey,
				AgentUrl: "http://127.0.0.1:8080",
			},
			wantFields: []string{"api_key"},
		},
		{
			name: "all required fields present",
			cfg: PluginConfig{
				APIKey:   "real-key",
				AgentUrl: "http://127.0.0.1:8080",
			},
			wantFields: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.MissingRequiredFields()
			if len(got) != len(tc.wantFields) {
				t.Fatalf("MissingRequiredFields() = %v, want %v", got, tc.wantFields)
			}

			for i := range got {
				if got[i] != tc.wantFields[i] {
					t.Fatalf("MissingRequiredFields() = %v, want %v", got, tc.wantFields)
				}
			}
		})
	}
}

func TestAppSecExempt(t *testing.T) {
	cfg := PluginConfig{AppSecExemptHosts: " Auth.Example.com ,idp.example.org ,,"}
	if err := cfg.PostProcess(); err != nil {
		t.Fatalf("PostProcess() error = %v", err)
	}

	tests := []struct {
		host string
		want bool
	}{
		{"auth.example.com", true},
		{"AUTH.EXAMPLE.COM", true},
		{"auth.example.com:443", true},
		{"idp.example.org", true},
		{"idp.example.org:8443", true},
		{"other.example.com", false},
		{"sub.auth.example.com", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := cfg.AppSecExempt(tc.host); got != tc.want {
			t.Errorf("AppSecExempt(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}

	empty := PluginConfig{}
	if err := empty.PostProcess(); err != nil {
		t.Fatalf("PostProcess() error = %v", err)
	}
	if empty.AppSecExempt("auth.example.com") {
		t.Error("AppSecExempt on empty list should be false")
	}
}
