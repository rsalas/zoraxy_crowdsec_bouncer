package dynamiccapture

import (
	"io"
	"testing"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func newTestDSFR(method, host, uri string, headers map[string][]string) *plugin.DynamicSniffForwardRequest {
	return &plugin.DynamicSniffForwardRequest{
		Method:     method,
		Hostname:   host,
		Host:       host,
		RequestURI: uri,
		Header:     headers,
		RemoteAddr: "1.2.3.4:5678",
		ClientIP:   "1.2.3.4",
	}
}

func newTestConfig(t *testing.T, exempt string) *config.PluginConfig {
	t.Helper()
	cfg := &config.PluginConfig{
		AppSecEnabled:     true,
		AppSecInspectBody: true,
		AppSecExemptHosts: exempt,
	}
	if err := cfg.PostProcess(); err != nil {
		t.Fatalf("PostProcess() error = %v", err)
	}
	return cfg
}

func TestSniffExemptHostSkipsBodyCapture(t *testing.T) {
	cfg := newTestConfig(t, "auth.example.com")
	verdicts := NewVerdicts()
	dsfr := newTestDSFR("POST", "auth.example.com", "/api/v3/flows/executor", map[string][]string{
		"Content-Length": {"42"},
	})

	got := SniffHandler(testLogger(), metrics.NewMetricsHandler(testLogger()), cfg, dsfr, decisions.NewCache(), nil, nil, verdicts, nil)
	if got != plugin.SniffResultSkip {
		t.Fatalf("SniffHandler() = %v, want SniffResultSkip for exempt host", got)
	}
}

func TestSniffNonExemptHostCapturesBody(t *testing.T) {
	cfg := newTestConfig(t, "auth.example.com")
	verdicts := NewVerdicts()
	dsfr := newTestDSFR("POST", "app.example.com", "/submit", map[string][]string{
		"Content-Length": {"42"},
	})

	got := SniffHandler(testLogger(), metrics.NewMetricsHandler(testLogger()), cfg, dsfr, decisions.NewCache(), nil, nil, verdicts, nil)
	if got != plugin.SniffResultAccept {
		t.Fatalf("SniffHandler() = %v, want SniffResultAccept for body capture", got)
	}
}

func TestSniffExemptHostStillAppliesBan(t *testing.T) {
	cfg := newTestConfig(t, "auth.example.com")
	cache := decisions.NewCache()
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{{
		ID:     1,
		Scope:  ptr.Of("ip"),
		Value:  ptr.Of("1.2.3.4"),
		Type:   ptr.Of("ban"),
		Origin: ptr.Of("test"),
	}}})
	verdicts := NewVerdicts()
	dsfr := newTestDSFR("GET", "auth.example.com", "/api/v3/", nil)

	got := SniffHandler(testLogger(), metrics.NewMetricsHandler(testLogger()), cfg, dsfr, cache, nil, nil, verdicts, nil)
	if got != plugin.SniffResultAccept {
		t.Fatalf("SniffHandler() = %v, want SniffResultAccept: ban decisions must still apply on exempt hosts", got)
	}
}
