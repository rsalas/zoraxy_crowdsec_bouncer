package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const DefaultStreamUpdateFrequency = "10s"
const PlaceholderAPIKey = "<CROWDSEC_BOUNCER_API_KEY>"

var ErrConfigCreated = errors.New("config file created")

const defaultConfigTemplate = `# Crowdsec Bouncer Configuration
# api_key: "YOUR_CROWDSEC_BOUNCER_API_KEY"
agent_url: http://127.0.0.1:8080
# How frequently to request decision deltas from CrowdSec's stream endpoint.
stream_update_frequency: 10s
# Log level for the bouncer, options: trace, debug, info, warning, error
log_level: warning
# Set to true if zoraxy is proxied behind Cloudflare
is_proxied_behind_cloudflare: true
# CrowdSec AppSec (WAF) inspection of request URL and headers.
# NOTE: Zoraxy's plugin API does not expose the request body to the sniff
# handler, so body-based AppSec rules cannot match.
appsec_enabled: false
appsec_url: http://127.0.0.1:7422
appsec_timeout: 200ms
# If true, requests are allowed through when the AppSec engine is unreachable.
appsec_fail_open: true
# Inspect request bodies (POST/PUT): requests with a body are captured, sent
# fully to AppSec, and clean ones replayed back through Zoraxy so upstream
# routing, vdirs and load balancing still apply.
appsec_inspect_body: false
# Zoraxy listener where inspected requests are replayed.
appsec_relay_url: https://127.0.0.1
# Max body bytes sent to the AppSec engine (the full body is always relayed).
appsec_max_body: 1048576
# Skip AppSec inspection for static assets: GET/HEAD requests without query
# string whose path ends in one of these extensions. Ban decisions still apply.
static_bypass: true
static_extensions: .css,.js,.mjs,.map,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.avif,.woff,.woff2,.ttf,.eot,.otf,.mp4,.webm,.mp3,.wav,.ogg,.flac,.pdf,.txt
# CAPTCHA remediation: CrowdSec "captcha" decisions serve a challenge instead
# of blocking. Requires a Turnstile or hCaptcha site key + secret key.
captcha_enabled: false
captcha_provider: turnstile
captcha_site_key: ""
captcha_secret_key: ""
captcha_session_duration: 4h
`

type PluginConfig struct {
	APIKey                    string `yaml:"api_key"`
	AgentUrl                  string `yaml:"agent_url"`
	StreamUpdateFrequency     string `yaml:"stream_update_frequency"`
	LogLevelString            string `yaml:"log_level"`
	IsProxiedBehindCloudflare bool   `yaml:"is_proxied_behind_cloudflare"`
	AppSecEnabled             bool   `yaml:"appsec_enabled"`
	AppSecURL                 string `yaml:"appsec_url"`
	AppSecTimeout             string `yaml:"appsec_timeout"`
	AppSecFailOpen            bool   `yaml:"appsec_fail_open"`
	AppSecInspectBody         bool   `yaml:"appsec_inspect_body"`
	AppSecRelayURL            string `yaml:"appsec_relay_url"`
	AppSecMaxBody             int64  `yaml:"appsec_max_body"`
	StaticBypass              bool   `yaml:"static_bypass"`
	StaticExtensions          string `yaml:"static_extensions"`
	CaptchaEnabled            bool   `yaml:"captcha_enabled"`
	CaptchaProvider           string `yaml:"captcha_provider"`
	CaptchaSiteKey            string `yaml:"captcha_site_key"`
	CaptchaSecretKey          string `yaml:"captcha_secret_key"`
	CaptchaSessionDuration    string `yaml:"captcha_session_duration"`

	LogLevel                  logrus.Level    `yaml:"-"`
	AppSecTimeoutValue        time.Duration   `yaml:"-"`
	StaticExtSet              map[string]bool `yaml:"-"`
	CaptchaSessionDurationVal time.Duration   `yaml:"-"`
}

func (p *PluginConfig) MissingRequiredFields() []string {
	missing := make([]string, 0, 2)

	trimmedAPIKey := strings.TrimSpace(p.APIKey)
	if trimmedAPIKey == "" || trimmedAPIKey == PlaceholderAPIKey {
		missing = append(missing, "api_key")
	}

	if strings.TrimSpace(p.AgentUrl) == "" {
		missing = append(missing, "agent_url")
	}

	if p.AppSecEnabled && strings.TrimSpace(p.AppSecURL) == "" {
		missing = append(missing, "appsec_url")
	}

	return missing
}

func (p *PluginConfig) PostProcess() error {
	// This function can be used to perform any post-processing on the configuration
	// For now, it populates the LogLevel based on the LogLevelString
	// parse the log level string into a logrus Level
	if p.LogLevelString == "" {
		p.LogLevelString = "warning"
	}

	level, err := logrus.ParseLevel(p.LogLevelString)
	if err != nil {
		return fmt.Errorf("unable to parse log level: %w", err)
	}
	p.LogLevel = level

	if p.StreamUpdateFrequency == "" {
		p.StreamUpdateFrequency = DefaultStreamUpdateFrequency
	}

	if p.AppSecTimeout == "" {
		p.AppSecTimeout = "200ms"
	}
	timeout, err := time.ParseDuration(p.AppSecTimeout)
	if err != nil {
		return fmt.Errorf("unable to parse appsec_timeout: %w", err)
	}
	p.AppSecTimeoutValue = timeout

	if p.AppSecInspectBody && !p.AppSecEnabled {
		return errors.New("appsec_inspect_body requires appsec_enabled")
	}
	if p.AppSecRelayURL == "" {
		p.AppSecRelayURL = "https://127.0.0.1"
	}
	if p.AppSecMaxBody <= 0 {
		p.AppSecMaxBody = 1048576
	}

	if p.StaticExtensions == "" {
		p.StaticExtensions = ".css,.js,.mjs,.map,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.avif,.woff,.woff2,.ttf,.eot,.otf,.mp4,.webm,.mp3,.wav,.ogg,.flac,.pdf,.txt"
	}
	p.StaticExtSet = make(map[string]bool)
	for _, ext := range strings.Split(p.StaticExtensions, ",") {
		ext = strings.TrimSpace(strings.ToLower(ext))
		if ext != "" {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			p.StaticExtSet[ext] = true
		}
	}

	if p.CaptchaEnabled {
		if p.CaptchaProvider == "" {
			p.CaptchaProvider = "turnstile"
		}
		if strings.TrimSpace(p.CaptchaSiteKey) == "" || strings.TrimSpace(p.CaptchaSecretKey) == "" {
			return errors.New("captcha_enabled requires captcha_site_key and captcha_secret_key")
		}
		if p.CaptchaSessionDuration == "" {
			p.CaptchaSessionDuration = "4h"
		}
		d, err := time.ParseDuration(p.CaptchaSessionDuration)
		if err != nil {
			return fmt.Errorf("unable to parse captcha_session_duration: %w", err)
		}
		p.CaptchaSessionDurationVal = d
	}

	return nil
}

func (p *PluginConfig) LoadConfig() error {
	configFile, err := os.Open(info.CONFIGURATION_FILE)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if writeErr := os.WriteFile(info.CONFIGURATION_FILE, []byte(defaultConfigTemplate), 0o644); writeErr != nil {
				return fmt.Errorf("unable to create default config file: %w", writeErr)
			}
			return fmt.Errorf("%w: %s (please edit api_key and agent_url, then restart)", ErrConfigCreated, info.CONFIGURATION_FILE)
		}
		return fmt.Errorf("unable to open config file: %w", err)
	}
	defer configFile.Close()

	content, err := io.ReadAll(configFile)
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	if err := yaml.Unmarshal(content, p); err != nil {
		return fmt.Errorf("unable to unmarshal config file: %w", err)
	}

	// parse the log level string into a logrus Level
	if err := p.PostProcess(); err != nil {
		return fmt.Errorf("unable to post-process config: %w", err)
	}

	return nil
}
