package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// secretFields are masked on read and kept-as-is when submitted unchanged.
var secretFields = map[string]string{
	"api_key":            "",
	"captcha_secret_key": "",
}

// hotFields can be applied without restarting the plugin process: they are
// read from the shared PluginConfig on every request. Everything else needs a
// plugin restart (components were built at boot).
var hotFields = map[string]bool{
	"appsec_inspect_body": true, "appsec_fail_open": true, "appsec_max_body": true,
	"static_bypass": true, "static_extensions": true, "log_level": true,
	"is_proxied_behind_cloudflare": true, "appsec_enabled": false,
}

// ConfigAPI exposes read/write access to the plugin configuration file.
type ConfigAPI struct {
	mu     sync.Mutex
	logger *logrus.Logger
	cfg    *config.PluginConfig
}

func NewConfigAPI(logger *logrus.Logger, cfg *config.PluginConfig) *ConfigAPI {
	return &ConfigAPI{logger: logger, cfg: cfg}
}

func (a *ConfigAPI) Register(mux *http.ServeMux) {
	mux.HandleFunc(info.UI_PATH+"api/config", a.handle)
	mux.HandleFunc(info.UI_PATH+"api/config-editor", a.editor)
}

func mask(v string) string {
	if len(v) > 4 {
		return "••••" + v[len(v)-4:]
	}
	if v == "" {
		return ""
	}
	return "••••"
}

// handle serves GET (sanitized JSON snapshot) and POST (merge + persist).
func (a *ConfigAPI) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.get(w)
	case http.MethodPost:
		a.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *ConfigAPI) get(w http.ResponseWriter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, err := yaml.Marshal(a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for f := range secretFields {
		if v, ok := m[f].(string); ok {
			m[f] = mask(v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"config": m})
}

func (a *ConfigAPI) post(w http.ResponseWriter, r *http.Request) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Serialize the current config to yaml, merge updates on top, re-validate.
	raw, err := yaml.Marshal(a.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var current map[string]interface{}
	yaml.Unmarshal(raw, &current)

	for k, v := range updates {
		if _, secret := secretFields[k]; secret {
			s, _ := v.(string)
			if s == "" || strings.HasPrefix(s, "••••") {
				continue // keep existing secret
			}
		}
		current[k] = v
	}

	merged, _ := yaml.Marshal(current)
	candidate := &config.PluginConfig{}
	if err := yaml.Unmarshal(merged, candidate); err != nil {
		http.Error(w, "invalid config values: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := candidate.PostProcess(); err != nil {
		http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := os.WriteFile(info.CONFIGURATION_FILE, merged, 0o600); err != nil {
		http.Error(w, "cannot write config file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	*a.cfg = *candidate // hot-apply shared fields
	a.logger.SetLevel(candidate.LogLevel)
	a.logger.Info("configuration updated via web API")

	restart := []string{}
	hot := []string{}
	for k := range updates {
		if hotFields[k] {
			hot = append(hot, k)
		} else {
			restart = append(restart, k)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"saved":            true,
		"applied_live":     hot,
		"restart_required": restart,
		"restart_hint":     "restart the plugin from the Zoraxy plugin page to apply",
	})
}

// editor serves a minimal built-in editor so the UI needs no external assets.
func (a *ConfigAPI) editor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(editorPage))
}
