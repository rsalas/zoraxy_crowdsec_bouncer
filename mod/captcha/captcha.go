// Package captcha implements the "captcha" CrowdSec remediation: instead of a
// hard block, the client gets a challenge page (Cloudflare Turnstile or
// hCaptcha). Solving it sets a signed cookie that skips the challenge for a
// configurable duration.
package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CookieName carries the proof-of-humanity token.
const CookieName = "zcsb_captcha"

const (
	ProviderTurnstile = "turnstile"
	ProviderHCaptcha  = "hcaptcha"
)

// siteverify endpoints per provider.
var verifyURLs = map[string]string{
	ProviderTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	ProviderHCaptcha:  "https://hcaptcha.com/siteverify",
}

// responseField is the form field carrying the challenge token per provider.
var responseFields = map[string]string{
	ProviderTurnstile: "cf-turnstile-response",
	ProviderHCaptcha:  "h-captcha-response",
}

// widgetSnippets render the provider widget inside the challenge form.
var widgetSnippets = map[string]string{
	ProviderTurnstile: `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><div class="cf-turnstile" data-sitekey="%SITEKEY%"></div>`,
	ProviderHCaptcha:  `<script src="https://hcaptcha.com/1/api.js" async defer></script><div class="h-captcha" data-sitekey="%SITEKEY%"></div>`,
}

const challengePage = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security check</title>
<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f4f4f4}
.box{background:#fff;padding:2.5rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);text-align:center;max-width:420px}
h1{font-size:1.2rem;margin-bottom:.5rem}p{color:#666;font-size:.9rem}form{margin-top:1.5rem}
button{margin-top:1rem;padding:.6rem 2rem;border:0;border-radius:4px;background:#333;color:#fff;cursor:pointer}</style></head>
<body><div class="box"><h1>Security check</h1><p>Please complete the challenge to continue.</p>
<form method="POST">%WIDGET%<button type="submit">Verify</button></form></div></body></html>`

// Manager signs/verifies captcha-pass cookies and talks to the provider's
// siteverify endpoint.
type Manager struct {
	provider        string
	siteKey         string
	secretKey       string
	sessionDuration time.Duration
	secret          []byte
	client          *http.Client
}

func New(provider, siteKey, secretKey string, sessionDuration time.Duration) (*Manager, error) {
	if _, ok := verifyURLs[provider]; !ok {
		return nil, fmt.Errorf("unsupported captcha provider %q (expected turnstile or hcaptcha)", provider)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating captcha secret: %w", err)
	}
	return &Manager{
		provider:        provider,
		siteKey:         siteKey,
		secretKey:       secretKey,
		sessionDuration: sessionDuration,
		secret:          secret,
		client:          &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (m *Manager) sign(ip string, expiry int64) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(ip))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(expiry, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Passed reports whether the request carries a valid captcha cookie for ip.
func (m *Manager) Passed(header map[string][]string, ip string) bool {
	for name, values := range header {
		if http.CanonicalHeaderKey(name) != "Cookie" {
			continue
		}
		for _, cookieHeader := range values {
			for _, part := range strings.Split(cookieHeader, ";") {
				kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(kv) != 2 || kv[0] != CookieName {
					continue
				}
				fields := strings.SplitN(kv[1], ".", 2)
				if len(fields) != 2 {
					continue
				}
				expiry, err := strconv.ParseInt(fields[0], 10, 64)
				if err != nil || time.Now().Unix() > expiry {
					continue
				}
				if hmac.Equal([]byte(fields[1]), []byte(m.sign(ip, expiry))) {
					return true
				}
			}
		}
	}
	return false
}

// ServeChallenge writes the challenge page.
func (m *Manager) ServeChallenge(w http.ResponseWriter) {
	page := strings.ReplaceAll(challengePage, "%WIDGET%",
		strings.ReplaceAll(widgetSnippets[m.provider], "%SITEKEY%", html.EscapeString(m.siteKey)))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(page))
}

// TokenField returns the provider's response field name.
func (m *Manager) TokenField() string {
	return responseFields[m.provider]
}

// Verify calls the provider's siteverify endpoint for the submitted token.
func (m *Manager) Verify(token, ip string) (bool, error) {
	resp, err := m.client.PostForm(verifyURLs[m.provider], url.Values{
		"secret":   {m.secretKey},
		"response": {token},
		"remoteip": {ip},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	var result struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}
	return result.Success, nil
}

// SetPassCookie writes the signed proof cookie for this IP.
func (m *Manager) SetPassCookie(w http.ResponseWriter, ip string) {
	expiry := time.Now().Add(m.sessionDuration).Unix()
	value := fmt.Sprintf("%d.%s", expiry, m.sign(ip, expiry))
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.sessionDuration.Seconds()),
	})
}
