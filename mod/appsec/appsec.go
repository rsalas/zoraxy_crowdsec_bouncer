// Package appsec implements forwarding of incoming requests to a CrowdSec
// AppSec engine for in-band (blocking) inspection.
package appsec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Hop-by-hop headers that must not be forwarded to the AppSec engine.
var stripHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	// Internal relay marker must never reach the engine or upstream.
	"X-Zcsb-Relay": {},
}

type Checker struct {
	url      string
	apiKey   string
	client   *http.Client
	failOpen bool
}

func NewChecker(url, apiKey string, timeout time.Duration, failOpen bool) *Checker {
	return &Checker{
		url:      url,
		apiKey:   apiKey,
		failOpen: failOpen,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// FailOpen reports whether the checker is configured to allow requests when
// the AppSec engine is unreachable.
func (c *Checker) FailOpen() bool {
	return c.failOpen
}

// Check forwards a request (method, URI, headers and optional body) to the
// AppSec engine and reports whether it must be blocked: in-band rule matches
// are answered with 403 by the engine.
//
// An error is returned when the engine cannot be reached or answers with an
// unexpected status code; the caller decides based on FailOpen.
func (c *Checker) Check(ctx context.Context, method, uri, host string, header http.Header, body io.Reader, clientIP string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url+uri, body)
	if err != nil {
		return false, fmt.Errorf("building appsec request: %w", err)
	}

	for name, values := range header {
		if _, skip := stripHeaders[http.CanonicalHeaderKey(name)]; skip {
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	req.Header.Set("X-Crowdsec-Appsec-Ip", clientIP)
	req.Header.Set("X-Crowdsec-Appsec-Uri", uri)
	req.Header.Set("X-Crowdsec-Appsec-Host", host)
	req.Header.Set("X-Crowdsec-Appsec-Verb", method)
	req.Header.Set("X-Crowdsec-Appsec-Api-Key", c.apiKey)
	if ua := header.Get("User-Agent"); ua != "" {
		req.Header.Set("X-Crowdsec-Appsec-User-Agent", ua)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("appsec request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return false, nil
	case http.StatusForbidden:
		return true, nil
	default:
		return false, fmt.Errorf("unexpected appsec status code: %d", resp.StatusCode)
	}
}
