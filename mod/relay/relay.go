package relay

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Hop-by-hop headers stripped from the replayed request and from upstream
// responses (Go sets Content-Length and Transfer-Encoding itself).
var hopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// Client replays inspected requests back to the Zoraxy listener and streams
// the upstream response back to the caller.
type Client struct {
	target string // e.g. https://127.0.0.1
	http   *http.Client
}

func NewClient(target string, timeout time.Duration) *Client {
	return &Client{
		target: strings.TrimSuffix(target, "/"),
		http: &http.Client{
			Timeout: timeout,
			// The replay hop is loopback to our own Zoraxy, which serves a
			// self-signed certificate.
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
			// Do not follow redirects: relay them verbatim to the client.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Relay forwards the (already inspected) request to Zoraxy and copies the
// response back to w. The original request headers are preserved, including
// the client's X-Forwarded-For chain, so Zoraxy still resolves the real
// client IP (127.0.0.1 must be in trusted proxies).
func (c *Client) Relay(w http.ResponseWriter, r *http.Request, body io.Reader, contentLength int64, marker *Marker, logger *logrus.Logger) error {
	req, err := http.NewRequest(r.Method, c.target+r.RequestURI, body)
	if err != nil {
		return fmt.Errorf("building relay request: %w", err)
	}

	for name, values := range r.Header {
		if _, skip := hopHeaders[http.CanonicalHeaderKey(name)]; skip {
			continue
		}
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Host = r.Host
	req.ContentLength = contentLength

	// Any client-supplied marker was dropped above (it cannot be forged), set ours.
	marker.Set(req.Header, r.Method, r.RequestURI)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("relay to zoraxy failed: %w", err)
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		if _, skip := hopHeaders[http.CanonicalHeaderKey(name)]; skip {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}
