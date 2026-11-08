// Package relay implements the "inspect then replay" mechanism used to give
// the plugin access to request bodies.
//
// Zoraxy's plugin API never exposes the request body to the sniff handler;
// the body only reaches the capture ingress, where the plugin must produce
// the response itself. To avoid reimplementing Zoraxy's proxy logic, clean
// requests are replayed back to the Zoraxy listener with a signed marker
// header. On the second pass the sniff handler recognizes the marker and
// skips, so Zoraxy routes the request normally to the upstream.
package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
)

// MarkerHeader is added to requests replayed by the plugin. It is signed per
// request so clients cannot forge it to bypass inspection.
const MarkerHeader = "X-Zcsb-Relay"

// Marker signs and verifies relay markers bound to method+URI. The secret is
// generated per process boot and never leaves the plugin.
type Marker struct {
	secret []byte
}

func NewMarker() (*Marker, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating relay secret: %w", err)
	}
	return &Marker{secret: secret}, nil
}

func (m *Marker) sign(method, uri string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(method))
	mac.Write([]byte{0})
	mac.Write([]byte(uri))
	return hex.EncodeToString(mac.Sum(nil))
}

// Set signs the marker for this request and writes it into the header map.
func (m *Marker) Set(h http.Header, method, uri string) {
	h.Set(MarkerHeader, m.sign(method, uri))
}

// Valid reports whether the header map carries a marker valid for this request.
func (m *Marker) Valid(h map[string][]string, method, uri string) bool {
	for name, values := range h {
		if http.CanonicalHeaderKey(name) != MarkerHeader {
			continue
		}
		for _, v := range values {
			if hmac.Equal([]byte(v), []byte(m.sign(method, uri))) {
				return true
			}
		}
	}
	return false
}

// Strip removes any client-supplied marker headers so they cannot reach the
// AppSec engine or the upstream.
func Strip(h http.Header) {
	h.Del(MarkerHeader)
}
