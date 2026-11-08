package dynamiccapture

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/appsec"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/captcha"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/relay"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/sirupsen/logrus"
)

var ingressAppsecDecision = &models.Decision{Origin: ptr.Of("crowdsec-appsec-body")}

// CaptureHandler handles requests accepted by the sniff handler.
//
//   - VerdictBlock: the request is malicious (banned IP or in-band match),
//     answer 403.
//   - VerdictInspect: the request carries a body the sniff handler could not
//     see. The full request, body included, is sent to the AppSec engine;
//     clean requests are replayed back to Zoraxy with a signed relay marker
//     so Zoraxy proxies them to the real upstream.
func CaptureHandler(logger *logrus.Logger, metricsHandler *metrics.MetricsHandler, appsecChecker *appsec.Checker, relayClient *relay.Client, marker *relay.Marker, verdicts *Verdicts, captchaManager *captcha.Manager, maxInspectBody int64, w http.ResponseWriter, r *http.Request) {
	uuid := r.Header.Get("X-Zoraxy-RequestID")

	verdict, ok := verdicts.Take(uuid)
	if !ok {
		// Unknown request: safest default is to re-inspect fully.
		verdict = VerdictInspect
	}

	if verdict == VerdictBlock {
		logger.Infof("Request blocked: %s %s", r.Method, r.RequestURI)
		forbidden(w)
		return
	}

	if verdict == VerdictCaptcha {
		handleCaptcha(logger, captchaManager, w, r)
		return
	}

	// VerdictInspect: full AppSec check with body.
	if appsecChecker == nil || relayClient == nil || marker == nil {
		logger.Warn("body inspection requested but relay/appsec not configured")
		forbidden(w)
		return
	}

	ip := ingressClientIP(r)

	// Read up to maxInspectBody for inspection; the remainder is appended for
	// the relay so the upstream still receives the complete body.
	inspectBytes, err := io.ReadAll(io.LimitReader(r.Body, maxInspectBody))
	if err != nil {
		logger.Warnf("unable to read request body for inspection: %v", err)
		forbidden(w)
		return
	}

	blocked, err := appsecChecker.Check(context.Background(), r.Method, r.RequestURI, r.Host, r.Header, bytes.NewReader(inspectBytes), ip)
	switch {
	case err != nil:
		if !appsecChecker.FailOpen() {
			logger.Errorf("AppSec body check failed, blocking request (fail-closed): %v", err)
			forbidden(w)
			return
		}
		logger.Warnf("AppSec body check failed, relaying uninspected (fail-open): %v", err)
	case blocked:
		logger.Infof("AppSec blocked request with body: %s %s from %s", r.Method, r.RequestURI, ip)
		metricsHandler.MarkRequestDropped(r.Host, ingressAppsecDecision)
		forbidden(w)
		return
	}

	// Clean: replay to Zoraxy. The relayed body is the inspected prefix plus
	// whatever bytes remained unread beyond the inspection limit.
	relayBody := io.MultiReader(bytes.NewReader(inspectBytes), r.Body)
	if err := relayClient.Relay(w, r, relayBody, r.ContentLength, marker, logger); err != nil {
		logger.Errorf("relay of inspected request failed: %v", err)
	}
}

// ingressClientIP resolves the client IP on the capture hop. Zoraxy's internal
// proxy forwards X-Forwarded-For with the original client address.
func ingressClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if ip, _, err := net.SplitHostPort(xff); err == nil {
			return ip
		}
		// XFF may hold a bare IP or a list; take the first.
		for i, c := range xff {
			if c == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// handleCaptcha serves the challenge page and processes its submission. A
// verified submission sets the proof cookie and redirects back to the
// originally requested URL (as a GET).
func handleCaptcha(logger *logrus.Logger, captchaManager *captcha.Manager, w http.ResponseWriter, r *http.Request) {
	if captchaManager == nil {
		logger.Warn("captcha verdict received but captcha is not configured")
		forbidden(w)
		return
	}

	ip := ingressClientIP(r)

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			if token := r.PostFormValue(captchaManager.TokenField()); token != "" {
				ok, err := captchaManager.Verify(token, ip)
				switch {
				case err != nil:
					logger.Warnf("captcha verification failed for %s: %v", ip, err)
				case ok:
					logger.Infof("captcha passed for %s", ip)
					captchaManager.SetPassCookie(w, ip)
					// Zoraxy's internal proxy rewrites Location headers of
					// redirects, so hand back a client-side refresh instead.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><script>location.replace(%s)</script></body></html>`,
						html.EscapeString(r.RequestURI), strconv.Quote(r.RequestURI))
					return
				default:
					logger.Infof("captcha rejected for %s", ip)
				}
			}
		}
	}

	captchaManager.ServeChallenge(w)
}

func forbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("Forbidden"))
}
