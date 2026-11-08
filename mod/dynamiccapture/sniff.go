package dynamiccapture

import (
	"context"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/appsec"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/captcha"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/relay"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/sirupsen/logrus"
)

var appsecDecision = &models.Decision{Origin: ptr.Of("crowdsec-appsec")}

// isStaticAsset reports whether the request is a safe-to-skip static asset
// fetch: GET or HEAD, no query string, path ending in a static extension.
// Requests carrying a query string are still inspected.
func isStaticAsset(dsfr *plugin.DynamicSniffForwardRequest, exts map[string]bool) bool {
	if dsfr.Method != http.MethodGet && dsfr.Method != http.MethodHead {
		return false
	}
	if strings.IndexByte(dsfr.RequestURI, '?') >= 0 {
		return false
	}
	return exts[strings.ToLower(path.Ext(dsfr.RequestURI))]
}

// hasBody reports whether the request carries a body the sniff handler cannot
// see (either Content-Length > 0 or chunked transfer encoding). Methods that
// typically carry a body but present no Content-Length are treated as
// possibly chunked so they are still inspected.
func hasBody(dsfr *plugin.DynamicSniffForwardRequest) bool {
	hasCL := false
	for name, values := range dsfr.Header {
		switch http.CanonicalHeaderKey(name) {
		case "Content-Length":
			hasCL = true
			for _, v := range values {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
					return true
				}
			}
		case "Transfer-Encoding":
			return true
		}
	}
	if !hasCL {
		switch dsfr.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			return true // no Content-Length on a body-capable method: probably chunked
		}
	}
	return false
}

// The Sniff handler decides whether to accept or skip a request.
// It is called for each request hitting a plugin-tagged endpoint.
//
// Order matters:
//  1. Signed relay marker: the request is our own replay of an already
//     inspected request -> skip so Zoraxy proxies it normally.
//  2. Ban decisions: cheap in-memory lookup -> capture for 403.
//  3. Body inspection: requests carrying a body are captured so the ingress
//     handler can run a full AppSec check and relay the clean ones.
//  4. Bodiless requests get the cheap AppSec URL+header check inline.
func SniffHandler(logger *logrus.Logger, metricsHandler *metrics.MetricsHandler, config *config.PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, decisions *decisions.Cache, appsecChecker *appsec.Checker, marker *relay.Marker, verdicts *Verdicts, captchaManager *captcha.Manager) plugin.SniffResult {
	defer metricsHandler.MarkRequestProcessed(dsfr.Hostname)

	// 1. Our own replayed request: inspected already, let Zoraxy route it.
	if marker != nil && marker.Valid(dsfr.Header, dsfr.Method, dsfr.RequestURI) {
		return plugin.SniffResultSkip
	}

	ip, err := utils.GetRealIP(logger, dsfr, config.IsProxiedBehindCloudflare)
	if err != nil {
		logger.Warnf("GetRealIP Got an error: %v for request: %s", err, dsfr.GetRequest().RequestURI)
		return plugin.SniffResultSkip
	}

	// 2. Decisions: bans block, captcha decisions challenge (unless the client
	// already passed and carries a valid cookie).
	if decision := decisions.GetDecision(ip); decision != nil {
		if captchaManager != nil && decision.Type != nil && strings.EqualFold(*decision.Type, "captcha") {
			if captchaManager.Passed(dsfr.Header, ip) {
				return plugin.SniffResultSkip
			}
			metricsHandler.MarkRequestDropped(dsfr.Hostname, decision)
			verdicts.Set(dsfr.GetRequestUUID(), VerdictCaptcha)
			return plugin.SniffResultAccept
		}
		logger.Debugf("Decision found for IP: %s", ip)
		metricsHandler.MarkRequestDropped(dsfr.Hostname, decision)
		verdicts.Set(dsfr.GetRequestUUID(), VerdictBlock)
		return plugin.SniffResultAccept
	}
	logger.Debugf("No decision found for IP: %s", ip)

	// 3. Static assets: GET/HEAD without query string to a known static
	// extension skip AppSec entirely (bans were already checked above).
	if config.StaticBypass && isStaticAsset(dsfr, config.StaticExtSet) {
		return plugin.SniffResultSkip
	}

	// 4. Body inspection path: capture so the ingress handler sees the body.
	if config.AppSecInspectBody && hasBody(dsfr) {
		verdicts.Set(dsfr.GetRequestUUID(), VerdictInspect)
		return plugin.SniffResultAccept
	}

	// 5. Cheap AppSec check on URL + headers for bodiless requests.
	if appsecChecker != nil {
		blocked, err := appsecChecker.Check(context.Background(), dsfr.Method, dsfr.RequestURI, dsfr.Host, dsfr.Header, nil, ip)
		switch {
		case err != nil:
			if appsecChecker.FailOpen() {
				logger.Warnf("AppSec check failed, allowing request (fail-open): %v", err)
			} else {
				logger.Errorf("AppSec check failed, blocking request (fail-closed): %v", err)
				verdicts.Set(dsfr.GetRequestUUID(), VerdictBlock)
				return plugin.SniffResultAccept
			}
		case blocked:
			logger.Infof("AppSec blocked request: %s %s from %s", dsfr.Method, dsfr.RequestURI, ip)
			metricsHandler.MarkRequestDropped(dsfr.Hostname, appsecDecision)
			verdicts.Set(dsfr.GetRequestUUID(), VerdictBlock)
			return plugin.SniffResultAccept
		}
	}

	return plugin.SniffResultSkip
}
