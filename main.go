package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/appsec"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/captcha"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/dynamiccapture"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/relay"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/web"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func startBouncer(g *errgroup.Group, ctx context.Context, pluginConfig *config.PluginConfig, logger *logrus.Logger, decisionCache *decisions.Cache, metricsHandler *metrics.MetricsHandler) {

	// Initialize the CrowdSec stream bouncer. It keeps the decision cache local
	// and only requests deltas from LAPI at the configured interval.
	bouncer := &csbouncer.StreamBouncer{
		APIKey:              pluginConfig.APIKey,
		APIUrl:              pluginConfig.AgentUrl,
		UserAgent:           info.BOUNCER_USER_AGENT,
		TickerInterval:      pluginConfig.StreamUpdateFrequency,
		Scopes:              []string{"ip", "range"},
		RetryInitialConnect: true,
	}
	if err := bouncer.Init(); err != nil {
		logger.Fatalf("unable to initialize bouncer: %v", err)
	}

	g.Go(func() error {
		if err := bouncer.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	})

	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case update, ok := <-bouncer.Stream:
				if !ok {
					return nil
				}
				decisionCache.Apply(update)
			}
		}
	})

	// initialize and start a metrics provider
	metricsProvider, err := csbouncer.NewMetricsProvider(
		bouncer.APIClient,
		info.BOUNCER_TYPE,
		metricsHandler.MetricsUpdater,
		logger,
	)
	if err != nil {
		logger.Fatalf("unable to initialize metrics provider: %v", err)
		panic(err)
	}

	g.Go(func() error {
		return metricsProvider.Run(ctx)
	})
}

func main() {
	// Serve the plugin introspect
	// This will print the plugin introspect and exit if the -introspect flag is provided
	pluginIntoSpect := &plugin.IntroSpect{
		ID:            info.PLUGIN_ID,
		Name:          info.PLUGIN_NAME,
		Author:        info.PLUGIN_AUTHOR,
		AuthorContact: info.PLUGIN_AUTHOR_CONTACT,
		Description:   info.PLUGIN_DESCRIPTION,
		URL:           info.PLUGIN_URL,
		Type:          plugin.PluginType_Router,
		VersionMajor:  info.VERSION_MAJOR,
		VersionMinor:  info.VERSION_MINOR,
		VersionPatch:  info.VERSION_PATCH,

		DynamicCaptureSniff:   info.DYNAMIC_CAPTURE_SNIFF,
		DynamicCaptureIngress: info.DYNAMIC_CAPTURE_INGRESS,

		UIPath: info.UI_PATH,
	}
	runtimeCfg, err := plugin.ServeAndRecvSpec(pluginIntoSpect)
	if err != nil {
		//Terminate or enter standalone mode here
		panic(err)
	}

	// load the configuration
	pluginConfig := &config.PluginConfig{}
	if err := pluginConfig.LoadConfig(); err != nil {
		if errors.Is(err, config.ErrConfigCreated) {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return
		}
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		panic(err)
	}

	// initialize the logger
	logger := logrus.StandardLogger()
	logger.Level = pluginConfig.LogLevel

	missingFields := pluginConfig.MissingRequiredFields()
	onboardingMode := len(missingFields) > 0
	configStatus := web.ConfigStatusResponse{
		Onboarding:      onboardingMode,
		BlockingEnabled: !onboardingMode,
	}
	if onboardingMode {
		configStatus.MissingFields = missingFields
		configStatus.Message = fmt.Sprintf(
			"Bouncer onboarding mode: update %s in %s, then restart the plugin.",
			strings.Join(missingFields, ", "),
			info.CONFIGURATION_FILE,
		)
		logger.Warn(configStatus.Message)
	}

	// initialize the path router
	pathRouter := plugin.NewPathRouter()
	pathRouter.SetDebugPrintMode(pluginConfig.LogLevel >= logrus.DebugLevel)

	// errGroup and context for plugin goroutines
	g, ctx := errgroup.WithContext(context.Background())
	decisionCache := decisions.NewCache()

	// initialize metrics and register custom and CrowdSec metrics
	metricsHandler := metrics.NewMetricsHandler(logger)
	metrics.Map.MustRegisterAll()
	prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)

	if !onboardingMode {
		startBouncer(g, ctx, pluginConfig, logger, decisionCache, metricsHandler)
	}

	// AppSec (WAF) checker. Inspects request URL and headers inline; body
	// inspection additionally captures body-carrying requests and replays the
	// clean ones back through Zoraxy.
	var appsecChecker *appsec.Checker
	var relayClient *relay.Client
	var marker *relay.Marker
	verdicts := dynamiccapture.NewVerdicts()
	if pluginConfig.AppSecEnabled && !onboardingMode {
		appsecChecker = appsec.NewChecker(
			pluginConfig.AppSecURL,
			pluginConfig.APIKey,
			pluginConfig.AppSecTimeoutValue,
			pluginConfig.AppSecFailOpen,
		)
		logger.Infof("AppSec inspection enabled, forwarding request metadata to %s", pluginConfig.AppSecURL)

		if pluginConfig.AppSecInspectBody {
			var err error
			marker, err = relay.NewMarker()
			if err != nil {
				logger.Fatalf("unable to create relay marker: %v", err)
			}
			relayClient = relay.NewClient(pluginConfig.AppSecRelayURL, 30*time.Second)
			logger.Infof("AppSec body inspection enabled, clean requests replayed via %s", pluginConfig.AppSecRelayURL)
		}
	}

	// CAPTCHA remediation: CrowdSec "captcha" decisions serve a challenge
	// instead of blocking outright.
	var captchaManager *captcha.Manager
	if pluginConfig.CaptchaEnabled && !onboardingMode {
		var err error
		captchaManager, err = captcha.New(
			pluginConfig.CaptchaProvider,
			pluginConfig.CaptchaSiteKey,
			pluginConfig.CaptchaSecretKey,
			pluginConfig.CaptchaSessionDurationVal,
		)
		if err != nil {
			logger.Fatalf("unable to initialize captcha: %v", err)
		}
		logger.Infof("Captcha remediation enabled (%s)", pluginConfig.CaptchaProvider)
	}

	/*
		Dynamic Captures

		If there is not a decision matching the requests IP, we will skip the request so
		that it can be handled by the next plugin or Zoraxy itself.
		If there is a decision for the request IP, we will accept the request and handle it in the dynamic capture handler.
		We will also print the request information to the console for debugging purposes.
	*/
	pathRouter.RegisterDynamicSniffHandler("/d_sniff", http.DefaultServeMux, func(dsfr *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
		return dynamiccapture.SniffHandler(logger, metricsHandler, pluginConfig, dsfr, decisionCache, appsecChecker, marker, verdicts, captchaManager)
	})
	pathRouter.RegisterDynamicCaptureHandle(info.DYNAMIC_CAPTURE_INGRESS, http.DefaultServeMux, func(w http.ResponseWriter, r *http.Request) {
		dynamiccapture.CaptureHandler(logger, metricsHandler, appsecChecker, relayClient, marker, verdicts, captchaManager, pluginConfig.AppSecMaxBody, w, r)
	})

	// Config management API + built-in editor, served on the plugin UI path.
	web.NewConfigAPI(logger, pluginConfig).Register(http.DefaultServeMux)

	web.InitWebServer(logger, g, ctx, runtimeCfg.Port, configStatus)

	// Handle signals
	utils.StartSignalHandler(logger, g, ctx)

	// wait for the goroutines to finish
	if err := g.Wait(); err != nil && !(errors.Is(err, utils.SignalTermError) || errors.Is(err, utils.SignalIntError)) {
		fmt.Printf("Process terminated with error of type %T: %v\n", err, err)
		logrus.Fatalf("process terminated with error: %v", err)
	} else {
		logrus.Info("process terminated gracefully")
	}
}
