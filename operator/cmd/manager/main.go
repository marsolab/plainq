// Command manager runs the PlainQ operator.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/controller"
	plainqwebhook "github.com/marsolab/plainq/operator/internal/webhook"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(plainqv1alpha1.AddToScheme(scheme))
}

// config holds the manager's flags.
type config struct {
	metricsAddr    string
	probeAddr      string
	webhookPort    int
	certDir        string
	leaderElection bool
	leaderElectID  string
	namespaces     string
	enableWebhooks bool
	zapOptions     zap.Options
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "plainq-operator: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&cfg.zapOptions)))
	logger := ctrl.Log.WithName("setup")

	options := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: cfg.metricsAddr},
		HealthProbeBindAddress: cfg.probeAddr,
		LeaderElection:         cfg.leaderElection,
		LeaderElectionID:       cfg.leaderElectID,
	}

	// Restricting the cache to named namespaces is how a shared cluster runs
	// the operator without granting it a view of everything.
	if namespaces := splitNamespaces(cfg.namespaces); len(namespaces) > 0 {
		byNamespace := map[string]cache.Config{}
		for _, ns := range namespaces {
			byNamespace[ns] = cache.Config{}
		}

		options.Cache = cache.Options{DefaultNamespaces: byNamespace}

		logger.Info("watching a restricted set of namespaces", "namespaces", namespaces)
	}

	if cfg.enableWebhooks {
		options.WebhookServer = webhook.NewServer(webhook.Options{
			Port:    cfg.webhookPort,
			CertDir: cfg.certDir,
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	clients := controller.NewClientFactory(mgr.GetClient())

	reconcilers := []interface{ SetupWithManager(ctrl.Manager) error }{
		&controller.PlainQReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("plainq"),
			Clients:  clients,
		},
		&controller.PlainQQueueReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("plainqqueue"),
			Clients:  clients,
		},
		&controller.PlainQTopicReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("plainqtopic"),
			Clients:  clients,
		},
		&controller.PlainQAccountReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("plainqaccount"),
			Clients:  clients,
		},
	}

	for _, r := range reconcilers {
		if err := r.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up reconciler %T: %w", r, err)
		}
	}

	if cfg.enableWebhooks {
		if err := plainqwebhook.SetupAll(mgr); err != nil {
			return fmt.Errorf("set up webhooks: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add ready check: %w", err)
	}

	logger.Info("starting the PlainQ operator")

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}

	return nil
}

func parseFlags() *config {
	cfg := &config{zapOptions: zap.Options{Development: false}}

	flag.StringVar(&cfg.metricsAddr, "metrics-bind-address", ":8080",
		"Address the metrics endpoint binds to.")
	flag.StringVar(&cfg.probeAddr, "health-probe-bind-address", ":8081",
		"Address the health probe endpoint binds to.")
	flag.IntVar(&cfg.webhookPort, "webhook-port", 9443,
		"Port the admission webhook server binds to.")
	flag.StringVar(&cfg.certDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs",
		"Directory holding the webhook server's TLS certificate and key.")
	flag.BoolVar(&cfg.leaderElection, "leader-elect", true,
		"Elect a leader so only one manager reconciles at a time.")
	flag.StringVar(&cfg.leaderElectID, "leader-election-id", "plainq-operator.plainq.dev",
		"Name of the lease used for leader election.")
	flag.StringVar(&cfg.namespaces, "namespaces", "",
		"Comma-separated namespaces to watch. Empty watches all of them.")
	flag.BoolVar(&cfg.enableWebhooks, "enable-webhooks", true,
		"Serve the admission webhooks. Turn off for local runs without certificates.")

	cfg.zapOptions.BindFlags(flag.CommandLine)
	flag.Parse()

	return cfg
}

func splitNamespaces(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	var namespaces []string

	for _, ns := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(ns); trimmed != "" {
			namespaces = append(namespaces, trimmed)
		}
	}

	return namespaces
}
