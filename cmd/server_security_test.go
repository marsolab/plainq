package main

import (
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/cluster"
	"github.com/marsolab/plainq/internal/server/config"
)

func TestValidateAgentSecurity(t *testing.T) {
	t.Parallel()

	valid := func() config.Config {
		return config.Config{
			AgentEnable:                true,
			AgentAuthIssuer:            "plainq",
			AgentAuthAudience:          "plainq-agents",
			AgentAuthJWTSecret:         strings.Repeat("s", 32),
			AgentAccessTokenTTL:        5 * time.Minute,
			AgentRateRequestsPerSecond: 100,
			AgentRateBurst:             200,
			GRPCAddr:                   ":8080",
			GRPCTLSMode:                "server",
			GRPCTLSCertFile:            "/tls/tls.crt",
			GRPCTLSKeyFile:             "/tls/tls.key",
		}
	}

	for name, mutate := range map[string]func(*config.Config, *cluster.Config){
		"short secret": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentAuthJWTSecret = "short"
		},
		"missing issuer": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentAuthIssuer = ""
		},
		"missing audience": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentAuthAudience = ""
		},
		"zero ttl": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentAccessTokenTTL = 0
		},
		"long ttl": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentAccessTokenTTL = 16 * time.Minute
		},
		"invalid rate": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentRateRequestsPerSecond = 0
		},
		"invalid burst": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentRateBurst = 0
		},
		"insecure wildcard": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentDevelopmentInsecureTransport = true
			cfg.GRPCAddr = ":8080"
		},
		"insecure non-loopback": func(cfg *config.Config, _ *cluster.Config) {
			cfg.AgentDevelopmentInsecureTransport = true
			cfg.GRPCAddr = "192.0.2.1:8080"
		},
		"invalid tls mode": func(cfg *config.Config, _ *cluster.Config) {
			cfg.GRPCTLSMode = "off"
		},
		"missing tls cert": func(cfg *config.Config, _ *cluster.Config) {
			cfg.GRPCTLSCertFile = ""
		},
		"missing tls key": func(cfg *config.Config, _ *cluster.Config) {
			cfg.GRPCTLSKeyFile = ""
		},
		"mutual missing client ca": func(cfg *config.Config, _ *cluster.Config) {
			cfg.GRPCTLSMode = "mutual"
		},
		"cluster missing advertise": func(cfg *config.Config, clusterCfg *cluster.Config) {
			clusterCfg.Enabled = true
		},
		"cluster wildcard advertise": func(cfg *config.Config, clusterCfg *cluster.Config) {
			clusterCfg.Enabled = true
			cfg.GRPCAdvertiseAddr = "0.0.0.0:8080"
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := valid()
			clusterCfg := cluster.Config{}
			mutate(&cfg, &clusterCfg)

			if err := validateAgentSecurity(&cfg, &clusterCfg); err == nil {
				t.Fatal("validateAgentSecurity() unexpectedly succeeded")
			}
		})
	}

	t.Run("disabled ignores agent security fields", func(t *testing.T) {
		t.Parallel()

		if err := validateAgentSecurity(&config.Config{}, &cluster.Config{Enabled: true}); err != nil {
			t.Fatalf("validateAgentSecurity() error = %v", err)
		}
	})

	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		t.Run("development loopback "+addr, func(t *testing.T) {
			t.Parallel()

			cfg := valid()
			cfg.GRPCAddr = addr
			cfg.AgentDevelopmentInsecureTransport = true
			cfg.GRPCTLSMode = ""
			cfg.GRPCTLSCertFile = ""
			cfg.GRPCTLSKeyFile = ""

			if err := validateAgentSecurity(&cfg, &cluster.Config{}); err != nil {
				t.Fatalf("validateAgentSecurity() error = %v", err)
			}
		})
	}

	t.Run("server tls", func(t *testing.T) {
		t.Parallel()

		cfg := valid()
		if err := validateAgentSecurity(&cfg, &cluster.Config{}); err != nil {
			t.Fatalf("validateAgentSecurity() error = %v", err)
		}
	})

	t.Run("mutual tls", func(t *testing.T) {
		t.Parallel()

		cfg := valid()
		cfg.GRPCTLSMode = "mutual"
		cfg.GRPCTLSClientCAFile = "/tls/ca.crt"
		if err := validateAgentSecurity(&cfg, &cluster.Config{}); err != nil {
			t.Fatalf("validateAgentSecurity() error = %v", err)
		}
	})

	t.Run("cluster routable advertise", func(t *testing.T) {
		t.Parallel()

		cfg := valid()
		cfg.GRPCAdvertiseAddr = "plainq-0.plainq:8080"
		if err := validateAgentSecurity(&cfg, &cluster.Config{Enabled: true}); err != nil {
			t.Fatalf("validateAgentSecurity() error = %v", err)
		}
	})
}

func TestIsWildcardAddress(t *testing.T) {
	t.Parallel()

	for address, want := range map[string]bool{
		":8080":               true,
		"0.0.0.0:8080":        true,
		"[::]:8080":           true,
		"127.0.0.1:8080":      false,
		"plainq-0.local:8080": false,
		"malformed":           true,
	} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()

			if got := isWildcardAddress(address); got != want {
				t.Fatalf("isWildcardAddress(%q) = %v, want %v", address, got, want)
			}
		})
	}
}
