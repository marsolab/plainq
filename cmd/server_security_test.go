package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/plainq/internal/cluster"
	"github.com/marsolab/plainq/internal/server"
	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/interceptor"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/plainq/internal/server/service/queue"
	"github.com/marsolab/servekit/authkit/jwtkit"
	"github.com/marsolab/servekit/logkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type protectedLegacyAccountStorage struct{ account.Storage }

func (protectedLegacyAccountStorage) IsAccessTokenDenied(context.Context, string) (bool, error) {
	return false, nil
}

func (protectedLegacyAccountStorage) ResolveHumanSecurity(
	context.Context,
	string,
) (string, string, uint64, error) {
	return "tenant-1", account.AccountStatusActive, 1, nil
}

type protectedLegacyQueueStorage struct{ queue.Storage }

func (protectedLegacyQueueStorage) ListQueues(
	context.Context,
	*v1.ListQueuesRequest,
) (*v1.ListQueuesResponse, error) {
	return &v1.ListQueuesResponse{}, nil
}

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
		"cluster IPv4 loopback advertise": func(cfg *config.Config, clusterCfg *cluster.Config) {
			clusterCfg.Enabled = true
			cfg.GRPCAdvertiseAddr = "127.0.0.1:8080"
		},
		"cluster IPv6 loopback advertise": func(cfg *config.Config, clusterCfg *cluster.Config) {
			clusterCfg.Enabled = true
			cfg.GRPCAdvertiseAddr = "[::1]:8080"
		},
		"cluster zoned IPv6 loopback advertise": func(cfg *config.Config, clusterCfg *cluster.Config) {
			clusterCfg.Enabled = true
			cfg.GRPCAdvertiseAddr = "[::1%lo0]:8080"
		},
		"cluster zoned IPv6 unspecified advertise": func(cfg *config.Config, clusterCfg *cluster.Config) {
			clusterCfg.Enabled = true
			cfg.GRPCAdvertiseAddr = "[::%lo0]:8080"
		},
		"cluster localhost advertise": func(cfg *config.Config, clusterCfg *cluster.Config) {
			clusterCfg.Enabled = true
			cfg.GRPCAdvertiseAddr = "localhost:8080"
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

	for _, address := range []string{
		"plainq-0.plainq:8080",
		"[2001:db8::1]:8080",
		"[2001:db8::1%eth0]:8080",
	} {
		t.Run("cluster routable advertise "+address, func(t *testing.T) {
			t.Parallel()

			cfg := valid()
			cfg.GRPCAdvertiseAddr = address
			if err := validateAgentSecurity(&cfg, &cluster.Config{Enabled: true}); err != nil {
				t.Fatalf("validateAgentSecurity() error = %v", err)
			}
		})
	}
}

func TestValidateHumanSecurity(t *testing.T) {
	valid := func() config.Config {
		return config.Config{
			AuthEnable: true, AuthJWTSecret: strings.Repeat("h", 32),
			AuthJWTIssuer: "plainq-server", AuthJWTAudience: "plainq-human",
			AuthBootstrapSecret: strings.Repeat("b", 32), AuthRequestMaxBytes: 32 << 10,
			AuthRateRequestsPerSecond: 5, AuthRateBurst: 10,
			AgentRateRequestsPerSecond: 100, AgentRateBurst: 200,
			AuthAccessTokenTTL: time.Hour, AuthRefreshTokenTTL: 30 * 24 * time.Hour,
		}
	}

	for name, mutate := range map[string]func(*config.Config){
		"missing jwt secret":               func(cfg *config.Config) { cfg.AuthJWTSecret = "" },
		"missing issuer":                   func(cfg *config.Config) { cfg.AuthJWTIssuer = "" },
		"missing audience":                 func(cfg *config.Config) { cfg.AuthJWTAudience = "" },
		"short bootstrap secret":           func(cfg *config.Config) { cfg.AuthBootstrapSecret = "short" },
		"missing body limit":               func(cfg *config.Config) { cfg.AuthRequestMaxBytes = 0 },
		"invalid rate":                     func(cfg *config.Config) { cfg.AuthRateRequestsPerSecond = 0 },
		"invalid burst":                    func(cfg *config.Config) { cfg.AuthRateBurst = 0 },
		"invalid gRPC rate":                func(cfg *config.Config) { cfg.AgentRateRequestsPerSecond = 0 },
		"invalid gRPC burst":               func(cfg *config.Config) { cfg.AgentRateBurst = 0 },
		"verification dependencies absent": func(cfg *config.Config) { cfg.AuthEmailVerificationEnable = true },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			mutate(&cfg)
			if err := validateHumanSecurity(&cfg); err == nil {
				t.Fatal("validateHumanSecurity() unexpectedly succeeded")
			}
		})
	}

	cfg := valid()
	if err := validateHumanSecurity(&cfg); err != nil {
		t.Fatalf("validateHumanSecurity() error = %v", err)
	}

	if err := validateHumanSecurity(&config.Config{GRPCProtectLegacy: true}); err == nil {
		t.Fatal("legacy protection without a human or agent authenticator unexpectedly succeeded")
	}
}

func TestHumanOnlyProtectedLegacyGRPCInitializesAdmission(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		AuthEnable: true, AgentEnable: false, GRPCProtectLegacy: true,
		AuthJWTSecret: strings.Repeat("h", 32), AuthJWTIssuer: "plainq-server",
		AuthJWTAudience: "plainq-human", AgentRateRequestsPerSecond: 0.000001, AgentRateBurst: 1,
		GRPCAddr: "127.0.0.1:0",
	}

	tokens, err := initTokenManager(&cfg)
	if err != nil {
		t.Fatalf("initTokenManager() error = %v", err)
	}

	accountStorage := protectedLegacyAccountStorage{}
	authenticator, admission, err := initHumanGRPCSecurity(&cfg, tokens, accountStorage)
	if err != nil {
		t.Fatalf("initHumanGRPCSecurity() error = %v", err)
	}

	listener, err := server.NewGRPCListener(cfg.GRPCAddr, nil, []grpc.UnaryServerInterceptor{
		interceptor.UnaryAuth(
			authenticator, interceptor.PublicMethods(),
			interceptor.WithUnaryLegacyProtection(cfg.GRPCProtectLegacy),
		),
		interceptor.UnaryAdmission(admission),
		interceptor.UnaryAuthorize(nil),
	}, nil)
	if err != nil {
		t.Fatalf("NewGRPCListener() error = %v", err)
	}

	listener.Mount(queue.NewService(&cfg, logkit.NewNop(), protectedLegacyQueueStorage{}))
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- listener.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if serveErr := <-serveDone; serveErr != nil {
			t.Errorf("Serve() error = %v", serveErr)
		}
	})

	conn, err := grpc.NewClient(
		listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	now := time.Now().UTC()
	rawToken, err := tokens.Sign(&jwtkit.Token{
		Claims: jwtkit.Claims{
			ID: "human-jti", Subject: "user-1", Issuer: cfg.AuthJWTIssuer,
			Audience: []string{cfg.AuthJWTAudience}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		},
		Meta: map[string]any{
			"uid": "user-1", "tenant_id": "tenant-1", "auth_version": uint64(1),
			"token_use": "access", "roles": []string{"admin"},
		},
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	requestCtx := metadata.NewOutgoingContext(
		context.Background(), metadata.Pairs("authorization", "Bearer "+rawToken),
	)
	client := v1.NewPlainQServiceClient(conn)
	if _, err := client.ListQueues(requestCtx, &v1.ListQueuesRequest{}); err != nil {
		t.Fatalf("first protected ListQueues() error = %v", err)
	}

	_, err = client.ListQueues(requestCtx, &v1.ListQueuesRequest{})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("second protected ListQueues() code = %s, want %s (error %v)", got, codes.ResourceExhausted, err)
	}
}

func TestDisabledAuthLegacyCompatibilityBypassesAdmission(t *testing.T) {
	t.Parallel()

	cfg := config.Config{AuthEnable: false, AgentEnable: false, GRPCProtectLegacy: false, GRPCAddr: "127.0.0.1:0"}
	listener, err := server.NewGRPCListener(cfg.GRPCAddr, nil, []grpc.UnaryServerInterceptor{
		interceptor.UnaryAuth(nil, interceptor.PublicMethods(), interceptor.WithUnaryLegacyProtection(false)),
		interceptor.UnaryAdmission(nil),
		interceptor.UnaryAuthorize(nil),
	}, nil)
	if err != nil {
		t.Fatalf("NewGRPCListener() error = %v", err)
	}

	listener.Mount(queue.NewService(&cfg, logkit.NewNop(), protectedLegacyQueueStorage{}))
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- listener.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if serveErr := <-serveDone; serveErr != nil {
			t.Errorf("Serve() error = %v", serveErr)
		}
	})

	conn, err := grpc.NewClient(
		listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := v1.NewPlainQServiceClient(conn)
	for call := 1; call <= 2; call++ {
		if _, err := client.ListQueues(context.Background(), &v1.ListQueuesRequest{}); err != nil {
			t.Fatalf("anonymous compatibility ListQueues() call %d error = %v", call, err)
		}
	}
}

func TestIsWildcardOrLoopbackAddress(t *testing.T) {
	t.Parallel()

	for address, want := range map[string]bool{
		":8080":                   true,
		"0.0.0.0:8080":            true,
		"[::]:8080":               true,
		"127.0.0.1:8080":          true,
		"[::1]:8080":              true,
		"[::1%lo0]:8080":          true,
		"[::%lo0]:8080":           true,
		"localhost:8080":          true,
		"LOCALHOST.:8080":         true,
		"[2001:db8::1]:8080":      false,
		"[2001:db8::1%eth0]:8080": false,
		"plainq-0.local:8080":     false,
		"malformed":               true,
	} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()

			if got := isWildcardOrLoopbackAddress(address); got != want {
				t.Fatalf("isWildcardOrLoopbackAddress(%q) = %v, want %v", address, got, want)
			}
		})
	}
}
