package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const grpcShutdownTimeout = 5 * time.Second

// GRPCEndpointRegistrator mounts generated services on a gRPC server.
type GRPCEndpointRegistrator interface {
	Mount(server *grpc.Server)
}

// GRPCListener owns the network listener and gRPC server so transport
// credentials are applied at the serving boundary.
type GRPCListener struct {
	listener net.Listener
	server   *grpc.Server
	logger   *slog.Logger
}

// NewGRPCListener creates a bounded gRPC server and optionally attaches TLS.
func NewGRPCListener(
	addr string,
	tlsConfig *tls.Config,
	unary []grpc.UnaryServerInterceptor,
	streams []grpc.StreamServerInterceptor,
) (*GRPCListener, error) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen for gRPC: %w", err)
	}

	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(streams...),
		grpc.MaxRecvMsgSize(5 << 20),
		grpc.MaxConcurrentStreams(2048),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: 30 * time.Second, PermitWithoutStream: false,
		}),
	}
	if tlsConfig != nil {
		options = append(options, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	return &GRPCListener{
		listener: listener,
		server:   grpc.NewServer(options...),
		logger:   slog.Default(),
	}, nil
}

// SetLogger sets the secret-safe lifecycle logger.
func (l *GRPCListener) SetLogger(logger *slog.Logger) {
	if logger != nil {
		l.logger = logger
	}
}

// Mount registers generated service adapters.
func (l *GRPCListener) Mount(handlers ...GRPCEndpointRegistrator) {
	for _, handler := range handlers {
		if handler != nil {
			handler.Mount(l.server)
		}
	}
}

// RegisterService provides a narrow escape hatch for generated services that
// do not expose a Mount method.
func (l *GRPCListener) RegisterService(description *grpc.ServiceDesc, implementation any) {
	l.server.RegisterService(description, implementation)
}

// Addr returns the bound address, including the selected port for :0 tests.
func (l *GRPCListener) Addr() net.Addr { return l.listener.Addr() }

// Serve blocks until the server fails or the context is canceled. Cancellation
// first attempts graceful shutdown, then forces a stop after a bounded wait.
func (l *GRPCListener) Serve(ctx context.Context) error {
	l.logger.Info("gRPC listener started", slog.String("address", l.listener.Addr().String()))

	serveDone := make(chan error, 1)
	go func() { serveDone <- l.server.Serve(l.listener) }()

	select {
	case err := <-serveDone:
		if err == nil || errors.Is(err, grpc.ErrServerStopped) || ctx.Err() != nil {
			return nil
		}

		return fmt.Errorf("serve gRPC: %w", err)

	case <-ctx.Done():
	}

	gracefulDone := make(chan struct{})

	go func() {
		l.server.GracefulStop()
		close(gracefulDone)
	}()

	timer := time.NewTimer(grpcShutdownTimeout)
	defer timer.Stop()

	select {
	case <-gracefulDone:
	case <-timer.C:
		l.logger.Warn("gRPC graceful shutdown timed out", slog.String("address", l.listener.Addr().String()))
		l.server.Stop()
		<-gracefulDone
	}

	if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("stop gRPC: %w", err)
	}

	l.logger.Info("gRPC listener stopped", slog.String("address", l.listener.Addr().String()))

	return nil
}

// LoadGRPCTLSConfig loads server or mutual TLS material with TLS 1.3 as the
// minimum protocol version.
func LoadGRPCTLSConfig(mode, certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if mode != "server" && mode != "mutual" {
		return nil, fmt.Errorf("unsupported gRPC TLS mode %q", mode)
	}

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load gRPC TLS certificate: %w", err)
	}

	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
	}

	if mode == "server" {
		return config, nil
	}

	clientCAPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read gRPC client CA: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("parse gRPC client CA: no certificates found")
	}

	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.ClientCAs = clientCAs

	return config, nil
}
