package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

type healthMount struct {
	server *health.Server
}

func (m healthMount) Mount(server *grpc.Server) {
	healthv1.RegisterHealthServer(server, m.server)
}

func TestGRPCListenerServesAndStops(t *testing.T) {
	t.Parallel()

	listener, err := NewGRPCListener("127.0.0.1:0", nil, nil, nil)
	if err != nil {
		t.Fatalf("NewGRPCListener() error = %v", err)
	}

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	listener.Mount(healthMount{server: healthServer})

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- listener.Serve(ctx) }()

	clientConn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		<-serveDone
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	defer clientConn.Close()

	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer checkCancel()

	response, err := healthv1.NewHealthClient(clientConn).Check(checkCtx, &healthv1.HealthCheckRequest{})
	if err != nil {
		cancel()
		<-serveDone
		t.Fatalf("health Check() error = %v", err)
	}
	if response.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		t.Fatalf("health status = %v, want SERVING", response.GetStatus())
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Serve() did not stop after cancellation")
	}
}

func TestLoadGRPCTLSConfigRequiresTLS13(t *testing.T) {
	t.Parallel()

	certFile, keyFile, caFile := writeTestCertificate(t)

	serverConfig, err := LoadGRPCTLSConfig("server", certFile, keyFile, "")
	if err != nil {
		t.Fatalf("LoadGRPCTLSConfig(server) error = %v", err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("server MinVersion = %#x, want TLS 1.3", serverConfig.MinVersion)
	}
	if serverConfig.ClientAuth != tls.NoClientCert {
		t.Fatalf("server ClientAuth = %v, want NoClientCert", serverConfig.ClientAuth)
	}

	mutualConfig, err := LoadGRPCTLSConfig("mutual", certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("LoadGRPCTLSConfig(mutual) error = %v", err)
	}
	if mutualConfig.ClientCAs == nil {
		t.Fatal("mutual ClientCAs is nil")
	}
	if mutualConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("mutual ClientAuth = %v, want RequireAndVerifyClientCert", mutualConfig.ClientAuth)
	}
}

func TestLoadGRPCTLSConfigRejectsInvalidMaterial(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	invalidCA := filepath.Join(directory, "invalid-ca.pem")
	if err := os.WriteFile(invalidCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write invalid CA: %v", err)
	}

	certFile, keyFile, _ := writeTestCertificate(t)
	if _, err := LoadGRPCTLSConfig("mutual", certFile, keyFile, invalidCA); err == nil {
		t.Fatal("LoadGRPCTLSConfig() unexpectedly accepted invalid CA")
	}
}

func writeTestCertificate(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "plainq-test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
		DNSNames:     []string{"localhost"},
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	directory := t.TempDir()
	certFile = filepath.Join(directory, "tls.crt")
	keyFile = filepath.Join(directory, "tls.key")
	caFile = filepath.Join(directory, "ca.crt")

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})

	if err := os.WriteFile(certFile, certificatePEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, privateKeyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(caFile, certificatePEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	return certFile, keyFile, caFile
}
