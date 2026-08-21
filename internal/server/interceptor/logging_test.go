package interceptor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/marsolab/servekit/ctxkit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLoggingRedactsHandlerAndStatusErrors(t *testing.T) {
	t.Parallel()

	const (
		bootstrapCredential = "pqac_01TEST_secret"
		receiptHandle       = "receipt-handle-secret"
		messageBody         = "message-body-secret"
	)

	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	interceptor := Logging(logger)

	_, gotErr := interceptor(
		context.Background(),
		struct {
			BootstrapCredential string
			ReceiptHandle       string
			Body                string
		}{bootstrapCredential, receiptHandle, messageBody},
		&grpc.UnaryServerInfo{FullMethod: "/agent.v1.AgentService/ExchangeAgentCredential"},
		func(ctx context.Context, _ any) (any, error) {
			ctxkit.GetLogErrHook(ctx)(errors.New("storage rejected " + bootstrapCredential + " " + receiptHandle))

			return nil, status.Error(codes.InvalidArgument, "bad body: "+messageBody)
		},
	)
	if status.Code(gotErr) != codes.InvalidArgument {
		t.Fatalf("status code = %v, want %v", status.Code(gotErr), codes.InvalidArgument)
	}

	logged := output.String()
	for _, secret := range []string{bootstrapCredential, receiptHandle, messageBody} {
		if strings.Contains(logged, secret) {
			t.Fatalf("log contains sensitive value %q: %s", secret, logged)
		}
	}

	for _, field := range []string{"method=", "code=InvalidArgument", "duration="} {
		if !strings.Contains(logged, field) {
			t.Fatalf("log does not contain safe field %q: %s", field, logged)
		}
	}
}

func TestLoggingDoesNotPanicWithoutRequestErrorHook(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	interceptor := Logging(logger)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Logging panicked: %v", recovered)
		}
	}()

	_, gotErr := interceptor(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{FullMethod: "/agent.v1.AgentService/GetAgent"},
		func(context.Context, any) (any, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	)
	if status.Code(gotErr) != codes.NotFound {
		t.Fatalf("status code = %v, want %v", status.Code(gotErr), codes.NotFound)
	}
}
