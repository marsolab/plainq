package main

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCErrorWithListHintUsesTopicAdviceAndPreservesStatus(t *testing.T) {
	original := status.Error(codes.NotFound, "topic does not exist")

	err := grpcErrorWithListHint(
		"localhost:8080",
		"delete topic",
		"plainq topic list",
		original,
	)

	if !strings.Contains(err.Error(), `"plainq topic list"`) {
		t.Errorf("error = %q, want topic list advice", err)
	}
	if strings.Contains(err.Error(), `"plainq list"`) {
		t.Errorf("error = %q, contains queue list advice", err)
	}
	if got := status.Code(err); got != codes.NotFound {
		t.Errorf("status code = %v, want %v", got, codes.NotFound)
	}
	if !errors.Is(err, original) {
		t.Error("topic advice error does not unwrap to the original status")
	}
}

func TestGRPCErrorKeepsQueueListAdvice(t *testing.T) {
	err := grpcError("localhost:8080", "describe queue", status.Error(codes.NotFound, "queue does not exist"))

	if !strings.Contains(err.Error(), `"plainq list"`) {
		t.Errorf("error = %q, want queue list advice", err)
	}
	if strings.Contains(err.Error(), `"plainq topic list"`) {
		t.Errorf("error = %q, contains topic list advice", err)
	}
}

func TestGRPCErrorWithListHintChangesOnlyNotFoundAdvice(t *testing.T) {
	tests := map[string]error{
		"invalid argument": status.Error(codes.InvalidArgument, "bad request"),
		"unavailable":      status.Error(codes.Unavailable, "server unavailable"),
		"permission denied": status.Error(
			codes.PermissionDenied,
			"permission denied",
		),
	}

	for name, original := range tests {
		t.Run(name, func(t *testing.T) {
			queueErr := grpcErrorWithListHint("localhost:8080", "operation", "plainq list", original)
			topicErr := grpcErrorWithListHint("localhost:8080", "operation", "plainq topic list", original)

			if queueErr.Error() != topicErr.Error() {
				t.Errorf("non-NotFound output changed with list hint:\nqueue: %q\ntopic: %q", queueErr, topicErr)
			}
		})
	}
}
