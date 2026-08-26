package grpccodec

import (
	"testing"

	"google.golang.org/grpc/encoding"
)

func TestProtoRegistryKeepsPlainQCodecAfterDefaultInitialization(t *testing.T) {
	t.Parallel()

	registered := encoding.GetCodec(codecName)
	if _, ok := registered.(Codec); !ok {
		t.Fatalf("registered proto codec = %T, want grpccodec.Codec", registered)
	}
}
