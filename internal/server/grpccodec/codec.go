// Package grpccodec provides PlainQ's protobuf transport codec.
package grpccodec

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto" // Initialize gRPC's default before PlainQ replaces the proto codec.
	"google.golang.org/protobuf/proto"
)

const codecName = "proto"

type vtMessage interface {
	MarshalVT() ([]byte, error)
	UnmarshalVT(data []byte) error
}

// Codec uses generated vtprotobuf helpers when present and falls back to the
// standard protobuf implementation for ecosystem services such as gRPC
// health and google.rpc status details.
type Codec struct{}

// Register before any server or client can read gRPC's process-wide codec
// registry. Registering from service constructors races with concurrent RPCs.
func init() { //nolint:gochecknoinits // gRPC codecs are registered through a process-wide init-time registry.
	if encoding.GetCodecV2(codecName) == nil {
		panic("gRPC default proto codec must initialize before PlainQ's codec")
	}

	encoding.RegisterCodec(Codec{})
}

// Marshal implements encoding.Codec.
func (Codec) Marshal(value any) ([]byte, error) {
	if message, ok := value.(vtMessage); ok {
		data, err := message.MarshalVT()
		if err != nil {
			return nil, fmt.Errorf("marshal gRPC vtprotobuf: %w", err)
		}

		return data, nil
	}

	message, ok := value.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("gRPC proto marshal: message is %T", value)
	}

	data, err := proto.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal gRPC protobuf: %w", err)
	}

	return data, nil
}

// Unmarshal implements encoding.Codec.
func (Codec) Unmarshal(data []byte, value any) error {
	if message, ok := value.(vtMessage); ok {
		if err := message.UnmarshalVT(data); err != nil {
			return fmt.Errorf("unmarshal gRPC vtprotobuf: %w", err)
		}

		return nil
	}

	message, ok := value.(proto.Message)
	if !ok {
		return fmt.Errorf("gRPC proto unmarshal: message is %T", value)
	}

	if err := proto.Unmarshal(data, message); err != nil {
		return fmt.Errorf("unmarshal gRPC protobuf: %w", err)
	}

	return nil
}

// Name implements encoding.Codec.
func (Codec) Name() string { return codecName }
