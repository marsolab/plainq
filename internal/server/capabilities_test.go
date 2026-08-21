package server

import (
	"context"
	"testing"

	"github.com/marsolab/plainq/internal/server/config"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
)

func TestCapabilitiesReportLegacyProtection(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		service := newCapabilitiesService(&PlainQ{cfg: &config.Config{GRPCProtectLegacy: enabled}})
		response, err := service.GetCapabilities(context.Background(), &agentv1.GetCapabilitiesRequest{})
		if err != nil {
			t.Fatalf("GetCapabilities() error = %v", err)
		}
		if response.GetLegacyV1AuthRequired() != enabled {
			t.Fatalf("legacy protection = %v, want %v", response.GetLegacyV1AuthRequired(), enabled)
		}
	}
}
