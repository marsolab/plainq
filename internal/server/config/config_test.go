package config

import (
	"math"
	"testing"
)

func TestValidateAgentAdmission(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		rate    float64
		burst   int
		wantErr bool
	}{
		"valid":         {rate: 100, burst: 200},
		"zero rate":     {rate: 0, burst: 1, wantErr: true},
		"negative rate": {rate: -1, burst: 1, wantErr: true},
		"nan rate":      {rate: math.NaN(), burst: 1, wantErr: true},
		"infinite rate": {rate: math.Inf(1), burst: 1, wantErr: true},
		"zero burst":    {rate: 1, burst: 0, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := Config{AgentRateRequestsPerSecond: test.rate, AgentRateBurst: test.burst}
			if err := cfg.ValidateAgentAdmission(); (err != nil) != test.wantErr {
				t.Fatalf("ValidateAgentAdmission() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
