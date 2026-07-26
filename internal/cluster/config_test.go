package cluster

import (
	"testing"
	"time"

	"github.com/maxatome/go-testdeep/td"
)

func TestConfigNormalizeFillsDefaults(t *testing.T) {
	cfg := Config{Enabled: true, NodeID: "node-1"}

	td.Require(t).CmpNoError(cfg.Normalize())

	td.Cmp(t, cfg.BindAddr, DefaultBindAddr)
	td.Cmp(t, cfg.GossipAddr, DefaultGossipAddr)
	td.Cmp(t, cfg.DiscoveryInterval, DefaultDiscoveryInterval)
	td.Cmp(t, cfg.ReconcileInterval, DefaultReconcileInterval)
	td.Cmp(t, cfg.RemoveTimeout, DefaultRemoveTimeout)
	td.Cmp(t, cfg.SweepInterval, DefaultSweepInterval)
	td.Cmp(t, cfg.Consistency, ConsistencyLocal)
	td.Cmp(t, cfg.GossipProfile, "lan")
}

func TestConfigNormalizeUsesTheHostnameAsNodeID(t *testing.T) {
	cfg := Config{Enabled: true}

	td.Require(t).CmpNoError(cfg.Normalize())
	td.Cmp(t, cfg.NodeID, td.Not(""))
}

// Advertising the cluster port but not the gossip one is a half-configured
// node, and the missing half is derivable: same host, different port.
func TestConfigDerivesTheGossipAdvertiseAddress(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		NodeID:        "node-1",
		AdvertiseAddr: "10.0.0.7:8082",
		GossipAddr:    "0.0.0.0:8083",
	}

	td.Require(t).CmpNoError(cfg.Normalize())
	td.Cmp(t, cfg.GossipAdvertiseAddr, "10.0.0.7:8083")
}

func TestConfigValidateIsSilentWhenDisabled(t *testing.T) {
	// Nothing about clustering may fail a server that is not clustered.
	cfg := Config{Enabled: false, BindAddr: "nonsense", Consistency: "invented"}

	td.CmpNoError(t, cfg.Validate())
}

func TestConfigValidate(t *testing.T) {
	base := func() Config {
		return Config{
			Enabled:     true,
			NodeID:      "node-1",
			BindAddr:    "127.0.0.1:8082",
			GossipAddr:  "127.0.0.1:8083",
			Bootstrap:   true,
			Consistency: ConsistencyLocal,
		}
	}

	cases := map[string]struct {
		mutate func(*Config)
		wants  string
	}{
		"valid": {mutate: func(*Config) {}},
		"bootstrap and bootstrap-expect together": {
			mutate: func(c *Config) { c.BootstrapExpect = 3 },
			wants:  "mutually exclusive",
		},
		// A two-node cluster tolerates zero failures: it is strictly worse
		// than one node, because now either machine can take it down.
		"two-node cluster": {
			mutate: func(c *Config) { c.Bootstrap = false; c.BootstrapExpect = 2 },
			wants:  "no fault tolerance",
		},
		"even-sized cluster": {
			mutate: func(c *Config) { c.Bootstrap = false; c.BootstrapExpect = 4 },
			wants:  "is even",
		},
		"no way to find or form a cluster": {
			mutate: func(c *Config) { c.Bootstrap = false },
			wants:  "cluster.discovery",
		},
		"a non-voter cannot bootstrap": {
			mutate: func(c *Config) { c.NonVoter = true },
			wants:  "non-voting",
		},
		"unspecified advertise address": {
			mutate: func(c *Config) { c.AdvertiseAddr = "0.0.0.0:8082" },
			wants:  "unspecified",
		},
		"bind address without a port": {
			mutate: func(c *Config) { c.BindAddr = "127.0.0.1" },
			wants:  "host:port",
		},
		"unknown consistency mode": {
			mutate: func(c *Config) { c.Consistency = "eventual-ish" },
			wants:  "cluster.consistency",
		},
		"unknown gossip profile": {
			mutate: func(c *Config) { c.GossipProfile = "interplanetary" },
			wants:  "cluster.gossip.profile",
		},
		"malformed gossip secret": {
			mutate: func(c *Config) { c.GossipSecret = "not base64 !!" },
			wants:  "cluster.gossip.secret",
		},
		"partial TLS configuration": {
			mutate: func(c *Config) { c.TLSCertFile = "cert.pem" },
			wants:  "all of",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)

			td.Require(t).CmpNoError(cfg.Normalize())

			err := cfg.Validate()

			if tc.wants == "" {
				td.CmpNoError(t, err)

				return
			}

			td.Require(t).CmpError(err)
			td.Cmp(t, err.Error(), td.Contains(tc.wants))
		})
	}
}

// One flag carries several specs, and a spec may itself contain commas — a
// static address list, a query string. Splitting on every comma would tear
// those apart.
func TestDiscoverySpecs(t *testing.T) {
	cases := map[string]struct {
		raw  []string
		want []string
	}{
		"single spec": {
			raw:  []string{"static://10.0.0.1:8083"},
			want: []string{"static://10.0.0.1:8083"},
		},
		"a spec whose own value has commas stays whole": {
			raw:  []string{"static://10.0.0.1:8083,10.0.0.2:8083,10.0.0.3:8083"},
			want: []string{"static://10.0.0.1:8083,10.0.0.2:8083,10.0.0.3:8083"},
		},
		"several specs are separated": {
			raw: []string{"static://10.0.0.1:8083,10.0.0.2:8083,dns://plainq.internal?port=8083"},
			want: []string{
				"static://10.0.0.1:8083,10.0.0.2:8083",
				"dns://plainq.internal?port=8083",
			},
		},
		"blank entries are dropped": {
			raw:  []string{"", "  ", "static://10.0.0.1:8083"},
			want: []string{"static://10.0.0.1:8083"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Config{Discovery: tc.raw}

			td.Cmp(t, cfg.DiscoverySpecs(), tc.want)
		})
	}
}

func TestGossipPort(t *testing.T) {
	cfg := Config{GossipAddr: "127.0.0.1:8083"}
	td.Cmp(t, cfg.GossipPort(), 8083)

	cfg = Config{GossipAddr: "nonsense"}
	td.Cmp(t, cfg.GossipPort(), 0)
}

func TestConfigTimeoutsAreCoercedToSaneValues(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		NodeID:            "node-1",
		DiscoveryInterval: -time.Second,
		ReconcileInterval: -time.Second,
		RemoveTimeout:     -time.Second,
		SweepInterval:     -time.Second,
	}

	td.Require(t).CmpNoError(cfg.Normalize())

	td.Cmp(t, cfg.DiscoveryInterval, DefaultDiscoveryInterval)
	td.Cmp(t, cfg.ReconcileInterval, DefaultReconcileInterval)
	td.Cmp(t, cfg.RemoveTimeout, DefaultRemoveTimeout)
	td.Cmp(t, cfg.SweepInterval, DefaultSweepInterval)
}
