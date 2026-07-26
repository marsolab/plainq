package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/maxatome/go-testdeep/td"
)

func TestParseSpec(t *testing.T) {
	cases := map[string]struct {
		spec   string
		scheme string
		target string
		port   string
	}{
		"scheme and target": {
			spec:   "dns://plainq.internal?port=9000",
			scheme: "dns",
			target: "plainq.internal",
			port:   "9000",
		},
		"no target, options only": {
			spec:   "kubernetes://?namespace=prod&selector=app%3Dplainq",
			scheme: "kubernetes",
			target: "",
		},
		// A bare host list is what someone types when they have three
		// machines and a text editor. Requiring `static://` for that would be
		// ceremony for its own sake.
		"bare address list defaults to static": {
			spec:   "10.0.0.1:8082,10.0.0.2:8082",
			scheme: "static",
			target: "10.0.0.1:8082,10.0.0.2:8082",
		},
		"scheme is case insensitive": {
			spec:   "DNS://plainq.internal",
			scheme: "dns",
			target: "plainq.internal",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			spec, err := ParseSpec(tc.spec)
			td.Require(t).CmpNoError(err)

			td.Cmp(t, spec.Scheme, tc.scheme)
			td.Cmp(t, spec.Target, tc.target)

			if tc.port != "" {
				td.Cmp(t, spec.Options.Get("port"), tc.port)
			}
		})
	}
}

func TestParseSpecRejectsEmpty(t *testing.T) {
	_, err := ParseSpec("   ")
	td.CmpError(t, err)
}

func TestParseUnknownProvider(t *testing.T) {
	_, err := Parse("nowhere://somewhere")

	td.Require(t).CmpError(err)
	td.Cmp(t, errors.Is(err, ErrUnknownProvider), true, "the error says the scheme is unknown")

	// The message lists what *is* available, because "unknown provider" alone
	// leaves the operator guessing at the spelling.
	td.Cmp(t, err.Error(), td.Contains("kubernetes"))
}

func TestStaticDiscovery(t *testing.T) {
	discoverer, err := Parse("static://10.0.0.1:9000,10.0.0.2,  ,10.0.0.3:7000?port=8082")
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"10.0.0.1:9000", "10.0.0.2:8082", "10.0.0.3:7000"},
		"a bare host takes the default port; one that already has a port keeps it",
	)

	td.CmpNoError(t, discoverer.Close())
}

func TestStaticDiscoveryRejectsEmptyList(t *testing.T) {
	_, err := Parse("static://?port=8082")
	td.CmpError(t, err)
}

func TestJoinHostPort(t *testing.T) {
	td.Cmp(t, JoinHostPort("10.0.0.1", 8082), "10.0.0.1:8082")
	td.Cmp(t, JoinHostPort("10.0.0.1:9000", 8082), "10.0.0.1:9000", "an existing port wins")
	td.Cmp(t, JoinHostPort("fd00::1", 8082), "[fd00::1]:8082", "a v6 literal is bracketed")
	td.Cmp(t, JoinHostPort("[fd00::1]:9000", 8082), "[fd00::1]:9000")
	td.Cmp(t, JoinHostPort("", 8082), "")
}

func TestDedupe(t *testing.T) {
	peers := []Peer{
		{Addr: "10.0.0.2:8082", Source: "dns"},
		{Addr: "10.0.0.1:8082", ID: "", Meta: map[string]string{"zone": "a"}, Source: "dns"},
		// The same node seen by a second provider, which knows its name.
		{Addr: "10.0.0.1:8082", ID: "node-1", Meta: map[string]string{"rack": "r1"}, Source: "k8s"},
		{Addr: "", Source: "broken"},
	}

	deduped := Dedupe(peers)

	td.Require(t).Cmp(len(deduped), 2, "one entry per address, and the empty one is dropped")
	td.Cmp(t, deduped[0].Addr, "10.0.0.1:8082", "results are sorted by address")
	td.Cmp(t, deduped[0].ID, "node-1", "an id the first sighting lacked is filled in")
	td.Cmp(t, deduped[0].Meta, map[string]string{"zone": "a", "rack": "r1"}, "metadata is merged")
}

// stubDiscoverer is a Discoverer with a scripted answer.
type stubDiscoverer struct {
	name  string
	peers []Peer
	err   error
}

func (s *stubDiscoverer) Name() string { return s.name }

func (s *stubDiscoverer) Discover(context.Context) ([]Peer, error) { return s.peers, s.err }

func (s *stubDiscoverer) Close() error { return nil }

func TestMultiMergesResults(t *testing.T) {
	multi := NewMulti(
		&stubDiscoverer{name: "a", peers: []Peer{{Addr: "10.0.0.1:8082"}}},
		&stubDiscoverer{name: "b", peers: []Peer{{Addr: "10.0.0.2:8082"}, {Addr: "10.0.0.1:8082"}}},
	)

	peers, err := multi.Discover(context.Background())
	td.Require(t).CmpNoError(err)

	td.Cmp(t, Addrs(peers), []string{"10.0.0.1:8082", "10.0.0.2:8082"})
}

// A provider that fails must not blind the ones that work: a static seed list
// is precisely the fallback an operator adds for a flaky cloud API.
func TestMultiToleratesPartialFailure(t *testing.T) {
	multi := NewMulti(
		&stubDiscoverer{name: "broken", err: errors.New("cloud API is down")},
		&stubDiscoverer{name: "static", peers: []Peer{{Addr: "10.0.0.1:8082"}}},
	)

	peers, err := multi.Discover(context.Background())

	td.Cmp(t, Addrs(peers), []string{"10.0.0.1:8082"})
	td.Cmp(t, err, td.Not(nil), "the failure is still reported, so it can be logged")
}

func TestMultiFailsWhenEveryProviderFails(t *testing.T) {
	multi := NewMulti(
		&stubDiscoverer{name: "a", err: errors.New("down")},
		&stubDiscoverer{name: "b", err: errors.New("also down")},
	)

	peers, err := multi.Discover(context.Background())

	td.Cmp(t, peers, td.Nil())
	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("all discovery providers failed"))
}

func TestParseAllBuildsMulti(t *testing.T) {
	discoverer, err := ParseAll("static://10.0.0.1:8082", "static://10.0.0.2:8082")
	td.Require(t).CmpNoError(err)

	td.Cmp(t, discoverer.Name(), "multi(static,static)")

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)
	td.Cmp(t, Addrs(peers), []string{"10.0.0.1:8082", "10.0.0.2:8082"})
}

func TestParseAllWithOneSpecSkipsMulti(t *testing.T) {
	discoverer, err := ParseAll("static://10.0.0.1:8082", "  ")
	td.Require(t).CmpNoError(err)

	td.Cmp(t, discoverer.Name(), "static")
}

func TestParseAllRejectsNothing(t *testing.T) {
	_, err := ParseAll("", "   ")
	td.CmpError(t, err)
}

func TestSpecOptions(t *testing.T) {
	spec, err := ParseSpec("docker://?port=9000&tls=true&count=3&wait=5s")
	td.Require(t).CmpNoError(err)

	port, portErr := spec.OptionPort(8082)
	td.Require(t).CmpNoError(portErr)
	td.Cmp(t, port, 9000)

	tls, tlsErr := spec.OptionBool("tls", false)
	td.Require(t).CmpNoError(tlsErr)
	td.Cmp(t, tls, true)

	count, countErr := spec.OptionInt("count", 1)
	td.Require(t).CmpNoError(countErr)
	td.Cmp(t, count, 3)

	wait, waitErr := spec.OptionDuration("wait", 0)
	td.Require(t).CmpNoError(waitErr)
	td.Cmp(t, wait.String(), "5s")

	td.Cmp(t, spec.Option("missing", "fallback"), "fallback")
}

func TestSpecOptionPortRange(t *testing.T) {
	spec, err := ParseSpec("static://a?port=70000")
	td.Require(t).CmpNoError(err)

	_, portErr := spec.OptionPort(8082)
	td.CmpError(t, portErr)
}

func TestProvidersAreRegistered(t *testing.T) {
	// Every platform the cluster claims to support has to actually be
	// reachable through a spec string, or the claim is documentation only.
	td.Cmp(t, Providers(), td.SuperSetOf(
		"aws", "azure", "consul", "dns", "dns+srv", "docker", "gcp", "k8s", "kubernetes", "static",
	))
}
