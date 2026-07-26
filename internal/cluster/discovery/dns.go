package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// resolver is the slice of net.Resolver this provider uses, taken as an
// interface so tests can answer without a nameserver.
type resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// DNS discovers peers from DNS records.
//
// It covers the two shapes deployments actually use: a name that resolves to
// every pod or instance (a Kubernetes headless service, an AWS Cloud Map
// name), and an SRV record that carries ports as well as hosts.
type DNS struct {
	resolver resolver

	// name is the record to look up. For SRV in `_service._proto.domain` form
	// it is parsed into service/proto/domain by the resolver call.
	name string

	// port is attached to A/AAAA results, which carry no port of their own.
	port int

	// srv selects SRV lookup over A/AAAA.
	srv bool
}

// DNSOption configures a DNS discoverer.
type DNSOption func(*DNS)

// WithDNSResolver overrides the resolver, for tests and for deployments that
// need to query a specific nameserver.
func WithDNSResolver(r resolver) DNSOption { return func(d *DNS) { d.resolver = r } }

// NewDNS returns a Discoverer over A/AAAA records for name.
func NewDNS(name string, port int, opts ...DNSOption) *DNS {
	d := DNS{resolver: net.DefaultResolver, name: name, port: port}

	for _, opt := range opts {
		opt(&d)
	}

	return &d
}

// NewDNSSRV returns a Discoverer over SRV records for name. The port comes
// from the record; port is the fallback for a record that advertises none.
func NewDNSSRV(name string, port int, opts ...DNSOption) *DNS {
	d := NewDNS(name, port, opts...)
	d.srv = true

	return d
}

// Name implements Discoverer.
func (d *DNS) Name() string {
	if d.srv {
		return "dns+srv"
	}

	return "dns"
}

// Discover implements Discoverer.
func (d *DNS) Discover(ctx context.Context) ([]Peer, error) {
	if d.srv {
		return d.discoverSRV(ctx)
	}

	return d.discoverHosts(ctx)
}

func (d *DNS) discoverHosts(ctx context.Context) ([]Peer, error) {
	addrs, err := d.resolver.LookupHost(ctx, d.name)
	if err != nil {
		// A name with no records yet is the normal state of a StatefulSet
		// mid-rollout, not an error worth failing discovery over.
		var dnsErr *net.DNSError
		if ok := asDNSError(err, &dnsErr); ok && dnsErr.IsNotFound {
			return nil, nil
		}

		return nil, fmt.Errorf("lookup host %q: %w", d.name, err)
	}

	peers := make([]Peer, 0, len(addrs))

	for _, addr := range addrs {
		peers = append(peers, Peer{
			Addr:   net.JoinHostPort(addr, strconv.Itoa(d.port)),
			Meta:   map[string]string{"dns_name": d.name},
			Source: "dns",
		})
	}

	return peers, nil
}

func (d *DNS) discoverSRV(ctx context.Context) ([]Peer, error) {
	service, proto, domain := splitSRVName(d.name)

	_, records, err := d.resolver.LookupSRV(ctx, service, proto, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if ok := asDNSError(err, &dnsErr); ok && dnsErr.IsNotFound {
			return nil, nil
		}

		return nil, fmt.Errorf("lookup SRV %q: %w", d.name, err)
	}

	peers := make([]Peer, 0, len(records))

	for _, record := range records {
		if record == nil {
			continue
		}

		port := int(record.Port)
		if port == 0 {
			port = d.port
		}

		host := strings.TrimSuffix(record.Target, ".")
		if host == "" {
			continue
		}

		peers = append(peers, Peer{
			ID:     host,
			Addr:   net.JoinHostPort(host, strconv.Itoa(port)),
			Meta:   map[string]string{"dns_name": d.name},
			Source: "dns+srv",
		})
	}

	return peers, nil
}

// Close implements Discoverer.
func (d *DNS) Close() error { return nil }

// splitSRVName turns `_plainq._tcp.example.com` into the three arguments
// LookupSRV wants. A name that is not in underscore form is passed through as
// the domain with empty service and proto, which makes LookupSRV query the
// name verbatim.
func splitSRVName(name string) (service, proto, domain string) {
	if !strings.HasPrefix(name, "_") {
		return "", "", name
	}

	service, rest, found := strings.Cut(strings.TrimPrefix(name, "_"), "._")
	if !found {
		return "", "", name
	}

	proto, domain, hasDomain := strings.Cut(rest, ".")
	if !hasDomain {
		return "", "", name
	}

	return service, proto, domain
}

func asDNSError(err error, target **net.DNSError) bool {
	for err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok { //nolint:errorlint // unwrap loop below handles wrapping.
			*target = dnsErr

			return true
		}

		unwrapper, ok := err.(interface{ Unwrap() error }) //nolint:errorlint // same.
		if !ok {
			return false
		}

		err = unwrapper.Unwrap()
	}

	return false
}

func init() {
	Register("dns", func(spec *Spec) (Discoverer, error) {
		port, portErr := spec.OptionPort(defaultGossipPort)
		if portErr != nil {
			return nil, portErr
		}

		name := spec.Target
		if name == "" {
			name = spec.Option("name", "")
		}

		if name == "" {
			return nil, fmt.Errorf("dns discovery %q names no record", spec.Raw)
		}

		if strings.EqualFold(spec.Option("type", "a"), "srv") {
			return NewDNSSRV(name, port), nil
		}

		return NewDNS(name, port), nil
	})

	Register("dns+srv", func(spec *Spec) (Discoverer, error) {
		port, portErr := spec.OptionPort(defaultGossipPort)
		if portErr != nil {
			return nil, portErr
		}

		name := spec.Target
		if name == "" {
			name = spec.Option("name", "")
		}

		if name == "" {
			return nil, fmt.Errorf("dns+srv discovery %q names no record", spec.Raw)
		}

		return NewDNSSRV(name, port), nil
	})
}
