// Package discovery finds the addresses of other PlainQ nodes.
//
// Every deployment target answers the question "who else is running?"
// differently — a Kubernetes API, an EC2 tag filter, a DNS record, a hand-
// written list. Discoverer is that question; the rest of this package is one
// answer per platform, plus the plumbing to name them in configuration.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The provider schemes, as they appear in a discovery spec. They are also the
// names a provider reports and the Source stamped on the peers it finds, so
// they are spelled once here rather than repeated per file.
const (
	SchemeStatic     = "static"
	SchemeDNS        = "dns"
	SchemeDNSSRV     = "dns+srv"
	SchemeKubernetes = "kubernetes"
	SchemeK8s        = "k8s"
	SchemeDocker     = "docker"
	SchemeAWS        = "aws"
	SchemeGCP        = "gcp"
	SchemeGCE        = "gce"
	SchemeAzure      = "azure"
	SchemeConsul     = "consul"
)

// headerAuthorization is the bearer-token header the cloud providers use.
const headerAuthorization = "Authorization"

// ErrUnknownProvider is returned by Parse when a spec names a provider that is
// not registered.
var ErrUnknownProvider = errors.New("unknown discovery provider")

// Peer is one node found by a Discoverer.
//
// Addr is the only field a caller can rely on: it is the host:port of the
// peer's cluster port, which is what gossip needs to make contact. ID and Meta
// are best-effort — a DNS record carries neither, a Kubernetes endpoint
// carries both.
type Peer struct {
	// ID is a stable identity for the peer when the provider knows one
	// (a pod name, an instance id). Empty when it does not.
	ID string

	// Addr is the peer's gossip address as host:port.
	Addr string

	// Meta holds provider-supplied labels — pod labels, instance tags. It is
	// surfaced for operators and never interpreted here.
	Meta map[string]string

	// Source names the Discoverer that produced this peer.
	Source string
}

// String renders the peer the way an operator would write it down.
func (p Peer) String() string {
	if p.ID == "" {
		return p.Addr
	}

	return p.ID + "@" + p.Addr
}

// Discoverer resolves the current set of peers.
//
// Discover is called repeatedly for as long as the node runs — deployments
// scale, pods reschedule, instances are replaced — so implementations must be
// safe to call concurrently and cheap enough to call on an interval.
type Discoverer interface {
	// Name identifies the provider in logs and in cluster status.
	Name() string

	// Discover returns the peers visible right now. Returning an empty slice
	// with a nil error is legitimate: it means "nobody yet", not "failed".
	Discover(ctx context.Context) ([]Peer, error)

	io.Closer
}

// Factory builds a Discoverer from the query part of a spec string.
type Factory func(spec *Spec) (Discoverer, error)

// Spec is a parsed discovery spec string.
//
// The string form is `scheme://target?opt=value`, where target and options are
// interpreted by the provider: `dns://plainq.internal?port=8082` names a host,
// `kubernetes://?selector=app%3Dplainq` names nothing and leans on options.
type Spec struct {
	// Scheme is the provider name, e.g. "kubernetes".
	Scheme string

	// Target is everything between the scheme and the query string. Providers
	// that address a single thing (a DNS name, a Consul service) use it.
	Target string

	// Options are the query parameters.
	Options url.Values

	// Raw is the spec exactly as the operator wrote it, for error messages.
	Raw string
}

// Option returns the first value for key, or def when it is absent or empty.
func (s *Spec) Option(key, def string) string {
	if v := s.Options.Get(key); v != "" {
		return v
	}

	return def
}

// OptionBool reads key as a boolean, falling back to def.
func (s *Spec) OptionBool(key string, def bool) (bool, error) {
	raw := s.Options.Get(key)
	if raw == "" {
		return def, nil
	}

	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("option %q of %q: %w", key, s.Raw, err)
	}

	return v, nil
}

// OptionInt reads key as an integer, falling back to def.
func (s *Spec) OptionInt(key string, def int) (int, error) {
	raw := s.Options.Get(key)
	if raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("option %q of %q: %w", key, s.Raw, err)
	}

	return v, nil
}

// OptionDuration reads key as a duration, falling back to def.
func (s *Spec) OptionDuration(key string, def time.Duration) (time.Duration, error) {
	raw := s.Options.Get(key)
	if raw == "" {
		return def, nil
	}

	v, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("option %q of %q: %w", key, s.Raw, err)
	}

	return v, nil
}

// OptionPort reads the "port" option, which nearly every provider needs
// because most of them return addresses without one.
func (s *Spec) OptionPort(def int) (int, error) {
	port, err := s.OptionInt("port", def)
	if err != nil {
		return 0, err
	}

	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("option %q of %q: port %d out of range", "port", s.Raw, port)
	}

	return port, nil
}

// registry maps a scheme to the factory that builds it.
//
// The table is spelled out rather than assembled from per-file init functions:
// one place lists every platform PlainQ can discover on, and it is the first
// thing to read when adding another.
var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{
		SchemeStatic:     newStaticFromSpec,
		SchemeDNS:        newDNSFromSpec,
		SchemeDNSSRV:     newDNSSRVFromSpec,
		SchemeKubernetes: newKubernetesFromSpec,
		SchemeK8s:        newKubernetesFromSpec,
		SchemeDocker:     newDockerFromSpec,
		SchemeAWS:        newAWSFromSpec,
		SchemeGCP:        newGCPFromSpec,
		SchemeGCE:        newGCPFromSpec,
		SchemeAzure:      newAzureFromSpec,
		SchemeConsul:     newConsulFromSpec,
	}
)

// Register adds a provider under the given scheme. It panics on a duplicate
// scheme, because that can only be a programming error at init time.
func Register(scheme string, factory Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[scheme]; exists {
		panic("discovery: duplicate provider registration for scheme " + scheme)
	}

	registry[scheme] = factory
}

// Providers lists the registered schemes in sorted order.
func Providers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	schemes := make([]string, 0, len(registry))
	for scheme := range registry {
		schemes = append(schemes, scheme)
	}

	sort.Strings(schemes)

	return schemes
}

// ParseSpec splits a spec string into its parts without building anything.
func ParseSpec(spec string) (*Spec, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, errors.New("discovery spec is empty")
	}

	scheme, rest, found := strings.Cut(trimmed, "://")
	if !found {
		// A bare host list is the overwhelmingly common case for a hand-built
		// cluster, so treat `a:8082,b:8082` as `static://a:8082,b:8082` rather
		// than making operators type the scheme.
		scheme, rest = SchemeStatic, trimmed
	}

	target, rawQuery, _ := strings.Cut(rest, "?")

	options, queryErr := url.ParseQuery(rawQuery)
	if queryErr != nil {
		return nil, fmt.Errorf("parse discovery spec %q: %w", spec, queryErr)
	}

	unescaped, unescapeErr := url.PathUnescape(target)
	if unescapeErr != nil {
		return nil, fmt.Errorf("parse discovery spec %q: %w", spec, unescapeErr)
	}

	parsed := Spec{
		Scheme:  strings.ToLower(scheme),
		Target:  unescaped,
		Options: options,
		Raw:     trimmed,
	}

	return &parsed, nil
}

// Parse builds the Discoverer named by a single spec string.
func Parse(spec string) (Discoverer, error) {
	parsed, parseErr := ParseSpec(spec)
	if parseErr != nil {
		return nil, parseErr
	}

	registryMu.RLock()

	factory, ok := registry[parsed.Scheme]

	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w %q (have: %s)",
			ErrUnknownProvider, parsed.Scheme, strings.Join(Providers(), ", "),
		)
	}

	discoverer, buildErr := factory(parsed)
	if buildErr != nil {
		return nil, fmt.Errorf("build %q discovery: %w", parsed.Scheme, buildErr)
	}

	return discoverer, nil
}

// ParseAll builds one Discoverer from several specs. With a single spec it
// returns that provider directly; with several it returns a Multi.
func ParseAll(specs ...string) (Discoverer, error) {
	discoverers := make([]Discoverer, 0, len(specs))

	for _, spec := range specs {
		if strings.TrimSpace(spec) == "" {
			continue
		}

		discoverer, err := Parse(spec)
		if err != nil {
			// Close what we already built: a half-constructed set of providers
			// can still hold sockets and tickers.
			for _, built := range discoverers {
				_ = built.Close()
			}

			return nil, err
		}

		discoverers = append(discoverers, discoverer)
	}

	switch len(discoverers) {
	case 0:
		return nil, errors.New("no discovery providers configured")

	case 1:
		return discoverers[0], nil

	default:
		return NewMulti(discoverers...), nil
	}
}

// Multi queries several providers and merges their results.
//
// A partial failure is not a failure: an EC2 API hiccup should not blind a
// node that also has a static seed list. Multi only errors when every provider
// failed, and it reports all of their errors when it does.
type Multi struct {
	discoverers []Discoverer
}

// NewMulti returns a Discoverer that fans out over the given providers.
func NewMulti(discoverers ...Discoverer) *Multi { return &Multi{discoverers: discoverers} }

// Name implements Discoverer.
func (m *Multi) Name() string {
	names := make([]string, 0, len(m.discoverers))
	for _, d := range m.discoverers {
		names = append(names, d.Name())
	}

	return "multi(" + strings.Join(names, ",") + ")"
}

// Discover implements Discoverer.
func (m *Multi) Discover(ctx context.Context) ([]Peer, error) {
	type result struct {
		peers []Peer
		err   error
	}

	results := make([]result, len(m.discoverers)) //nolint:makezero // indexed in place below, never appended to.

	var wg sync.WaitGroup

	for i, d := range m.discoverers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			peers, err := d.Discover(ctx)
			results[i] = result{peers: peers, err: err}
		}()
	}

	wg.Wait()

	var (
		peers  []Peer
		errs   []error
		failed int
	)

	for _, r := range results {
		if r.err != nil {
			failed++

			errs = append(errs, r.err)

			continue
		}

		peers = append(peers, r.peers...)
	}

	if failed == len(m.discoverers) && failed > 0 {
		return nil, fmt.Errorf("all discovery providers failed: %w", errors.Join(errs...))
	}

	return Dedupe(peers), errors.Join(errs...)
}

// Close implements Discoverer, closing every wrapped provider.
func (m *Multi) Close() error {
	var errs []error

	for _, d := range m.discoverers {
		if err := d.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// Dedupe removes peers that share an address, keeping the first occurrence but
// filling in an ID or Meta a later duplicate knows and the first did not. The
// result is sorted by address so callers — and tests — see a stable order.
func Dedupe(peers []Peer) []Peer {
	if len(peers) == 0 {
		return nil
	}

	byAddr := make(map[string]int, len(peers))

	out := make([]Peer, 0, len(peers))

	for _, p := range peers {
		if p.Addr == "" {
			continue
		}

		idx, seen := byAddr[p.Addr]
		if !seen {
			byAddr[p.Addr] = len(out)
			out = append(out, p)

			continue
		}

		if out[idx].ID == "" {
			out[idx].ID = p.ID
		}

		for k, v := range p.Meta {
			if out[idx].Meta == nil {
				out[idx].Meta = make(map[string]string, len(p.Meta))
			}

			if _, exists := out[idx].Meta[k]; !exists {
				out[idx].Meta[k] = v
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })

	return out
}

// Addrs projects peers down to the address list gossip wants.
func Addrs(peers []Peer) []string {
	addrs := make([]string, 0, len(peers))
	for _, p := range peers {
		addrs = append(addrs, p.Addr)
	}

	return addrs
}

// JoinHostPort attaches a port to a bare host, and leaves an address that
// already carries one alone. Most providers return one or the other depending
// on how the deployment is configured, and callers should not have to care.
func JoinHostPort(host string, port int) string {
	if host == "" {
		return ""
	}

	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}

	// A bare IPv6 literal has colons but no port, so SplitHostPort rejects it
	// above and net.JoinHostPort brackets it correctly here.
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// Static is the simplest Discoverer: a fixed list, useful for hand-built
// clusters, for tests, and as a seed alongside a dynamic provider.
type Static struct {
	peers []Peer
}

// NewStatic returns a Discoverer over a fixed list of host:port addresses.
// A bare host takes defaultPort.
func NewStatic(addrs []string, defaultPort int) *Static {
	peers := make([]Peer, 0, len(addrs))

	for _, addr := range addrs {
		trimmed := strings.TrimSpace(addr)
		if trimmed == "" {
			continue
		}

		peers = append(peers, Peer{
			Addr:   JoinHostPort(trimmed, defaultPort),
			Source: SchemeStatic,
		})
	}

	return &Static{peers: peers}
}

// Name implements Discoverer.
func (s *Static) Name() string { return SchemeStatic }

// Discover implements Discoverer.
func (s *Static) Discover(context.Context) ([]Peer, error) {
	out := make([]Peer, len(s.peers)) //nolint:makezero // filled by copy, never appended to.
	copy(out, s.peers)

	return out, nil
}

// Close implements Discoverer.
func (s *Static) Close() error { return nil }

// defaultGossipPort is the port assumed when a provider hands back a bare
// address and the spec did not say otherwise.
//
// Discovery answers with *gossip* addresses, not consensus ones. Gossip is
// what makes first contact, and a peer's consensus address is part of the
// metadata it gossips — so discovery only ever has to find the one port, and
// the other is learned rather than configured twice.
const defaultGossipPort = 8083

// newStaticFromSpec builds a fixed-list discoverer.
func newStaticFromSpec(spec *Spec) (Discoverer, error) {
	port, portErr := spec.OptionPort(defaultGossipPort)
	if portErr != nil {
		return nil, portErr
	}

	addrs := strings.Split(spec.Target, ",")
	if extra := spec.Options["addr"]; len(extra) > 0 {
		addrs = append(addrs, extra...)
	}

	static := NewStatic(addrs, port)
	if len(static.peers) == 0 {
		return nil, fmt.Errorf("static discovery %q lists no addresses", spec.Raw)
	}

	return static, nil
}
