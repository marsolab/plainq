package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Consul discovers peers from a Consul catalog service.
//
// It reads the health endpoint rather than the catalog one so that failing
// instances are filtered out by Consul itself, which already knows more about
// their health than we do.
type Consul struct {
	client httpDoer

	// address is the Consul HTTP API base URL.
	address string

	// service is the registered service name.
	service string

	// tag narrows the result to instances carrying it; optional.
	tag string

	// datacenter selects a non-local datacenter; optional.
	datacenter string

	// token is an ACL token; optional.
	token string

	// port overrides the port Consul reports. Zero keeps Consul's.
	port int
}

// ConsulOption configures a Consul discoverer.
type ConsulOption func(*Consul)

// WithConsulClient overrides the HTTP client.
func WithConsulClient(client httpDoer) ConsulOption { return func(c *Consul) { c.client = client } }

// WithConsulToken sets the ACL token sent with each request.
func WithConsulToken(token string) ConsulOption { return func(c *Consul) { c.token = token } }

// WithConsulTag narrows discovery to instances carrying tag.
func WithConsulTag(tag string) ConsulOption { return func(c *Consul) { c.tag = tag } }

// WithConsulDatacenter selects the datacenter to query.
func WithConsulDatacenter(dc string) ConsulOption { return func(c *Consul) { c.datacenter = dc } }

// WithConsulPort overrides the port Consul reports for each instance.
func WithConsulPort(port int) ConsulOption { return func(c *Consul) { c.port = port } }

// NewConsul returns a Discoverer over healthy instances of a Consul service.
func NewConsul(address, service string, opts ...ConsulOption) (*Consul, error) {
	c := Consul{
		address: strings.TrimSuffix(address, "/"),
		service: service,
	}

	for _, opt := range opts {
		opt(&c)
	}

	if c.address == "" {
		c.address = "http://127.0.0.1:8500"
	}

	if c.service == "" {
		return nil, errors.New("consul discovery: service name is required")
	}

	if c.client == nil {
		c.client = newHTTPClient()
	}

	return &c, nil
}

// Name implements Discoverer.
func (c *Consul) Name() string { return SchemeConsul }

// consulHealthEntry is the subset of /v1/health/service we read.
type consulHealthEntry struct {
	Node struct {
		Node    string `json:"Node"`
		Address string `json:"Address"`
	} `json:"Node"`

	Service struct {
		ID      string            `json:"ID"`
		Service string            `json:"Service"`
		Address string            `json:"Address"`
		Port    int               `json:"Port"`
		Tags    []string          `json:"Tags"`
		Meta    map[string]string `json:"Meta"`
	} `json:"Service"`
}

// Discover implements Discoverer.
//
//nolint:cyclop // One branch per optional field of a Consul health entry.
func (c *Consul) Discover(ctx context.Context) ([]Peer, error) {
	query := url.Values{}
	query.Set("passing", "true")

	if c.tag != "" {
		query.Set("tag", c.tag)
	}

	if c.datacenter != "" {
		query.Set("dc", c.datacenter)
	}

	listURL := fmt.Sprintf("%s/v1/health/service/%s?%s",
		c.address, url.PathEscape(c.service), query.Encode(),
	)

	headers := map[string]string{}
	if c.token != "" {
		headers["X-Consul-Token"] = c.token
	}

	var entries []consulHealthEntry

	if err := getJSON(ctx, c.client, listURL, headers, &entries); err != nil {
		return nil, fmt.Errorf("list consul service %q: %w", c.service, err)
	}

	peers := make([]Peer, 0, len(entries))

	for _, entry := range entries {
		// A service registration may override the node address; Consul's own
		// resolution order is service address first, node address second.
		host := firstNonEmpty(entry.Service.Address, entry.Node.Address)
		if host == "" {
			continue
		}

		port := entry.Service.Port
		if c.port != 0 {
			port = c.port
		}

		if port == 0 {
			continue
		}

		meta := map[string]string{"node": entry.Node.Node}

		for key, value := range entry.Service.Meta {
			meta["meta."+key] = value
		}

		if len(entry.Service.Tags) > 0 {
			meta["tags"] = strings.Join(entry.Service.Tags, ",")
		}

		peers = append(peers, Peer{
			ID:     firstNonEmpty(entry.Service.ID, entry.Node.Node),
			Addr:   host + ":" + strconv.Itoa(port),
			Meta:   meta,
			Source: SchemeConsul,
		})
	}

	return peers, nil
}

// Close implements Discoverer.
func (c *Consul) Close() error { return nil }

// newConsulFromSpec builds a Consul discoverer.
//
// `consul://plainq` names the service; `consul://host:8500/plainq` names both.
// Either reads naturally.
func newConsulFromSpec(spec *Spec) (Discoverer, error) {
	service := spec.Option("service", "")
	address := spec.Option("address", "")

	if spec.Target != "" {
		address, service = consulTarget(spec.Target, address, service)
	}

	opts := make([]ConsulOption, 0, 4)

	if tag := spec.Option("tag", ""); tag != "" {
		opts = append(opts, WithConsulTag(tag))
	}

	if dc := spec.Option("dc", spec.Option("datacenter", "")); dc != "" {
		opts = append(opts, WithConsulDatacenter(dc))
	}

	if token := spec.Option("token", ""); token != "" {
		opts = append(opts, WithConsulToken(token))
	}

	if spec.Options.Get("port") != "" {
		port, portErr := spec.OptionPort(defaultGossipPort)
		if portErr != nil {
			return nil, portErr
		}

		opts = append(opts, WithConsulPort(port))
	}

	return NewConsul(address, service, opts...)
}

// consulTarget splits the target into an address and a service, keeping
// whatever the options already supplied.
//
//nolint:nonamedreturns // two bare strings in a row need naming to be readable.
func consulTarget(target, address, service string) (resolvedAddress, resolvedService string) {
	host, path, found := strings.Cut(target, "/")

	if !found {
		if service == "" {
			service = host
		}

		return address, service
	}

	if address == "" {
		address = "http://" + host
	}

	if service == "" {
		service = path
	}

	return address, service
}
