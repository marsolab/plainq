package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// dockerAPIVersion pins the Engine API version. Pinning keeps the request
// shape stable across daemon upgrades; this one has been available since
// Docker 20.10.
const dockerAPIVersion = "v1.41"

// defaultDockerSocket is where the Engine listens on Linux.
const defaultDockerSocket = "/var/run/docker.sock"

// Docker discovers peers from the Docker Engine API.
//
// This is the Compose and Swarm-less story: containers carrying an agreed
// label are the cluster. The provider reads container IPs from the Docker
// network they share, so peers reach each other on the container network
// rather than through published ports.
type Docker struct {
	client httpDoer

	// host is the base URL used for requests. For a unix socket it is a
	// placeholder host — the dialer, not the URL, decides where to connect.
	host string

	// labels filter containers; all must match.
	labels map[string]string

	// network selects which of a container's networks to read the IP from.
	// Empty takes the first, which is right when containers sit on one.
	network string

	// port is attached to container IPs.
	port int
}

// DockerOption configures a Docker discoverer.
type DockerOption func(*Docker)

// WithDockerClient overrides the HTTP client.
func WithDockerClient(client httpDoer) DockerOption {
	return func(d *Docker) { d.client = client }
}

// WithDockerHost overrides the daemon endpoint. It accepts the same forms as
// DOCKER_HOST: `unix:///var/run/docker.sock`, `tcp://host:2375`, `http://…`.
func WithDockerHost(host string) DockerOption {
	return func(d *Docker) { d.host = host }
}

// WithDockerNetwork selects the network whose IP identifies a peer.
func WithDockerNetwork(network string) DockerOption {
	return func(d *Docker) { d.network = network }
}

// NewDocker returns a Discoverer over containers matching labels.
func NewDocker(labels map[string]string, port int, opts ...DockerOption) (*Docker, error) {
	d := Docker{
		host:   "unix://" + defaultDockerSocket,
		labels: labels,
		port:   port,
	}

	for _, opt := range opts {
		opt(&d)
	}

	if len(d.labels) == 0 {
		return nil, errors.New("docker discovery: at least one label filter is required")
	}

	if d.client == nil {
		client, base, clientErr := newDockerHTTPClient(d.host)
		if clientErr != nil {
			return nil, clientErr
		}

		d.client = client
		d.host = base
	} else {
		d.host = normalizeDockerBase(d.host)
	}

	return &d, nil
}

// Name implements Discoverer.
func (d *Docker) Name() string { return SchemeDocker }

// dockerContainer is the subset of the Engine API container list we read.
type dockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`

	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`

	Ports []struct {
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// Discover implements Discoverer.
func (d *Docker) Discover(ctx context.Context) ([]Peer, error) {
	filters := map[string][]string{"status": {"running"}}

	labelFilters := make([]string, 0, len(d.labels))
	for key, value := range d.labels {
		if value == "" {
			labelFilters = append(labelFilters, key)

			continue
		}

		labelFilters = append(labelFilters, key+"="+value)
	}

	filters["label"] = labelFilters

	encoded, encodeErr := json.Marshal(filters)
	if encodeErr != nil {
		return nil, fmt.Errorf("encode docker filters: %w", encodeErr)
	}

	query := url.Values{}
	query.Set("filters", string(encoded))

	listURL := fmt.Sprintf("%s/%s/containers/json?%s", d.host, dockerAPIVersion, query.Encode())

	var containers []dockerContainer

	if err := getJSON(ctx, d.client, listURL, nil, &containers); err != nil {
		return nil, fmt.Errorf("list docker containers: %w", err)
	}

	peers := make([]Peer, 0, len(containers))

	for _, container := range containers {
		addr := d.containerAddr(container)
		if addr == "" {
			continue
		}

		meta := map[string]string{"container_id": shortID(container.ID)}
		if len(container.Names) > 0 {
			meta["container_name"] = strings.TrimPrefix(container.Names[0], "/")
		}

		for key, value := range container.Labels {
			meta["label."+key] = value
		}

		peers = append(peers, Peer{
			ID:     shortID(container.ID),
			Addr:   addr,
			Meta:   meta,
			Source: SchemeDocker,
		})
	}

	return peers, nil
}

// containerAddr picks the address a peer is reachable at. The container
// network IP is preferred — that is the address other containers can dial —
// with a published host port as the fallback for containers running on the
// host network.
func (d *Docker) containerAddr(container dockerContainer) string {
	networks := container.NetworkSettings.Networks

	if d.network != "" {
		if settings, ok := networks[d.network]; ok {
			if ip := firstNonEmpty(settings.IPAddress, settings.GlobalIPv6Address); ip != "" {
				return JoinHostPort(ip, d.port)
			}
		}

		return ""
	}

	// Map iteration order is random, so pick deterministically by network name
	// to keep repeated discoveries from flapping between two addresses.
	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		if ip := firstNonEmpty(networks[name].IPAddress, networks[name].GlobalIPv6Address); ip != "" {
			return JoinHostPort(ip, d.port)
		}
	}

	for _, port := range container.Ports {
		if port.PrivatePort == d.port && port.PublicPort != 0 {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port.PublicPort))
		}
	}

	return ""
}

// Close implements Discoverer.
func (d *Docker) Close() error { return nil }

// newDockerHTTPClient builds a client that speaks to a unix socket or a TCP
// endpoint, and returns the base URL to use with it.
func newDockerHTTPClient(host string) (*http.Client, string, error) {
	switch {
	case strings.HasPrefix(host, "unix://"):
		socket := strings.TrimPrefix(host, "unix://")

		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer

				return dialer.DialContext(ctx, "unix", socket)
			},
		}

		// The host in the URL is ignored by the unix dialer but still has to
		// parse, so give it a name that reads honestly in an error message.
		return &http.Client{Timeout: defaultHTTPTimeout, Transport: transport}, "http://docker", nil

	case strings.HasPrefix(host, "tcp://"):
		return newHTTPClient(), "http://" + strings.TrimPrefix(host, "tcp://"), nil

	case strings.HasPrefix(host, "http://"), strings.HasPrefix(host, "https://"):
		return newHTTPClient(), strings.TrimSuffix(host, "/"), nil

	default:
		return nil, "", fmt.Errorf("docker discovery: unsupported host %q", host)
	}
}

func normalizeDockerBase(host string) string {
	switch {
	case strings.HasPrefix(host, "unix://"):
		return "http://docker"

	case strings.HasPrefix(host, "tcp://"):
		return "http://" + strings.TrimPrefix(host, "tcp://")

	default:
		return strings.TrimSuffix(host, "/")
	}
}

func shortID(id string) string {
	const shortIDLen = 12

	if len(id) > shortIDLen {
		return id[:shortIDLen]
	}

	return id
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return ""
}

// newDockerFromSpec builds a Docker discoverer.
func newDockerFromSpec(spec *Spec) (Discoverer, error) {
	port, portErr := spec.OptionPort(defaultGossipPort)
	if portErr != nil {
		return nil, portErr
	}

	labels := map[string]string{}

	for _, raw := range spec.Options["label"] {
		key, value, _ := strings.Cut(raw, "=")
		if key = strings.TrimSpace(key); key != "" {
			labels[key] = value
		}
	}

	if spec.Target != "" {
		key, value, _ := strings.Cut(spec.Target, "=")
		if key = strings.TrimSpace(key); key != "" {
			labels[key] = value
		}
	}

	opts := make([]DockerOption, 0, 2)

	if host := spec.Option("host", ""); host != "" {
		opts = append(opts, WithDockerHost(host))
	}

	if network := spec.Option("network", ""); network != "" {
		opts = append(opts, WithDockerNetwork(network))
	}

	return NewDocker(labels, port, opts...)
}
