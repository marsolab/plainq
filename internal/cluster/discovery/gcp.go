package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GCE API and metadata endpoints.
const (
	gceAPIBase      = "https://compute.googleapis.com/compute/v1"
	gcpMetadataBase = "http://metadata.google.internal/computeMetadata/v1"
)

// gcpTokenSkew is how far before its stated expiry a metadata token is
// refreshed, so a token never expires mid-request.
const gcpTokenSkew = 60 * time.Second

// GCP discovers peers from Compute Engine instances.
//
// Authentication comes from the instance metadata server, which is how a
// workload on GCE or GKE is meant to get a token. That keeps the provider to
// two plain HTTPS calls and no SDK.
type GCP struct {
	client httpDoer

	// apiBase and metadataBase are overridable so the provider can be pointed
	// at a test server.
	apiBase      string
	metadataBase string

	// project is the GCP project id.
	project string

	// zones scopes the search; empty means every zone (an aggregated list).
	zones []string

	// filter is a GCE list filter expression, e.g. `labels.cluster=plainq`.
	filter string

	// port is attached to instance addresses (the gossip port).
	port int

	// internal selects the internal (NIC) IP over the external one.
	internal bool

	tokenMu      sync.Mutex
	token        string
	tokenExpires time.Time

	// staticToken bypasses the metadata server entirely.
	staticToken string

	now func() time.Time
}

// GCPOption configures a GCP discoverer.
type GCPOption func(*GCP)

// WithGCPClient overrides the HTTP client.
func WithGCPClient(client httpDoer) GCPOption { return func(g *GCP) { g.client = client } }

// WithGCPAPIBase overrides the Compute API base URL.
func WithGCPAPIBase(base string) GCPOption {
	return func(g *GCP) { g.apiBase = strings.TrimSuffix(base, "/") }
}

// WithGCPMetadataBase overrides the metadata server base URL.
func WithGCPMetadataBase(base string) GCPOption {
	return func(g *GCP) { g.metadataBase = strings.TrimSuffix(base, "/") }
}

// WithGCPToken sets a fixed OAuth token, bypassing the metadata server.
func WithGCPToken(token string) GCPOption { return func(g *GCP) { g.staticToken = token } }

// WithGCPExternalIP reads the external NAT address instead of the internal one.
func WithGCPExternalIP() GCPOption { return func(g *GCP) { g.internal = false } }

// WithGCPClock overrides the clock, for tests.
func WithGCPClock(now func() time.Time) GCPOption { return func(g *GCP) { g.now = now } }

// NewGCP returns a Discoverer over GCE instances matching filter.
func NewGCP(project string, zones []string, filter string, port int, opts ...GCPOption) (*GCP, error) {
	g := GCP{
		apiBase:      gceAPIBase,
		metadataBase: gcpMetadataBase,
		project:      project,
		zones:        zones,
		filter:       filter,
		port:         port,
		internal:     true,
		now:          time.Now,
	}

	for _, opt := range opts {
		opt(&g)
	}

	if g.client == nil {
		g.client = newHTTPClient()
	}

	if g.project == "" {
		project, err := g.metadata(context.Background(), "/project/project-id")
		if err != nil {
			return nil, fmt.Errorf("gcp discovery: project is not set and the metadata server did not answer: %w", err)
		}

		g.project = project
	}

	if g.filter == "" {
		return nil, errors.New("gcp discovery: a filter is required (e.g. labels.cluster=plainq)")
	}

	return &g, nil
}

// Name implements Discoverer.
func (g *GCP) Name() string { return SchemeGCP }

// gceInstanceList is the subset of the Compute API instance list we read. It
// covers both the zonal shape (`items` is a list) and the aggregated shape
// (`items` is a map of zone to a list), by decoding each separately.
type gceInstance struct {
	Name   string            `json:"name"`
	Status string            `json:"status"`
	Zone   string            `json:"zone"`
	Labels map[string]string `json:"labels"`

	NetworkInterfaces []struct {
		NetworkIP     string `json:"networkIP"`
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
}

type gceZonalList struct {
	Items         []gceInstance `json:"items"`
	NextPageToken string        `json:"nextPageToken"`
}

type gceAggregatedList struct {
	Items map[string]struct {
		Instances []gceInstance `json:"instances"`
	} `json:"items"`

	NextPageToken string `json:"nextPageToken"`
}

// Discover implements Discoverer.
func (g *GCP) Discover(ctx context.Context) ([]Peer, error) {
	token, tokenErr := g.accessToken(ctx)
	if tokenErr != nil {
		return nil, tokenErr
	}

	headers := map[string]string{headerAuthorization: bearer + token}

	if len(g.zones) == 0 {
		return g.discoverAggregated(ctx, headers)
	}

	var peers []Peer

	for _, zone := range g.zones {
		zonal, err := g.discoverZone(ctx, headers, zone)
		if err != nil {
			return nil, err
		}

		peers = append(peers, zonal...)
	}

	return peers, nil
}

func (g *GCP) discoverZone(ctx context.Context, headers map[string]string, zone string) ([]Peer, error) {
	var peers []Peer

	pageToken := ""

	for page := 0; page < 20; page++ {
		query := url.Values{}
		query.Set("filter", g.filter)

		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}

		listURL := fmt.Sprintf("%s/projects/%s/zones/%s/instances?%s",
			g.apiBase, url.PathEscape(g.project), url.PathEscape(zone), query.Encode(),
		)

		var list gceZonalList

		if err := getJSON(ctx, g.client, listURL, headers, &list); err != nil {
			return nil, fmt.Errorf("list GCE instances in zone %q: %w", zone, err)
		}

		peers = append(peers, g.toPeers(list.Items)...)

		if list.NextPageToken == "" {
			break
		}

		pageToken = list.NextPageToken
	}

	return peers, nil
}

func (g *GCP) discoverAggregated(ctx context.Context, headers map[string]string) ([]Peer, error) {
	var peers []Peer

	pageToken := ""

	for page := 0; page < 20; page++ {
		query := url.Values{}
		query.Set("filter", g.filter)

		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}

		listURL := fmt.Sprintf("%s/projects/%s/aggregated/instances?%s",
			g.apiBase, url.PathEscape(g.project), query.Encode(),
		)

		var list gceAggregatedList

		if err := getJSON(ctx, g.client, listURL, headers, &list); err != nil {
			return nil, fmt.Errorf("list GCE instances in project %q: %w", g.project, err)
		}

		for _, scoped := range list.Items {
			peers = append(peers, g.toPeers(scoped.Instances)...)
		}

		if list.NextPageToken == "" {
			break
		}

		pageToken = list.NextPageToken
	}

	return peers, nil
}

func (g *GCP) toPeers(instances []gceInstance) []Peer {
	peers := make([]Peer, 0, len(instances))

	for _, instance := range instances {
		if instance.Status != "RUNNING" {
			continue
		}

		host := ""

		for _, nic := range instance.NetworkInterfaces {
			if g.internal {
				host = nic.NetworkIP
			} else {
				for _, access := range nic.AccessConfigs {
					if access.NatIP != "" {
						host = access.NatIP

						break
					}
				}
			}

			if host != "" {
				break
			}
		}

		if host == "" {
			continue
		}

		meta := map[string]string{"instance": instance.Name, "zone": lastPathSegment(instance.Zone)}
		for key, value := range instance.Labels {
			meta["label."+key] = value
		}

		peers = append(peers, Peer{
			ID:     instance.Name,
			Addr:   JoinHostPort(host, g.port),
			Meta:   meta,
			Source: SchemeGCP,
		})
	}

	return peers
}

// Close implements Discoverer.
func (g *GCP) Close() error { return nil }

type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// accessToken fetches (and caches) an OAuth token from the metadata server.
func (g *GCP) accessToken(ctx context.Context) (string, error) {
	if g.staticToken != "" {
		return g.staticToken, nil
	}

	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()

	if g.token != "" && g.now().Before(g.tokenExpires) {
		return g.token, nil
	}

	var token gcpTokenResponse

	tokenURL := g.metadataBase + "/instance/service-accounts/default/token"
	headers := map[string]string{"Metadata-Flavor": "Google"}

	if err := getJSON(ctx, g.client, tokenURL, headers, &token); err != nil {
		return "", fmt.Errorf("fetch GCP access token: %w", err)
	}

	if token.AccessToken == "" {
		return "", errors.New("gcp discovery: metadata server returned an empty access token")
	}

	g.token = token.AccessToken
	g.tokenExpires = g.now().Add(time.Duration(token.ExpiresIn)*time.Second - gcpTokenSkew)

	return g.token, nil
}

// metadata reads a single value from the metadata server.
func (g *GCP) metadata(ctx context.Context, path string) (string, error) {
	req, reqErr := newTextRequest(ctx, g.metadataBase+path, map[string]string{"Metadata-Flavor": "Google"})
	if reqErr != nil {
		return "", reqErr
	}

	return readText(g.client, req)
}

// lastPathSegment turns a GCE self-link like
// `https://…/zones/europe-west1-b` into `europe-west1-b`.
func lastPathSegment(link string) string {
	if idx := strings.LastIndex(link, "/"); idx >= 0 {
		return link[idx+1:]
	}

	return link
}

func newGCPFromSpec(spec *Spec) (Discoverer, error) {
	port, portErr := spec.OptionPort(defaultGossipPort)
	if portErr != nil {
		return nil, portErr
	}

	project := spec.Option("project", spec.Target)

	var zones []string

	for _, zone := range spec.Options["zone"] {
		zones = append(zones, strings.Split(zone, ",")...)
	}

	filter := spec.Option("filter", "")

	// `label=cluster%3Dplainq` is the shorthand: it is what people mean when
	// they say "the instances tagged for this cluster", spelled without GCE
	// filter syntax.
	if filter == "" {
		if label := spec.Option("label", ""); label != "" {
			key, value, _ := strings.Cut(label, "=")
			filter = fmt.Sprintf("labels.%s=%s", key, value)
		}
	}

	opts := make([]GCPOption, 0, 3)

	if base := spec.Option("api-base", ""); base != "" {
		opts = append(opts, WithGCPAPIBase(base))
	}

	if base := spec.Option("metadata-base", ""); base != "" {
		opts = append(opts, WithGCPMetadataBase(base))
	}

	external, externalErr := spec.OptionBool("external", false)
	if externalErr != nil {
		return nil, externalErr
	}

	if external {
		opts = append(opts, WithGCPExternalIP())
	}

	return NewGCP(project, zones, filter, port, opts...)
}
