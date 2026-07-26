package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Azure endpoints. Resource Graph answers "which machines carry this tag, and
// what are their IPs" in one query, which is why it is preferred here over
// walking Compute → NIC → IP configuration across three API calls.
const (
	azureIMDSBase          = "http://169.254.169.254/metadata"
	azureManagementBase    = "https://management.azure.com"
	azureResourceGraphPath = "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
	azureManagementScope   = "https://management.azure.com/"
)

// azureTokenSkew mirrors the GCP one: refresh before expiry, never during a
// request.
const azureTokenSkew = 60 * time.Second

// Azure discovers peers from virtual machines (including scale-set instances)
// carrying a tag.
type Azure struct {
	client httpDoer

	imdsBase       string
	managementBase string

	// subscription scopes the Resource Graph query.
	subscriptions []string

	// resourceGroup narrows it further; optional.
	resourceGroup string

	// tagKey and tagValue select machines.
	tagKey   string
	tagValue string

	// scaleSet narrows to one VMSS by name; optional.
	scaleSet string

	port int

	tokenMu      sync.Mutex
	token        string
	tokenExpires time.Time
	staticToken  string

	now func() time.Time
}

// AzureOption configures an Azure discoverer.
type AzureOption func(*Azure)

// WithAzureClient overrides the HTTP client.
func WithAzureClient(client httpDoer) AzureOption { return func(a *Azure) { a.client = client } }

// WithAzureIMDSBase overrides the instance metadata base URL.
func WithAzureIMDSBase(base string) AzureOption {
	return func(a *Azure) { a.imdsBase = strings.TrimSuffix(base, "/") }
}

// WithAzureManagementBase overrides the management API base URL.
func WithAzureManagementBase(base string) AzureOption {
	return func(a *Azure) { a.managementBase = strings.TrimSuffix(base, "/") }
}

// WithAzureToken sets a fixed bearer token, bypassing IMDS.
func WithAzureToken(token string) AzureOption { return func(a *Azure) { a.staticToken = token } }

// WithAzureResourceGroup narrows the query to one resource group.
func WithAzureResourceGroup(group string) AzureOption {
	return func(a *Azure) { a.resourceGroup = group }
}

// WithAzureScaleSet narrows the query to one scale set.
func WithAzureScaleSet(name string) AzureOption { return func(a *Azure) { a.scaleSet = name } }

// WithAzureClock overrides the clock, for tests.
func WithAzureClock(now func() time.Time) AzureOption { return func(a *Azure) { a.now = now } }

// NewAzure returns a Discoverer over Azure VMs tagged tagKey=tagValue.
func NewAzure(subscriptions []string, tagKey, tagValue string, port int, opts ...AzureOption) (*Azure, error) {
	a := Azure{
		imdsBase:       azureIMDSBase,
		managementBase: azureManagementBase,
		subscriptions:  subscriptions,
		tagKey:         tagKey,
		tagValue:       tagValue,
		port:           port,
		now:            time.Now,
	}

	for _, opt := range opts {
		opt(&a)
	}

	if a.client == nil {
		a.client = newHTTPClient()
	}

	if a.tagKey == "" {
		return nil, errors.New("azure discovery: a tag is required (e.g. tag=cluster%3Dplainq)")
	}

	if len(a.subscriptions) == 0 {
		subscription, err := a.instanceSubscription(context.Background())
		if err != nil {
			return nil, fmt.Errorf("azure discovery: subscription is not set and IMDS did not answer: %w", err)
		}

		a.subscriptions = []string{subscription}
	}

	return &a, nil
}

// Name implements Discoverer.
func (a *Azure) Name() string { return SchemeAzure }

// azureGraphResponse is the subset of a Resource Graph answer we read. The
// projection in the query below fixes the column names, so the rows decode
// into a known shape.
type azureGraphResponse struct {
	Count int `json:"count"`
	Data  []struct {
		Name    string            `json:"name"`
		ID      string            `json:"id"`
		Address string            `json:"address"`
		Tags    map[string]string `json:"tags"`
	} `json:"data"`
}

// Discover implements Discoverer.
func (a *Azure) Discover(ctx context.Context) ([]Peer, error) {
	token, tokenErr := a.accessToken(ctx)
	if tokenErr != nil {
		return nil, tokenErr
	}

	body, encodeErr := json.Marshal(map[string]any{
		"subscriptions": a.subscriptions,
		"query":         a.graphQuery(),
	})
	if encodeErr != nil {
		return nil, fmt.Errorf("encode Resource Graph query: %w", encodeErr)
	}

	headers := map[string]string{
		headerAuthorization: bearer + token,
		"Content-Type":      "application/json",
	}

	var resp azureGraphResponse

	graphURL := a.managementBase + azureResourceGraphPath

	if err := doJSON(ctx, a.client, "POST", graphURL, headers, bytes.NewReader(body), &resp); err != nil {
		return nil, fmt.Errorf("query Azure Resource Graph: %w", err)
	}

	peers := make([]Peer, 0, len(resp.Data))

	for _, row := range resp.Data {
		if row.Address == "" {
			continue
		}

		meta := map[string]string{"resource_id": row.ID}
		for key, value := range row.Tags {
			meta["tag."+key] = value
		}

		peers = append(peers, Peer{
			ID:     row.Name,
			Addr:   JoinHostPort(row.Address, a.port),
			Meta:   meta,
			Source: SchemeAzure,
		})
	}

	return peers, nil
}

// graphQuery builds the KQL that Resource Graph runs. It joins network
// interfaces to their virtual machines so one round trip yields addresses,
// which is the whole reason for using Resource Graph instead of the Compute
// API.
func (a *Azure) graphQuery() string {
	var query strings.Builder

	query.WriteString(`Resources | where type =~ 'microsoft.network/networkinterfaces'`)
	query.WriteString(` | mv-expand ipconfig = properties.ipConfigurations`)
	query.WriteString(` | extend address = tostring(ipconfig.properties.privateIPAddress)`)
	query.WriteString(` | extend vmId = tostring(properties.virtualMachine.id)`)
	query.WriteString(` | join kind=inner (`)
	query.WriteString(`Resources | where type =~ 'microsoft.compute/virtualmachines'`)
	query.WriteString(` or type =~ 'microsoft.compute/virtualmachinescalesets/virtualmachines'`)
	fmt.Fprintf(&query, ` | where tags['%s'] =~ '%s'`, escapeKQL(a.tagKey), escapeKQL(a.tagValue))

	if a.resourceGroup != "" {
		fmt.Fprintf(&query, ` | where resourceGroup =~ '%s'`, escapeKQL(a.resourceGroup))
	}

	if a.scaleSet != "" {
		fmt.Fprintf(&query, ` | where id contains '/virtualMachineScaleSets/%s/'`, escapeKQL(a.scaleSet))
	}

	query.WriteString(` | project vmId = id, name, tags`)
	query.WriteString(`) on vmId`)
	query.WriteString(` | project name, id = vmId, address, tags`)

	return query.String()
}

// Close implements Discoverer.
func (a *Azure) Close() error { return nil }

type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   string `json:"expires_in"`
}

func (a *Azure) accessToken(ctx context.Context) (string, error) {
	if a.staticToken != "" {
		return a.staticToken, nil
	}

	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	if a.token != "" && a.now().Before(a.tokenExpires) {
		return a.token, nil
	}

	query := url.Values{}
	query.Set("api-version", "2018-02-01")
	query.Set("resource", azureManagementScope)

	tokenURL := a.imdsBase + "/identity/oauth2/token?" + query.Encode()

	var token azureTokenResponse

	if err := getJSON(ctx, a.client, tokenURL, azureIMDSHeaders(), &token); err != nil {
		return "", fmt.Errorf("fetch Azure access token: %w", err)
	}

	if token.AccessToken == "" {
		return "", errors.New("azure discovery: IMDS returned an empty access token")
	}

	// IMDS reports expires_in as a string of seconds. A malformed value is not
	// worth failing over — fall back to a short lifetime and refresh sooner.
	lifetime := 5 * time.Minute

	if seconds, err := time.ParseDuration(token.ExpiresIn + "s"); err == nil && seconds > azureTokenSkew {
		lifetime = seconds - azureTokenSkew
	}

	a.token = token.AccessToken
	a.tokenExpires = a.now().Add(lifetime)

	return a.token, nil
}

// instanceSubscription reads the subscription this VM belongs to from IMDS.
func (a *Azure) instanceSubscription(ctx context.Context) (string, error) {
	var instance struct {
		Compute struct {
			SubscriptionID string `json:"subscriptionId"`
		} `json:"compute"`
	}

	instanceURL := a.imdsBase + "/instance?api-version=2021-02-01"

	if err := getJSON(ctx, a.client, instanceURL, azureIMDSHeaders(), &instance); err != nil {
		return "", err
	}

	if instance.Compute.SubscriptionID == "" {
		return "", errors.New("IMDS returned no subscription id")
	}

	return instance.Compute.SubscriptionID, nil
}

// azureIMDSHeaders are the headers the instance metadata service requires.
func azureIMDSHeaders() map[string]string { return map[string]string{"Metadata": "true"} }

// escapeKQL makes a value safe to embed in a single-quoted KQL literal.
func escapeKQL(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `'`, `\'`)
}

// newAzureFromSpec builds an Azure discoverer.
func newAzureFromSpec(spec *Spec) (Discoverer, error) {
	port, portErr := spec.OptionPort(defaultGossipPort)
	if portErr != nil {
		return nil, portErr
	}

	var subscriptions []string

	for _, raw := range spec.Options["subscription"] {
		subscriptions = append(subscriptions, strings.Split(raw, ",")...)
	}

	if spec.Target != "" {
		subscriptions = append(subscriptions, spec.Target)
	}

	tagKey, tagValue, _ := strings.Cut(spec.Option("tag", ""), "=")

	opts := make([]AzureOption, 0, 4)

	if group := spec.Option("resource-group", ""); group != "" {
		opts = append(opts, WithAzureResourceGroup(group))
	}

	if scaleSet := spec.Option("scale-set", ""); scaleSet != "" {
		opts = append(opts, WithAzureScaleSet(scaleSet))
	}

	if base := spec.Option("management-base", ""); base != "" {
		opts = append(opts, WithAzureManagementBase(base))
	}

	if base := spec.Option("imds-base", ""); base != "" {
		opts = append(opts, WithAzureIMDSBase(base))
	}

	return NewAzure(subscriptions, tagKey, tagValue, port, opts...)
}
