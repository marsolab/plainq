package discovery

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// ec2APIVersion pins the EC2 query API version used for DescribeInstances.
const ec2APIVersion = "2016-11-15"

// emptyPayloadSHA256 is the SigV4 hash of an empty body, which every GET has.
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// AWS discovers peers from EC2 instance tags.
//
// It calls DescribeInstances directly rather than pulling in the EC2 service
// SDK: the request is one signed GET, the response is a small XML document,
// and the whole EC2 client would otherwise be the largest dependency in the
// binary by a wide margin.
type AWS struct {
	client httpDoer

	// credentials resolves the key used to sign requests.
	credentials aws.CredentialsProvider

	// signer signs the request with SigV4.
	signer *v4.Signer

	// region selects the EC2 endpoint.
	region string

	// endpoint overrides the derived EC2 endpoint, for tests and VPC
	// endpoints.
	endpoint string

	// filters are the EC2 filters applied to DescribeInstances, most often a
	// tag filter.
	filters map[string][]string

	// port is attached to instance addresses (the gossip port).
	port int

	// private selects the private IP over the public one.
	private bool

	// now is the clock, injectable for tests so signatures are reproducible.
	now func() time.Time
}

// AWSOption configures an AWS discoverer.
type AWSOption func(*AWS)

// WithAWSClient overrides the HTTP client.
func WithAWSClient(client httpDoer) AWSOption { return func(a *AWS) { a.client = client } }

// WithAWSEndpoint overrides the EC2 endpoint.
func WithAWSEndpoint(endpoint string) AWSOption {
	return func(a *AWS) { a.endpoint = strings.TrimSuffix(endpoint, "/") }
}

// WithAWSCredentials sets a fixed credentials provider.
func WithAWSCredentials(provider aws.CredentialsProvider) AWSOption {
	return func(a *AWS) { a.credentials = provider }
}

// WithAWSClock overrides the clock, for tests.
func WithAWSClock(now func() time.Time) AWSOption { return func(a *AWS) { a.now = now } }

// WithAWSPublicIP reads the public IPv4 address instead of the private one.
func WithAWSPublicIP() AWSOption { return func(a *AWS) { a.private = false } }

// NewAWS returns a Discoverer over EC2 instances matching filters. Filter keys
// are EC2 filter names, so a tag filter is `tag:Cluster`.
func NewAWS(region string, filters map[string][]string, port int, opts ...AWSOption) (*AWS, error) {
	a := AWS{
		region:  region,
		filters: filters,
		port:    port,
		private: true,
		signer:  v4.NewSigner(),
		now:     time.Now,
	}

	for _, opt := range opts {
		opt(&a)
	}

	if a.region == "" {
		a.region = firstNonEmpty(os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION"))
	}

	if a.region == "" {
		return nil, errors.New("aws discovery: region is not set and AWS_REGION is empty")
	}

	if len(a.filters) == 0 {
		return nil, errors.New("aws discovery: at least one filter is required")
	}

	if a.client == nil {
		a.client = newHTTPClient()
	}

	if a.credentials == nil {
		// The default chain covers every way an EC2 host or an ECS task is
		// given credentials: environment, shared config, IMDS, task role.
		cfg, cfgErr := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(a.region))
		if cfgErr != nil {
			return nil, fmt.Errorf("aws discovery: load credentials: %w", cfgErr)
		}

		a.credentials = cfg.Credentials
	}

	if a.endpoint == "" {
		a.endpoint = "https://ec2." + a.region + ".amazonaws.com"
	}

	return &a, nil
}

// Name implements Discoverer.
func (a *AWS) Name() string { return "aws" }

// ec2DescribeInstancesResponse is the subset of the EC2 query API response we
// read.
type ec2DescribeInstancesResponse struct {
	XMLName        xml.Name `xml:"DescribeInstancesResponse"`
	NextToken      string   `xml:"nextToken"`
	ReservationSet []struct {
		InstancesSet []struct {
			InstanceID       string `xml:"instanceId"`
			PrivateIPAddress string `xml:"privateIpAddress"`
			IPAddress        string `xml:"ipAddress"`
			PrivateDNSName   string `xml:"privateDnsName"`

			InstanceState struct {
				Name string `xml:"name"`
			} `xml:"instanceState"`

			TagSet []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"instancesSet>item"`
	} `xml:"reservationSet>item"`
}

// Discover implements Discoverer.
func (a *AWS) Discover(ctx context.Context) ([]Peer, error) {
	var (
		peers     []Peer
		nextToken string
	)

	// DescribeInstances paginates. A cluster is small, but an account's
	// instance list is not, and a filter that matches broadly must not
	// silently return only the first page.
	for page := 0; page < 20; page++ {
		resp, err := a.describeInstances(ctx, nextToken)
		if err != nil {
			return nil, err
		}

		for _, reservation := range resp.ReservationSet {
			for _, instance := range reservation.InstancesSet {
				if instance.InstanceState.Name != "running" {
					continue
				}

				host := instance.PrivateIPAddress
				if !a.private {
					host = instance.IPAddress
				}

				if host == "" {
					continue
				}

				meta := map[string]string{"instance_id": instance.InstanceID}
				for _, tag := range instance.TagSet {
					meta["tag."+tag.Key] = tag.Value
				}

				peers = append(peers, Peer{
					ID:     instance.InstanceID,
					Addr:   JoinHostPort(host, a.port),
					Meta:   meta,
					Source: "aws",
				})
			}
		}

		if resp.NextToken == "" {
			break
		}

		nextToken = resp.NextToken
	}

	return peers, nil
}

func (a *AWS) describeInstances(ctx context.Context, nextToken string) (*ec2DescribeInstancesResponse, error) {
	requestURL := a.endpoint + "/?" + a.describeInstancesQuery(nextToken).Encode()

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, http.NoBody)
	if reqErr != nil {
		return nil, fmt.Errorf("build EC2 request: %w", reqErr)
	}

	credentials, credErr := a.credentials.Retrieve(ctx)
	if credErr != nil {
		return nil, fmt.Errorf("retrieve AWS credentials: %w", credErr)
	}

	if err := a.signer.SignHTTP(ctx, credentials, req, emptyPayloadSHA256, "ec2", a.region, a.now().UTC()); err != nil {
		return nil, fmt.Errorf("sign EC2 request: %w", err)
	}

	resp, doErr := a.client.Do(req)
	if doErr != nil {
		return nil, fmt.Errorf("call EC2 DescribeInstances: %w", doErr)
	}

	defer closeResponse(resp)

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if readErr != nil {
		return nil, fmt.Errorf("read EC2 response: %w", readErr)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("call EC2 DescribeInstances: unexpected status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)),
		)
	}

	var decoded ec2DescribeInstancesResponse

	if err := xml.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("decode EC2 response: %w", err)
	}

	return &decoded, nil
}

// describeInstancesQuery builds the EC2 query API parameters.
//
// The API numbers filters from 1, and both the name and each value are separate
// parameters. Sorting keeps the encoding — and therefore the signature —
// reproducible.
func (a *AWS) describeInstancesQuery(nextToken string) url.Values {
	query := url.Values{}
	query.Set("Action", "DescribeInstances")
	query.Set("Version", ec2APIVersion)

	if nextToken != "" {
		query.Set("NextToken", nextToken)
	}

	names := make([]string, 0, len(a.filters))
	for name := range a.filters {
		names = append(names, name)
	}

	sort.Strings(names)

	for i, name := range names {
		prefix := fmt.Sprintf("Filter.%d.", i+1)
		query.Set(prefix+"Name", name)

		for j, value := range a.filters[name] {
			query.Set(fmt.Sprintf("%sValue.%d", prefix, j+1), value)
		}
	}

	return query
}

// Close implements Discoverer.
func (a *AWS) Close() error { return nil }

// newAWSFromSpec builds an EC2 discoverer.
//
// Anything that looks like an EC2 filter name is passed through, so an operator
// can write `tag:Cluster=plainq` or the more general
// `instance-state-name=running` without this package enumerating the EC2 filter
// vocabulary.
func newAWSFromSpec(spec *Spec) (Discoverer, error) {
	port, portErr := spec.OptionPort(defaultGossipPort)
	if portErr != nil {
		return nil, portErr
	}

	filters := map[string][]string{}

	for key, values := range spec.Options {
		if !strings.HasPrefix(key, "tag:") && !strings.Contains(key, "-") {
			continue
		}

		filters[key] = values
	}

	if tag := spec.Option("tag", ""); tag != "" {
		key, value, _ := strings.Cut(tag, "=")
		filters["tag:"+key] = []string{value}
	}

	opts := make([]AWSOption, 0, 2)

	if endpoint := spec.Option("endpoint", ""); endpoint != "" {
		opts = append(opts, WithAWSEndpoint(endpoint))
	}

	public, publicErr := spec.OptionBool("public", false)
	if publicErr != nil {
		return nil, publicErr
	}

	if public {
		opts = append(opts, WithAWSPublicIP())
	}

	return NewAWS(spec.Option("region", spec.Target), filters, port, opts...)
}
