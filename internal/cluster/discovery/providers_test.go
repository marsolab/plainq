package discovery

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/maxatome/go-testdeep/td"
)

// fixedTime is the clock every provider test runs against, so a signature or a
// token lifetime is reproducible rather than dependent on when the suite ran.
var fixedTime = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

// --- DNS -------------------------------------------------------------------

// stubResolver answers lookups from a script.
type stubResolver struct {
	hosts map[string][]string
	srv   map[string][]*net.SRV
	err   error
}

func (s *stubResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}

	addrs, ok := s.hosts[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return addrs, nil
}

func (s *stubResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	if s.err != nil {
		return "", nil, s.err
	}

	key := name
	if service != "" {
		key = "_" + service + "._" + proto + "." + name
	}

	records, ok := s.srv[key]
	if !ok {
		return "", nil, &net.DNSError{Err: "no such host", Name: key, IsNotFound: true}
	}

	return key, records, nil
}

func TestDNSDiscovery(t *testing.T) {
	resolver := &stubResolver{hosts: map[string][]string{
		"plainq.internal": {"10.0.0.1", "10.0.0.2"},
	}}

	discoverer := NewDNS("plainq.internal", 8082, WithDNSResolver(resolver))

	peers, err := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(err)

	td.Cmp(t, Addrs(peers), []string{"10.0.0.1:8082", "10.0.0.2:8082"})
	td.Cmp(t, discoverer.Name(), "dns")
}

// A headless service with no endpoints yet is the normal state of a
// StatefulSet mid-rollout. Reporting it as a failure would have every node log
// an error while the cluster is simply starting.
func TestDNSDiscoveryTreatsMissingRecordAsEmpty(t *testing.T) {
	discoverer := NewDNS("plainq.internal", 8082, WithDNSResolver(&stubResolver{}))

	peers, err := discoverer.Discover(context.Background())

	td.CmpNoError(t, err)
	td.Cmp(t, peers, td.Len(0))
}

func TestDNSSRVDiscovery(t *testing.T) {
	resolver := &stubResolver{srv: map[string][]*net.SRV{
		"_plainq._tcp.example.com": {
			{Target: "node-1.example.com.", Port: 9001},
			{Target: "node-2.example.com.", Port: 9002},
			// A record advertising no port falls back to the configured one.
			{Target: "node-3.example.com.", Port: 0},
		},
	}}

	discoverer := NewDNSSRV("_plainq._tcp.example.com", 8082, WithDNSResolver(resolver))

	peers, err := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(err)

	td.Cmp(t, Addrs(peers), []string{
		"node-1.example.com:9001",
		"node-2.example.com:9002",
		"node-3.example.com:8082",
	})
}

func TestSplitSRVName(t *testing.T) {
	service, proto, domain := splitSRVName("_plainq._tcp.example.com")
	td.Cmp(t, []string{service, proto, domain}, []string{"plainq", "tcp", "example.com"})

	service, proto, domain = splitSRVName("plainq.example.com")
	td.Cmp(t, []string{service, proto, domain}, []string{"", "", "plainq.example.com"})
}

// --- Kubernetes ------------------------------------------------------------

func TestKubernetesDiscoveryFromEndpoints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		td.Cmp(t, r.URL.Path, "/api/v1/namespaces/prod/endpoints/plainq")
		td.Cmp(t, r.Header.Get("Authorization"), "Bearer test-token")

		_, _ = w.Write([]byte(`{
			"subsets": [{
				"addresses": [
					{"ip": "10.1.0.1", "targetRef": {"name": "plainq-0", "kind": "Pod"}},
					{"ip": "10.1.0.2", "targetRef": {"name": "plainq-1", "kind": "Pod"}}
				],
				"notReadyAddresses": [
					{"ip": "10.1.0.3", "targetRef": {"name": "plainq-2", "kind": "Pod"}}
				],
				"ports": [{"name": "cluster", "port": 8082}]
			}]
		}`))
	}))
	defer server.Close()

	discoverer, err := NewKubernetes(
		KubernetesConfig{Namespace: "prod", Service: "plainq", Port: 8082, PortName: "cluster"},
		WithKubernetesAPIServer(server.URL),
		WithKubernetesToken("test-token"),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	// Not-ready endpoints are peers too: a PlainQ pod is not ready until it
	// has joined a cluster, and it cannot join one it cannot see.
	td.Cmp(t, Addrs(peers), []string{"10.1.0.1:8082", "10.1.0.2:8082", "10.1.0.3:8082"})
	td.Cmp(t, peers[0].ID, "plainq-0")
	td.Cmp(t, peers[2].Meta["ready"], "false")
}

// A service with no endpoints is exactly the bootstrap case, so the provider
// falls through to a pod listing rather than reporting an empty cluster.
func TestKubernetesDiscoveryFallsBackToPods(t *testing.T) {
	var podsCalled bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/prod/endpoints/plainq":
			_, _ = w.Write([]byte(`{"subsets": []}`))

		case "/api/v1/namespaces/prod/pods":
			podsCalled = true

			td.Cmp(t, r.URL.Query().Get("labelSelector"), "app=plainq")

			_, _ = w.Write([]byte(`{
				"items": [
					{
						"metadata": {"name": "plainq-0", "labels": {"app": "plainq"}},
						"status": {"phase": "Running", "podIP": "10.1.0.1"}
					},
					{
						"metadata": {"name": "plainq-1", "labels": {"app": "plainq"}},
						"status": {"phase": "Pending", "podIP": ""}
					},
					{
						"metadata": {"name": "plainq-old", "labels": {"app": "plainq"}},
						"status": {"phase": "Failed", "podIP": "10.1.0.9"}
					}
				]
			}`))

		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	discoverer, err := NewKubernetes(
		KubernetesConfig{Namespace: "prod", Service: "plainq", Selector: "app=plainq", Port: 8082},
		WithKubernetesAPIServer(server.URL),
		WithKubernetesToken("test-token"),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, podsCalled, true, "an empty endpoint list falls through to pods")
	td.Cmp(t, Addrs(peers), []string{"10.1.0.1:8082"},
		"an unscheduled pod has no address and a failed one is not coming back",
	)
	td.Cmp(t, peers[0].Meta["label.app"], "plainq")
}

// Projected service-account tokens rotate. A process that reads the file once
// starts collecting 401s within the hour.
func TestKubernetesRefreshesItsToken(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	td.Require(t).CmpNoError(os.WriteFile(tokenPath, []byte("first-token\n"), 0o600))

	var seen []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))

		_, _ = w.Write([]byte(`{"subsets": []}`))
	}))
	defer server.Close()

	now := fixedTime

	discoverer, err := NewKubernetes(
		KubernetesConfig{Namespace: "prod", Service: "plainq", Port: 8082},
		WithKubernetesAPIServer(server.URL),
		WithKubernetesTokenPath(tokenPath),
		WithKubernetesClock(func() time.Time { return now }),
	)
	td.Require(t).CmpNoError(err)

	_, _ = discoverer.Discover(context.Background())

	td.Require(t).CmpNoError(os.WriteFile(tokenPath, []byte("second-token"), 0o600))

	// Within the refresh window the cached token is reused.
	now = fixedTime.Add(time.Minute)
	_, _ = discoverer.Discover(context.Background())

	// Past it, the file is read again.
	now = fixedTime.Add(10 * time.Minute)
	_, _ = discoverer.Discover(context.Background())

	td.Cmp(t, seen, []string{
		"Bearer first-token",
		"Bearer first-token",
		"Bearer second-token",
	})
}

func TestKubernetesRequiresServiceOrSelector(t *testing.T) {
	_, err := NewKubernetes(
		KubernetesConfig{Namespace: "prod", Port: 8082},
		WithKubernetesAPIServer("http://127.0.0.1:1"),
		WithKubernetesToken("t"),
	)

	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("service or selector"))
}

func TestKubernetesSpecParsing(t *testing.T) {
	spec, err := ParseSpec("kubernetes://prod/plainq?port=9000&api-server=http://127.0.0.1:1&token-file=/dev/null")
	td.Require(t).CmpNoError(err)

	discoverer, buildErr := newKubernetesFromSpec(spec)
	td.Require(t).CmpNoError(buildErr)

	k8s, ok := discoverer.(*Kubernetes)
	td.Require(t).Cmp(ok, true)

	td.Cmp(t, k8s.namespace, "prod")
	td.Cmp(t, k8s.service, "plainq")
	td.Cmp(t, k8s.port, 9000)
}

// --- Docker ----------------------------------------------------------------

func TestDockerDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		td.Cmp(t, r.URL.Path, "/"+dockerAPIVersion+"/containers/json")

		var filters map[string][]string

		td.Require(t).CmpNoError(json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters))
		td.Cmp(t, filters["status"], []string{"running"})
		td.Cmp(t, filters["label"], []string{"plainq.cluster=prod"})

		_, _ = w.Write([]byte(`[
			{
				"Id": "abcdef0123456789",
				"Names": ["/plainq-1"],
				"State": "running",
				"Labels": {"plainq.cluster": "prod"},
				"NetworkSettings": {"Networks": {"plainq": {"IPAddress": "172.20.0.2"}}}
			},
			{
				"Id": "fedcba9876543210",
				"Names": ["/plainq-2"],
				"State": "running",
				"Labels": {"plainq.cluster": "prod"},
				"NetworkSettings": {"Networks": {"plainq": {"IPAddress": "172.20.0.3"}}}
			}
		]`))
	}))
	defer server.Close()

	discoverer, err := NewDocker(
		map[string]string{"plainq.cluster": "prod"}, 8082,
		WithDockerHost(server.URL),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"172.20.0.2:8082", "172.20.0.3:8082"})
	td.Cmp(t, peers[0].ID, "abcdef012345")
	td.Cmp(t, peers[0].Meta["container_name"], "plainq-1")
}

// A container on several networks must resolve to the same address every time,
// or repeated discovery flaps the peer list.
func TestDockerPicksNetworkDeterministically(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{
			"Id": "abcdef0123456789",
			"State": "running",
			"NetworkSettings": {"Networks": {
				"zeta": {"IPAddress": "172.30.0.2"},
				"alpha": {"IPAddress": "172.20.0.2"}
			}}
		}]`))
	}))
	defer server.Close()

	discoverer, err := NewDocker(map[string]string{"plainq.cluster": "prod"}, 8082, WithDockerHost(server.URL))
	td.Require(t).CmpNoError(err)

	for range 5 {
		peers, discoverErr := discoverer.Discover(context.Background())
		td.Require(t).CmpNoError(discoverErr)
		td.Cmp(t, Addrs(peers), []string{"172.20.0.2:8082"}, "the alphabetically first network wins, every time")
	}
}

func TestDockerRequiresALabel(t *testing.T) {
	_, err := NewDocker(nil, 8082)
	td.CmpError(t, err)
}

// --- AWS -------------------------------------------------------------------

func TestAWSDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		td.Cmp(t, query.Get("Action"), "DescribeInstances")
		td.Cmp(t, query.Get("Filter.1.Name"), "tag:Cluster")
		td.Cmp(t, query.Get("Filter.1.Value.1"), "plainq")
		td.Cmp(t, r.Header.Get("Authorization"), td.Contains("AWS4-HMAC-SHA256"),
			"the request is signed, so a real EC2 endpoint would accept it",
		)

		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
		<DescribeInstancesResponse>
			<reservationSet>
				<item>
					<instancesSet>
						<item>
							<instanceId>i-0001</instanceId>
							<privateIpAddress>10.2.0.1</privateIpAddress>
							<ipAddress>54.1.1.1</ipAddress>
							<instanceState><name>running</name></instanceState>
							<tagSet><item><key>Cluster</key><value>plainq</value></item></tagSet>
						</item>
						<item>
							<instanceId>i-0002</instanceId>
							<privateIpAddress>10.2.0.2</privateIpAddress>
							<instanceState><name>terminated</name></instanceState>
						</item>
					</instancesSet>
				</item>
			</reservationSet>
		</DescribeInstancesResponse>`))
	}))
	defer server.Close()

	discoverer, err := NewAWS(
		"eu-west-1", map[string][]string{"tag:Cluster": {"plainq"}}, 8082,
		WithAWSEndpoint(server.URL),
		WithAWSCredentials(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		WithAWSClock(func() time.Time { return fixedTime }),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"10.2.0.1:8082"}, "a terminated instance is not a peer")
	td.Cmp(t, peers[0].ID, "i-0001")
	td.Cmp(t, peers[0].Meta["tag.Cluster"], "plainq")
}

func TestAWSDiscoveryPublicIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<DescribeInstancesResponse><reservationSet><item><instancesSet><item>
			<instanceId>i-0001</instanceId>
			<privateIpAddress>10.2.0.1</privateIpAddress>
			<ipAddress>54.1.1.1</ipAddress>
			<instanceState><name>running</name></instanceState>
		</item></instancesSet></item></reservationSet></DescribeInstancesResponse>`))
	}))
	defer server.Close()

	discoverer, err := NewAWS(
		"eu-west-1", map[string][]string{"tag:Cluster": {"plainq"}}, 8082,
		WithAWSEndpoint(server.URL),
		WithAWSCredentials(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		WithAWSClock(func() time.Time { return fixedTime }),
		WithAWSPublicIP(),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"54.1.1.1:8082"})
}

func TestAWSRequiresRegionAndFilters(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	_, err := NewAWS("", map[string][]string{"tag:Cluster": {"plainq"}}, 8082,
		WithAWSCredentials(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
	)
	td.CmpError(t, err)

	_, err = NewAWS("eu-west-1", nil, 8082,
		WithAWSCredentials(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
	)
	td.CmpError(t, err)
}

// Compilation time check that the SDK's static provider still satisfies what
// the discoverer asks for.
var _ aws.CredentialsProvider = credentials.NewStaticCredentialsProvider("", "", "")

// --- GCP -------------------------------------------------------------------

func TestGCPDiscovery(t *testing.T) {
	var tokenCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/instance/service-accounts/default/token":
			tokenCalls++

			td.Cmp(t, r.Header.Get("Metadata-Flavor"), "Google")

			_, _ = w.Write([]byte(`{"access_token": "gcp-token", "expires_in": 3600}`))

		case "/projects/plainq-prod/zones/europe-west1-b/instances":
			td.Cmp(t, r.Header.Get("Authorization"), "Bearer gcp-token")
			td.Cmp(t, r.URL.Query().Get("filter"), "labels.cluster=plainq")

			_, _ = w.Write([]byte(`{"items": [
				{
					"name": "plainq-1",
					"status": "RUNNING",
					"zone": "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west1-b",
					"labels": {"cluster": "plainq"},
					"networkInterfaces": [{"networkIP": "10.3.0.1", "accessConfigs": [{"natIP": "35.1.1.1"}]}]
				},
				{
					"name": "plainq-2",
					"status": "TERMINATED",
					"networkInterfaces": [{"networkIP": "10.3.0.2"}]
				}
			]}`))

		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	discoverer, err := NewGCP(
		"plainq-prod", []string{"europe-west1-b"}, "labels.cluster=plainq", 8082,
		WithGCPAPIBase(server.URL),
		WithGCPMetadataBase(server.URL),
		WithGCPClock(func() time.Time { return fixedTime }),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"10.3.0.1:8082"}, "a terminated instance is not a peer")
	td.Cmp(t, peers[0].Meta["zone"], "europe-west1-b")

	// The token is cached until it nears expiry, so discovery on an interval
	// does not hammer the metadata server.
	_, _ = discoverer.Discover(context.Background())
	td.Cmp(t, tokenCalls, 1)
}

func TestGCPAggregatedDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/projects/plainq-prod/aggregated/instances" {
			_, _ = w.Write([]byte(`{"items": {
				"zones/europe-west1-b": {"instances": [
					{"name": "plainq-1", "status": "RUNNING",
					 "networkInterfaces": [{"networkIP": "10.3.0.1"}]}
				]}
			}}`))

			return
		}

		_, _ = w.Write([]byte(`{"access_token": "gcp-token", "expires_in": 3600}`))
	}))
	defer server.Close()

	discoverer, err := NewGCP(
		"plainq-prod", nil, "labels.cluster=plainq", 8082,
		WithGCPAPIBase(server.URL),
		WithGCPMetadataBase(server.URL),
		WithGCPClock(func() time.Time { return fixedTime }),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"10.3.0.1:8082"})
}

func TestGCPSpecShorthand(t *testing.T) {
	spec, err := ParseSpec("gcp://?project=p&label=cluster%3Dplainq&api-base=http://127.0.0.1:1&metadata-base=http://127.0.0.1:1")
	td.Require(t).CmpNoError(err)

	discoverer, buildErr := newGCPFromSpec(spec)
	td.Require(t).CmpNoError(buildErr)

	gcp, ok := discoverer.(*GCP)
	td.Require(t).Cmp(ok, true)

	td.Cmp(t, gcp.filter, "labels.cluster=plainq", "the label shorthand becomes a GCE filter")
}

// --- Azure -----------------------------------------------------------------

func TestAzureDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/oauth2/token" {
			td.Cmp(t, r.Header.Get("Metadata"), "true")

			_, _ = w.Write([]byte(`{"access_token": "azure-token", "expires_in": "3600"}`))

			return
		}

		td.Cmp(t, r.Header.Get("Authorization"), "Bearer azure-token")

		var body struct {
			Subscriptions []string `json:"subscriptions"`
			Query         string   `json:"query"`
		}

		td.Require(t).CmpNoError(json.NewDecoder(r.Body).Decode(&body))
		td.Cmp(t, body.Subscriptions, []string{"sub-1"})
		td.Cmp(t, body.Query, td.Contains("tags['cluster'] =~ 'plainq'"))

		_, _ = w.Write([]byte(`{"count": 2, "data": [
			{"name": "plainq-1", "id": "/subscriptions/sub-1/vm1", "address": "10.4.0.1",
			 "tags": {"cluster": "plainq"}},
			{"name": "plainq-2", "id": "/subscriptions/sub-1/vm2", "address": "10.4.0.2",
			 "tags": {"cluster": "plainq"}}
		]}`))
	}))
	defer server.Close()

	discoverer, err := NewAzure(
		[]string{"sub-1"}, "cluster", "plainq", 8082,
		WithAzureManagementBase(server.URL),
		WithAzureIMDSBase(server.URL),
		WithAzureClock(func() time.Time { return fixedTime }),
	)
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"10.4.0.1:8082", "10.4.0.2:8082"})
	td.Cmp(t, peers[0].ID, "plainq-1")
	td.Cmp(t, peers[0].Meta["tag.cluster"], "plainq")
}

// A tag value is interpolated into a KQL literal, so it has to be escaped —
// otherwise a quote in a tag rewrites the query.
func TestAzureEscapesKQL(t *testing.T) {
	td.Cmp(t, escapeKQL(`pl'ainq`), `pl\'ainq`)
	td.Cmp(t, escapeKQL(`a\b`), `a\\b`)
}

func TestAzureRequiresATag(t *testing.T) {
	_, err := NewAzure([]string{"sub-1"}, "", "", 8082,
		WithAzureManagementBase("http://127.0.0.1:1"),
		WithAzureIMDSBase("http://127.0.0.1:1"),
	)
	td.CmpError(t, err)
}

// --- Consul ----------------------------------------------------------------

func TestConsulDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		td.Cmp(t, r.URL.Path, "/v1/health/service/plainq")
		td.Cmp(t, r.URL.Query().Get("passing"), "true")
		td.Cmp(t, r.Header.Get("X-Consul-Token"), "secret-token")

		_, _ = w.Write([]byte(`[
			{
				"Node": {"Node": "node-a", "Address": "10.5.0.1"},
				"Service": {"ID": "plainq-a", "Service": "plainq", "Address": "", "Port": 8082,
				            "Tags": ["cluster"], "Meta": {"zone": "a"}}
			},
			{
				"Node": {"Node": "node-b", "Address": "10.5.0.2"},
				"Service": {"ID": "plainq-b", "Service": "plainq", "Address": "10.5.0.99", "Port": 8082}
			}
		]`))
	}))
	defer server.Close()

	discoverer, err := NewConsul(server.URL, "plainq", WithConsulToken("secret-token"))
	td.Require(t).CmpNoError(err)

	peers, discoverErr := discoverer.Discover(context.Background())
	td.Require(t).CmpNoError(discoverErr)

	td.Cmp(t, Addrs(peers), []string{"10.5.0.1:8082", "10.5.0.99:8082"},
		"a service address overrides the node address, as Consul's own resolution does",
	)
	td.Cmp(t, peers[0].Meta["meta.zone"], "a")
	td.Cmp(t, peers[0].Meta["tags"], "cluster")
}

func TestConsulSpecParsing(t *testing.T) {
	spec, err := ParseSpec("consul://127.0.0.1:8500/plainq?tag=prod&dc=dc1")
	td.Require(t).CmpNoError(err)

	discoverer, buildErr := Parse(spec.Raw)
	td.Require(t).CmpNoError(buildErr)

	consul, ok := discoverer.(*Consul)
	td.Require(t).Cmp(ok, true)

	td.Cmp(t, consul.address, "http://127.0.0.1:8500")
	td.Cmp(t, consul.service, "plainq")
	td.Cmp(t, consul.tag, "prod")
	td.Cmp(t, consul.datacenter, "dc1")
}

func TestConsulRequiresAService(t *testing.T) {
	_, err := NewConsul("http://127.0.0.1:8500", "")
	td.CmpError(t, err)
}

// --- Shared HTTP behaviour -------------------------------------------------

// A provider error must name the endpoint and carry the body, because the
// body is where the cloud says which permission is missing.
func TestProviderErrorsCarryTheProviderMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message": "pods is forbidden: missing RBAC rule"}`))
	}))
	defer server.Close()

	discoverer, err := NewKubernetes(
		KubernetesConfig{Namespace: "prod", Selector: "app=plainq", Port: 8082},
		WithKubernetesAPIServer(server.URL),
		WithKubernetesToken("t"),
	)
	td.Require(t).CmpNoError(err)

	_, discoverErr := discoverer.Discover(context.Background())

	td.Require(t).CmpError(discoverErr)
	td.Cmp(t, discoverErr.Error(), td.Contains("missing RBAC rule"))
	td.Cmp(t, discoverErr.Error(), td.Contains("403"))
}

// Query strings carry infrastructure detail — selectors, tags, subscription
// ids — that has no business in a shared log stream.
func TestRedactURL(t *testing.T) {
	td.Cmp(t, redactURL("https://api/pods?labelSelector=app%3Dsecret"), "https://api/pods?…")
	td.Cmp(t, redactURL("https://api/pods"), "https://api/pods")
}
