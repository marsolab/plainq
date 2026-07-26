package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kubernetes service-account paths. A pod running with a mounted service
// account has all three, and their presence is how we detect in-cluster.
const (
	k8sTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // path, not a credential.
	k8sCACertPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// k8sTokenRefresh is how long a projected service-account token is trusted
// before it is read from disk again. Projected tokens rotate; a long-lived
// process that reads the file once will start getting 401s within the hour.
const k8sTokenRefresh = 5 * time.Minute

// Kubernetes discovers peers through the Kubernetes API.
//
// It reads Endpoints for a service when one is named — that is the crisp
// answer, because an endpoint is by definition a pod that passed its readiness
// probe — and falls back to listing pods by label selector otherwise, which is
// what a cluster forming for the first time needs (no pod is ready until the
// cluster is up, and no cluster comes up until pods find each other).
type Kubernetes struct {
	client httpDoer

	// apiServer is the base URL of the API server.
	apiServer string

	// namespace scopes every query.
	namespace string

	// service, when set, selects Endpoints lookup.
	service string

	// selector is the label selector for pod lookup.
	selector string

	// port is attached to pod IPs, which carry no port.
	port int

	// portName, when set, takes the port from the named container/endpoint
	// port instead of the fixed port above.
	portName string

	// tokenPath is re-read on an interval so rotated tokens are picked up.
	tokenPath string

	tokenMu      sync.Mutex
	token        string
	tokenExpires time.Time

	// now is the clock, injectable for tests.
	now func() time.Time
}

// KubernetesOption configures a Kubernetes discoverer.
type KubernetesOption func(*Kubernetes)

// WithKubernetesClient overrides the HTTP client.
func WithKubernetesClient(client httpDoer) KubernetesOption {
	return func(k *Kubernetes) { k.client = client }
}

// WithKubernetesAPIServer overrides the API server base URL.
func WithKubernetesAPIServer(addr string) KubernetesOption {
	return func(k *Kubernetes) { k.apiServer = strings.TrimSuffix(addr, "/") }
}

// WithKubernetesToken sets a fixed bearer token, bypassing the token file.
func WithKubernetesToken(token string) KubernetesOption {
	return func(k *Kubernetes) {
		k.tokenPath = ""
		k.token = token
		k.tokenExpires = time.Time{}
	}
}

// WithKubernetesTokenPath overrides where the service-account token is read.
func WithKubernetesTokenPath(path string) KubernetesOption {
	return func(k *Kubernetes) { k.tokenPath = path }
}

// WithKubernetesClock overrides the clock, for tests.
func WithKubernetesClock(now func() time.Time) KubernetesOption {
	return func(k *Kubernetes) { k.now = now }
}

// KubernetesConfig is the settable part of a Kubernetes discoverer.
type KubernetesConfig struct {
	// Namespace to search. Defaults to the pod's own namespace in-cluster.
	Namespace string

	// Service names a Service whose Endpoints list the peers.
	Service string

	// Selector is a label selector, used when Service is empty.
	Selector string

	// Port is attached to discovered pod IPs.
	Port int

	// PortName takes the port from a named port instead of Port.
	PortName string
}

// NewKubernetes returns a Discoverer backed by the Kubernetes API. Called
// inside a pod it configures itself from the mounted service account.
func NewKubernetes(cfg KubernetesConfig, opts ...KubernetesOption) (*Kubernetes, error) {
	k := Kubernetes{
		namespace: cfg.Namespace,
		service:   cfg.Service,
		selector:  cfg.Selector,
		port:      cfg.Port,
		portName:  cfg.PortName,
		tokenPath: k8sTokenPath,
		now:       time.Now,
	}

	for _, opt := range opts {
		opt(&k)
	}

	if k.apiServer == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" {
			return nil, errors.New("kubernetes discovery: not running in a cluster " +
				"(KUBERNETES_SERVICE_HOST unset) and no api-server option given",
			)
		}

		if port == "" {
			port = "443"
		}

		k.apiServer = "https://" + net.JoinHostPort(host, port)
	}

	if k.namespace == "" {
		k.namespace = readNamespace()
	}

	if k.namespace == "" {
		return nil, errors.New("kubernetes discovery: namespace is not set and could not be read from the service account")
	}

	if k.service == "" && k.selector == "" {
		return nil, errors.New("kubernetes discovery: one of service or selector must be set")
	}

	if k.client == nil {
		// Only an HTTPS API server needs the cluster CA. A plain-HTTP endpoint
		// is a local kubectl proxy or a test server, and demanding a CA file
		// for it would fail on a machine that has no service account mounted.
		if strings.HasPrefix(k.apiServer, "https://") {
			client, clientErr := newKubernetesHTTPClient()
			if clientErr != nil {
				return nil, clientErr
			}

			k.client = client
		} else {
			k.client = newHTTPClient()
		}
	}

	return &k, nil
}

// Name implements Discoverer.
func (k *Kubernetes) Name() string { return "kubernetes" }

// Discover implements Discoverer.
func (k *Kubernetes) Discover(ctx context.Context) ([]Peer, error) {
	if k.service != "" {
		peers, err := k.discoverEndpoints(ctx)
		if err != nil {
			return nil, err
		}

		// A service with no ready endpoints is exactly the bootstrap case, so
		// fall through to the pod listing rather than reporting an empty
		// cluster to a node that is trying to form one.
		if len(peers) > 0 || k.selector == "" {
			return peers, nil
		}
	}

	return k.discoverPods(ctx)
}

// Close implements Discoverer.
func (k *Kubernetes) Close() error { return nil }

// k8sEndpoints is the subset of core/v1 Endpoints we read.
type k8sEndpoints struct {
	Subsets []struct {
		Addresses []struct {
			IP        string `json:"ip"`
			Hostname  string `json:"hostname"`
			NodeName  string `json:"nodeName"`
			TargetRef struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"targetRef"`
		} `json:"addresses"`

		NotReadyAddresses []struct {
			IP        string `json:"ip"`
			Hostname  string `json:"hostname"`
			TargetRef struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"targetRef"`
		} `json:"notReadyAddresses"`

		Ports []struct {
			Name string `json:"name"`
			Port int    `json:"port"`
		} `json:"ports"`
	} `json:"subsets"`
}

func (k *Kubernetes) discoverEndpoints(ctx context.Context) ([]Peer, error) {
	endpointURL := fmt.Sprintf("%s/api/v1/namespaces/%s/endpoints/%s",
		k.apiServer, url.PathEscape(k.namespace), url.PathEscape(k.service),
	)

	headers, headerErr := k.headers()
	if headerErr != nil {
		return nil, headerErr
	}

	var endpoints k8sEndpoints

	if err := getJSON(ctx, k.client, endpointURL, headers, &endpoints); err != nil {
		// A Service that does not exist yet is not a discovery failure — it is
		// a deployment that has not finished applying.
		if strings.Contains(err.Error(), "unexpected status 404") {
			return nil, nil
		}

		return nil, fmt.Errorf("list endpoints of service %q: %w", k.service, err)
	}

	var peers []Peer

	for _, subset := range endpoints.Subsets {
		port := k.port

		for _, p := range subset.Ports {
			if k.portName != "" && p.Name == k.portName {
				port = p.Port

				break
			}
		}

		// Not-ready addresses count. A PlainQ pod is not ready until it has
		// joined a cluster, and it cannot join a cluster it cannot see.
		for _, addr := range subset.Addresses {
			peers = append(peers, Peer{
				ID:     addr.TargetRef.Name,
				Addr:   net.JoinHostPort(addr.IP, strconv.Itoa(port)),
				Meta:   map[string]string{"namespace": k.namespace, "service": k.service, "ready": "true"},
				Source: "kubernetes",
			})
		}

		for _, addr := range subset.NotReadyAddresses {
			peers = append(peers, Peer{
				ID:     addr.TargetRef.Name,
				Addr:   net.JoinHostPort(addr.IP, strconv.Itoa(port)),
				Meta:   map[string]string{"namespace": k.namespace, "service": k.service, "ready": "false"},
				Source: "kubernetes",
			})
		}
	}

	return peers, nil
}

// k8sPodList is the subset of core/v1 PodList we read.
type k8sPodList struct {
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`

		Spec struct {
			Containers []struct {
				Ports []struct {
					Name          string `json:"name"`
					ContainerPort int    `json:"containerPort"`
				} `json:"ports"`
			} `json:"containers"`
		} `json:"spec"`

		Status struct {
			Phase string `json:"phase"`
			PodIP string `json:"podIP"`
		} `json:"status"`
	} `json:"items"`
}

func (k *Kubernetes) discoverPods(ctx context.Context) ([]Peer, error) {
	query := url.Values{}
	if k.selector != "" {
		query.Set("labelSelector", k.selector)
	}

	podURL := fmt.Sprintf("%s/api/v1/namespaces/%s/pods?%s",
		k.apiServer, url.PathEscape(k.namespace), query.Encode(),
	)

	headers, headerErr := k.headers()
	if headerErr != nil {
		return nil, headerErr
	}

	var pods k8sPodList

	if err := getJSON(ctx, k.client, podURL, headers, &pods); err != nil {
		return nil, fmt.Errorf("list pods with selector %q: %w", k.selector, err)
	}

	peers := make([]Peer, 0, len(pods.Items))

	for _, pod := range pods.Items {
		// A pod without an IP has not been scheduled onto a node yet, and a
		// terminal pod is never coming back. Neither is a peer.
		if pod.Status.PodIP == "" || pod.Status.Phase == "Succeeded" || pod.Status.Phase == "Failed" {
			continue
		}

		port := k.port

		if k.portName != "" {
			for _, container := range pod.Spec.Containers {
				for _, p := range container.Ports {
					if p.Name == k.portName {
						port = p.ContainerPort
					}
				}
			}
		}

		meta := map[string]string{"namespace": k.namespace, "phase": pod.Status.Phase}
		for key, value := range pod.Metadata.Labels {
			meta["label."+key] = value
		}

		peers = append(peers, Peer{
			ID:     pod.Metadata.Name,
			Addr:   net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(port)),
			Meta:   meta,
			Source: "kubernetes",
		})
	}

	return peers, nil
}

// headers builds the request headers, refreshing the service-account token
// when the cached copy is old enough that a rotation could have happened.
func (k *Kubernetes) headers() (map[string]string, error) {
	k.tokenMu.Lock()
	defer k.tokenMu.Unlock()

	if k.tokenPath != "" && (k.token == "" || k.now().After(k.tokenExpires)) {
		raw, err := os.ReadFile(k.tokenPath)
		if err != nil {
			return nil, fmt.Errorf("read kubernetes service account token: %w", err)
		}

		k.token = strings.TrimSpace(string(raw))
		k.tokenExpires = k.now().Add(k8sTokenRefresh)
	}

	if k.token == "" {
		return nil, errors.New("kubernetes discovery: no service account token available")
	}

	return map[string]string{"Authorization": "Bearer " + k.token}, nil
}

func readNamespace() string {
	raw, err := os.ReadFile(k8sNamespacePath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(raw))
}

// newKubernetesHTTPClient trusts the cluster CA and nothing else. Falling back
// to the system pool would let any publicly trusted certificate impersonate
// the API server, so a missing CA file is an error rather than a downgrade.
func newKubernetesHTTPClient() (*http.Client, error) {
	pem, err := os.ReadFile(filepath.Clean(k8sCACertPath))
	if err != nil {
		return nil, fmt.Errorf("read kubernetes CA certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("kubernetes discovery: CA certificate file holds no usable certificate")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck,forcetypeassert // stdlib invariant.
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	return &http.Client{Timeout: defaultHTTPTimeout, Transport: transport}, nil
}

func init() {
	Register("kubernetes", newKubernetesFromSpec)
	Register("k8s", newKubernetesFromSpec)
}

// newKubernetesFromSpec accepts both `kubernetes://namespace/service` and the
// all-options form, because the first is what people type and the second is
// what a Helm chart generates.
func newKubernetesFromSpec(spec *Spec) (Discoverer, error) {
	port, portErr := spec.OptionPort(defaultGossipPort)
	if portErr != nil {
		return nil, portErr
	}

	cfg := KubernetesConfig{
		Namespace: spec.Option("namespace", ""),
		Service:   spec.Option("service", ""),
		Selector:  spec.Option("selector", ""),
		Port:      port,
		PortName:  spec.Option("port-name", ""),
	}

	if spec.Target != "" {
		namespace, service, _ := strings.Cut(spec.Target, "/")
		if cfg.Namespace == "" {
			cfg.Namespace = namespace
		}

		if cfg.Service == "" {
			cfg.Service = service
		}
	}

	opts := make([]KubernetesOption, 0, 2)

	if apiServer := spec.Option("api-server", ""); apiServer != "" {
		opts = append(opts, WithKubernetesAPIServer(apiServer))
	}

	if tokenPath := spec.Option("token-file", ""); tokenPath != "" {
		opts = append(opts, WithKubernetesTokenPath(tokenPath))
	}

	return NewKubernetes(cfg, opts...)
}
