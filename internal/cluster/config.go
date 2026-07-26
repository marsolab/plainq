// Package cluster turns a PlainQ server into one node of several.
//
// Three things have to happen for that, and they happen in this order:
// discovery finds the other nodes, gossip keeps track of which of them are
// alive, and consensus decides what the queue's state actually is. Everything
// in this package is in service of those three, plus the reconciliation that
// keeps the second and third in agreement.
package cluster

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marsolab/plainq/internal/cluster/gossip"
)

// Defaults for a cluster node. The ports sit just above the queue's own
// (8080 gRPC, 8081 HTTP) so a full PlainQ node occupies one contiguous range.
const (
	// DefaultBindAddr is the cluster port: consensus and peer RPC, muxed.
	DefaultBindAddr = ":8082"

	// DefaultGossipAddr is the membership port (TCP and UDP).
	DefaultGossipAddr = ":8083"

	// DefaultDiscoveryInterval is how often peers are re-discovered.
	DefaultDiscoveryInterval = 15 * time.Second

	// DefaultReconcileInterval is how often the leader compares the gossip
	// view against the consensus configuration.
	DefaultReconcileInterval = 30 * time.Second

	// DefaultRemoveTimeout is how long a member must be gone before the leader
	// removes it from the configuration. It is deliberately long: removing a
	// voter shrinks quorum, and doing that in response to a network blip is
	// how a cluster talks itself into unavailability.
	DefaultRemoveTimeout = 5 * time.Minute

	// DefaultSweepInterval is how often the leader proposes eviction.
	DefaultSweepInterval = 5 * time.Minute
)

// Config configures a cluster node.
type Config struct {
	// Enabled turns clustering on. With it off, nothing in this package runs
	// and the server behaves exactly as a single node always has.
	Enabled bool

	// NodeID is this node's stable cluster identity. It must be unique in the
	// cluster and must survive restarts — the consensus log is keyed on it.
	// Empty defaults to the hostname.
	NodeID string

	// BindAddr is the local address for consensus and peer RPC.
	BindAddr string

	// AdvertiseAddr is the cluster address peers are told to dial. It is
	// required whenever BindAddr is unspecified (0.0.0.0), which is the
	// common case in a container.
	AdvertiseAddr string

	// GossipAddr and GossipAdvertiseAddr are the membership port's equivalents.
	GossipAddr          string
	GossipAdvertiseAddr string

	// GossipSecret encrypts and authenticates gossip. Base64 of a 16, 24 or
	// 32 byte key.
	GossipSecret string

	// GossipProfile selects the failure-detector timing: "lan", "wan" or
	// "local".
	GossipProfile string

	// Secret authenticates internal peer RPC.
	Secret string

	// DataDir holds the consensus log and snapshots. Empty derives it from
	// the storage path.
	DataDir string

	// Discovery holds the discovery specs used to find peers.
	Discovery []string

	// DiscoveryInterval is how often discovery runs.
	DiscoveryInterval time.Duration

	// Bootstrap forms a single-node cluster immediately. Use it for the first
	// node of a hand-built cluster, and never on more than one node.
	Bootstrap bool

	// BootstrapExpect waits for this many nodes to be visible and then forms a
	// cluster containing all of them. This is the safe way to start a cluster
	// from nothing: every node can be given the same configuration, and only
	// one of them — the lowest id — actually bootstraps.
	BootstrapExpect int

	// NonVoter joins the cluster as a replica that does not vote.
	NonVoter bool

	// Consistency decides where reads are answered: "local" or "strong".
	Consistency ConsistencyMode

	// ReconcileInterval is how often the leader reconciles gossip against the
	// consensus configuration.
	ReconcileInterval time.Duration

	// RemoveTimeout is how long a member must be absent before the leader
	// removes it.
	RemoveTimeout time.Duration

	// AutoRemove lets the leader remove failed members on its own. It is off
	// by default: shrinking a cluster is a decision with quorum consequences,
	// and an operator may prefer to make it.
	AutoRemove bool

	// SweepInterval is how often the leader proposes queue eviction.
	SweepInterval time.Duration

	// Consensus tuning. Zero means the engine's default.
	HeartbeatTimeout   time.Duration
	ElectionTimeout    time.Duration
	LeaderLeaseTimeout time.Duration
	CommitTimeout      time.Duration
	SnapshotInterval   time.Duration
	SnapshotThreshold  uint64
	TrailingLogs       uint64

	// ApplyTimeout bounds one replicated write.
	ApplyTimeout time.Duration

	// TLSCertFile, TLSKeyFile and TLSCAFile encrypt cluster traffic. All three
	// are needed for mutual authentication between nodes.
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string

	// Version is the build identifier this node gossips about itself.
	Version string
}

// Normalize fills in defaults. It is called before Validate.
//
//nolint:cyclop // Defaulting a config is a flat sequence of independent checks.
func (c *Config) Normalize() error {
	if c.NodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("derive cluster node id from hostname: %w", err)
		}

		c.NodeID = hostname
	}

	if c.BindAddr == "" {
		c.BindAddr = DefaultBindAddr
	}

	if c.GossipAddr == "" {
		c.GossipAddr = DefaultGossipAddr
	}

	if c.DiscoveryInterval <= 0 {
		c.DiscoveryInterval = DefaultDiscoveryInterval
	}

	if c.ReconcileInterval <= 0 {
		c.ReconcileInterval = DefaultReconcileInterval
	}

	if c.RemoveTimeout <= 0 {
		c.RemoveTimeout = DefaultRemoveTimeout
	}

	if c.SweepInterval <= 0 {
		c.SweepInterval = DefaultSweepInterval
	}

	if c.Consistency == "" {
		c.Consistency = ConsistencyLocal
	}

	if c.GossipProfile == "" {
		c.GossipProfile = string(gossip.ProfileLAN)
	}

	// A node that advertises a cluster address but not a gossip one almost
	// certainly means the same host for both — the ports differ, the host does
	// not. Deriving it removes a whole class of half-configured clusters.
	if c.GossipAdvertiseAddr == "" && c.AdvertiseAddr != "" {
		host, _, err := net.SplitHostPort(c.AdvertiseAddr)
		if err == nil {
			_, gossipPort, portErr := net.SplitHostPort(c.GossipAddr)
			if portErr == nil {
				c.GossipAdvertiseAddr = net.JoinHostPort(host, gossipPort)
			}
		}
	}

	return nil
}

// Validate reports configuration that cannot work, with an explanation of why.
//
//nolint:cyclop,gocyclo // Each branch is one independent rule, and each carries its own message.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	var errs []error

	if c.NodeID == "" {
		errs = append(errs, errors.New("cluster.node-id is required"))
	}

	if c.Bootstrap && c.BootstrapExpect > 1 {
		errs = append(errs, errors.New(
			"cluster.bootstrap and cluster.bootstrap-expect are mutually exclusive: "+
				"the first forms a one-node cluster now, the second waits for peers",
		))
	}

	if c.Bootstrap && c.NonVoter {
		errs = append(errs, errors.New("a non-voting node cannot bootstrap a cluster"))
	}

	if c.BootstrapExpect == 2 {
		errs = append(errs, errors.New(
			"cluster.bootstrap-expect=2 has no fault tolerance: a two-node cluster loses quorum "+
				"when either node fails. Use 1 for a single node or 3 for a fault-tolerant cluster",
		))
	}

	if c.BootstrapExpect > 0 && c.BootstrapExpect%2 == 0 {
		errs = append(errs, fmt.Errorf(
			"cluster.bootstrap-expect=%d is even: an even-sized cluster tolerates no more failures "+
				"than the odd size below it, so prefer %d",
			c.BootstrapExpect, c.BootstrapExpect-1,
		))
	}

	if len(c.Discovery) == 0 && !c.Bootstrap && c.BootstrapExpect == 0 {
		errs = append(errs, errors.New(
			"a cluster node needs either cluster.discovery (to find peers) or cluster.bootstrap "+
				"(to form a new cluster)",
		))
	}

	if _, err := gossip.ParseSecretKey(c.GossipSecret); err != nil {
		errs = append(errs, fmt.Errorf("cluster.gossip.secret: %w", err))
	}

	if err := c.validateAddrs(); err != nil {
		errs = append(errs, err)
	}

	if err := c.validateTLS(); err != nil {
		errs = append(errs, err)
	}

	switch c.Consistency {
	case ConsistencyLocal, ConsistencyStrong:

	default:
		errs = append(errs, fmt.Errorf("cluster.consistency %q is not %q or %q",
			c.Consistency, ConsistencyLocal, ConsistencyStrong,
		))
	}

	switch gossip.Profile(c.GossipProfile) {
	case gossip.ProfileLAN, gossip.ProfileWAN, gossip.ProfileLocal:

	default:
		errs = append(errs, fmt.Errorf("cluster.gossip.profile %q is not %q, %q or %q",
			c.GossipProfile, gossip.ProfileLAN, gossip.ProfileWAN, gossip.ProfileLocal,
		))
	}

	return errors.Join(errs...)
}

func (c *Config) validateAddrs() error {
	var errs []error

	for name, addr := range map[string]string{
		"cluster.bind.addr":   c.BindAddr,
		"cluster.gossip.addr": c.GossipAddr,
	} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			errs = append(errs, fmt.Errorf("%s %q is not host:port: %w", name, addr, err))
		}
	}

	for name, addr := range map[string]string{
		"cluster.advertise.addr":        c.AdvertiseAddr,
		"cluster.gossip.advertise.addr": c.GossipAdvertiseAddr,
	} {
		if addr == "" {
			continue
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %q is not host:port: %w", name, addr, err))

			continue
		}

		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			errs = append(errs, fmt.Errorf(
				"%s is %q: peers cannot dial an unspecified address, so advertise this node's routable address",
				name, addr,
			))
		}
	}

	return errors.Join(errs...)
}

func (c *Config) validateTLS() error {
	set := 0

	for _, file := range []string{c.TLSCertFile, c.TLSKeyFile, c.TLSCAFile} {
		if file != "" {
			set++
		}
	}

	if set != 0 && set != 3 {
		return errors.New(
			"cluster TLS needs all of cluster.tls.cert, cluster.tls.key and cluster.tls.ca, or none of them",
		)
	}

	return nil
}

// GossipPort returns the port gossip binds, for discovery specs that need it.
func (c *Config) GossipPort() int {
	_, port, err := net.SplitHostPort(c.GossipAddr)
	if err != nil {
		return 0
	}

	parsed, convErr := strconv.Atoi(port)
	if convErr != nil {
		return 0
	}

	return parsed
}

// GossipSecretKey decodes the configured gossip key.
func (c *Config) GossipSecretKey() ([]byte, error) {
	key, err := gossip.ParseSecretKey(c.GossipSecret)
	if err != nil {
		return nil, fmt.Errorf("cluster.gossip.secret: %w", err)
	}

	return key, nil
}

// DiscoverySpecs returns the configured specs with blanks removed. A single
// flag may carry several, comma-separated, so `-cluster.discovery` reads the
// way an operator expects when they have both a static seed and a dynamic
// provider.
func (c *Config) DiscoverySpecs() []string {
	specs := make([]string, 0, len(c.Discovery))

	for _, raw := range c.Discovery {
		for _, spec := range splitSpecs(raw) {
			if trimmed := strings.TrimSpace(spec); trimmed != "" {
				specs = append(specs, trimmed)
			}
		}
	}

	return specs
}

// splitSpecs splits a flag value into individual specs.
//
// Splitting on every comma would tear apart `static://a:1,b:2` and the query
// strings the cloud providers use, so a comma only separates specs when what
// follows looks like the start of one.
func splitSpecs(raw string) []string {
	parts := strings.Split(raw, ",")
	specs := make([]string, 0, len(parts))

	current := ""

	for _, part := range parts {
		if current != "" && !strings.Contains(part, "://") {
			current += "," + part

			continue
		}

		if current != "" {
			specs = append(specs, current)
		}

		current = part
	}

	if current != "" {
		specs = append(specs, current)
	}

	return specs
}
