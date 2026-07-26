package gossip

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/marsolab/servekit/logkit"
)

// eventBuffer is how many membership changes are held for a subscriber that
// has fallen behind. Events are a hint — Members() is authoritative — so
// dropping the oldest beats blocking memberlist's own goroutines.
const eventBuffer = 256

// Compilation time check that Memberlist implements Gossip.
var _ Gossip = (*Memberlist)(nil)

// Profile selects a set of timing defaults for the gossip layer.
type Profile string

// The available profiles.
const (
	// ProfileLAN suits nodes in one datacenter or VPC. It is the default.
	ProfileLAN Profile = "lan"

	// ProfileWAN suits nodes separated by tens of milliseconds.
	ProfileWAN Profile = "wan"

	// ProfileLocal suits several nodes on one machine — tests, and a
	// developer's laptop.
	ProfileLocal Profile = "local"
)

// Config configures a Memberlist gossip layer.
type Config struct {
	// NodeID is this node's cluster identity. It doubles as the memberlist
	// node name, so it must be unique and stable.
	NodeID string

	// BindAddr and BindPort are where gossip listens (TCP and UDP).
	BindAddr string
	BindPort int

	// AdvertiseAddr and AdvertisePort are what other nodes are told to use.
	// Empty falls back to the bind address, which is wrong behind NAT or in a
	// container with a published port — hence the override.
	AdvertiseAddr string
	AdvertisePort int

	// SecretKey encrypts and authenticates gossip. It must be 16, 24 or 32
	// bytes; an empty key leaves gossip in the clear.
	SecretKey []byte

	// Meta is this node's advertised metadata.
	Meta Meta

	// Profile selects the timing defaults.
	Profile Profile

	// Logger receives memberlist's own diagnostics.
	Logger *slog.Logger
}

// Memberlist is the hashicorp/memberlist implementation of Gossip.
type Memberlist struct {
	list   *memberlist.Memberlist
	logger *slog.Logger

	// metaMu guards meta, which changes when a node is promoted or demoted.
	metaMu sync.RWMutex
	meta   Meta

	events chan Event

	// members is this layer's own view of the pool.
	//
	// It exists because memberlist.Members() hands back pointers into state it
	// goes on mutating: reading a node's metadata after that call races with
	// the failure detector updating it. The delegate callbacks, by contrast,
	// run while memberlist holds its own lock, so copying the fields there is
	// safe — and everything downstream reads this map instead.
	membersMu sync.RWMutex
	members   map[string]Member
	localName string

	// done is closed when the layer shuts down. The event channel itself is
	// never closed: memberlist's own goroutines can still be inside a delegate
	// callback when Shutdown returns, and closing the channel under them turns
	// a clean shutdown into a send on a closed channel.
	done      chan struct{}
	closeOnce sync.Once
}

// New starts a gossip layer and returns it. The node is alive and listening
// when New returns; it has not yet contacted anybody, which is what Join does.
func New(cfg Config) (*Memberlist, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("gossip: node id is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = logkit.NewNop()
	}

	g := Memberlist{
		logger:    logger,
		meta:      cfg.Meta,
		events:    make(chan Event, eventBuffer),
		members:   make(map[string]Member),
		localName: cfg.NodeID,
		done:      make(chan struct{}),
	}

	mlConfig, configErr := memberlistConfig(cfg, &g)
	if configErr != nil {
		return nil, configErr
	}

	list, listErr := memberlist.Create(mlConfig)
	if listErr != nil {
		return nil, fmt.Errorf("start gossip listener on %s: %w",
			net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindPort)), listErr,
		)
	}

	g.list = list

	return &g, nil
}

//nolint:cyclop // Assembling the memberlist config is a flat sequence of optional overrides.
func memberlistConfig(cfg Config, g *Memberlist) (*memberlist.Config, error) {
	var mlConfig *memberlist.Config

	switch cfg.Profile {
	case ProfileWAN:
		mlConfig = memberlist.DefaultWANConfig()

	case ProfileLocal:
		mlConfig = memberlist.DefaultLocalConfig()

	case ProfileLAN, "":
		mlConfig = memberlist.DefaultLANConfig()

	default:
		return nil, fmt.Errorf("gossip: unknown profile %q (want %q, %q or %q)",
			cfg.Profile, ProfileLAN, ProfileWAN, ProfileLocal,
		)
	}

	mlConfig.Name = cfg.NodeID

	if cfg.BindAddr != "" {
		mlConfig.BindAddr = cfg.BindAddr
	}

	if cfg.BindPort != 0 {
		mlConfig.BindPort = cfg.BindPort
	}

	if cfg.AdvertiseAddr != "" {
		mlConfig.AdvertiseAddr = cfg.AdvertiseAddr
	}

	if cfg.AdvertisePort != 0 {
		mlConfig.AdvertisePort = cfg.AdvertisePort
	}

	if len(cfg.SecretKey) > 0 {
		if l := len(cfg.SecretKey); l != 16 && l != 24 && l != 32 {
			return nil, fmt.Errorf("gossip: secret key is %d bytes, want 16, 24 or 32", l)
		}

		mlConfig.SecretKey = cfg.SecretKey
		mlConfig.GossipVerifyIncoming = true
		mlConfig.GossipVerifyOutgoing = true
	}

	delegate := &delegate{gossip: g}
	mlConfig.Delegate = delegate
	mlConfig.Events = delegate

	// memberlist logs through the standard library. Route it into slog at
	// debug so a chatty failure detector does not drown the server log, while
	// still being available when someone goes looking.
	mlConfig.LogOutput = &slogWriter{logger: g.logger}

	return mlConfig, nil
}

// Join implements Gossip.
func (g *Memberlist) Join(ctx context.Context, addrs []string) (int, error) {
	if len(addrs) == 0 {
		return 0, nil
	}

	// memberlist.Join is synchronous and unbounded; run it where the caller's
	// deadline can still cut it short.
	type result struct {
		contacted int
		err       error
	}

	done := make(chan result, 1)

	go func() {
		contacted, err := g.list.Join(addrs)
		done <- result{contacted: contacted, err: err}
	}()

	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("join gossip cluster: %w", ctx.Err())

	case r := <-done:
		if r.err != nil && r.contacted == 0 {
			return 0, fmt.Errorf("join gossip cluster: %w", r.err)
		}

		// Reaching some of the seeds is success: the rest may simply not be up
		// yet, and the ones we reached will tell us about them.
		return r.contacted, nil
	}
}

// Members implements Gossip.
func (g *Memberlist) Members() []Member {
	g.membersMu.RLock()
	defer g.membersMu.RUnlock()

	members := make([]Member, 0, len(g.members))
	for _, member := range g.members {
		members = append(members, member)
	}

	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })

	return members
}

// Local implements Gossip.
func (g *Memberlist) Local() Member {
	g.membersMu.RLock()
	member, ok := g.members[g.localName]
	g.membersMu.RUnlock()

	if ok {
		return member
	}

	// Before the transport has announced this node to itself there is no entry
	// yet. Answer from what the node knows about itself rather than nothing.
	g.metaMu.RLock()
	meta := g.meta
	g.metaMu.RUnlock()

	return Member{Meta: meta, Name: g.localName, State: StateAlive}
}

// UpdateMeta implements Gossip.
func (g *Memberlist) UpdateMeta(meta Meta) error {
	g.metaMu.Lock()
	g.meta = meta
	g.metaMu.Unlock()

	// UpdateNode re-runs the delegate's NodeMeta and pushes the result out.
	if err := g.list.UpdateNode(5 * time.Second); err != nil {
		return fmt.Errorf("broadcast gossip metadata: %w", err)
	}

	return nil
}

// Events implements Gossip.
func (g *Memberlist) Events() <-chan Event { return g.events }

// Leave implements Gossip.
func (g *Memberlist) Leave(timeout time.Duration) error {
	if err := g.list.Leave(timeout); err != nil {
		return fmt.Errorf("leave gossip cluster: %w", err)
	}

	return nil
}

// Close implements Gossip.
func (g *Memberlist) Close() error {
	var err error

	g.closeOnce.Do(func() {
		// Signal first, shut down second. Any delegate callback still running
		// then finds the layer closed and drops its event instead of writing
		// into a channel nobody will read.
		close(g.done)

		err = g.list.Shutdown()
	})

	if err != nil {
		return fmt.Errorf("shut down gossip: %w", err)
	}

	return nil
}

// NumMembers returns how many members gossip currently sees. It is cheaper
// than Members when only the count matters, which is what bootstrap-expect
// polls for.
func (g *Memberlist) NumMembers() int {
	g.membersMu.RLock()
	defer g.membersMu.RUnlock()

	return len(g.members)
}

// setMember records a member. It is called only from a delegate callback,
// where memberlist holds the lock that protects the node it hands us.
func (g *Memberlist) setMember(member Member) {
	g.membersMu.Lock()
	defer g.membersMu.Unlock()

	g.members[member.Name] = member
}

// removeMember forgets a member that left or failed.
func (g *Memberlist) removeMember(name string) {
	g.membersMu.Lock()
	defer g.membersMu.Unlock()

	delete(g.members, name)
}

func (g *Memberlist) toMember(node *memberlist.Node, state State) Member {
	meta, err := DecodeMeta(node.Meta)
	if err != nil {
		// A member whose metadata we cannot read is still a member. Report it
		// with what the transport knows and let the operator see the gap.
		g.logger.Warn("Failed to decode gossip metadata",
			slog.String("node", node.Name),
			slog.String("error", err.Error()),
		)
	}

	if meta.ID == "" {
		meta.ID = node.Name
	}

	return Member{
		Meta:  meta,
		Name:  node.Name,
		Addr:  net.JoinHostPort(node.Addr.String(), strconv.Itoa(int(node.Port))),
		State: state,
	}
}

// emit publishes an event, dropping it if the subscriber is behind or the
// layer is closing. Blocking here would stall memberlist's failure detector,
// which is a far worse outcome than a missed notification.
func (g *Memberlist) emit(event Event) {
	select {
	case <-g.done:
		return

	default:
	}

	select {
	case g.events <- event:

	case <-g.done:

	default:
		g.logger.Debug("Dropped gossip event, subscriber is behind",
			slog.String("type", string(event.Type)),
			slog.String("node", event.Member.Name),
		)
	}
}

// delegate implements both memberlist.Delegate and memberlist.EventDelegate.
type delegate struct {
	gossip *Memberlist
}

// NodeMeta implements memberlist.Delegate.
func (d *delegate) NodeMeta(limit int) []byte {
	d.gossip.metaMu.RLock()
	meta := d.gossip.meta
	d.gossip.metaMu.RUnlock()

	encoded, err := meta.Encode(limit)
	if err != nil {
		d.gossip.logger.Error("Failed to encode gossip metadata",
			slog.String("error", err.Error()),
		)

		return nil
	}

	return encoded
}

// NotifyMsg implements memberlist.Delegate. PlainQ carries no user payload
// over gossip — everything that must be agreed goes through the consensus log
// instead — so there is nothing to do here.
func (d *delegate) NotifyMsg([]byte) {}

// GetBroadcasts implements memberlist.Delegate.
func (d *delegate) GetBroadcasts(int, int) [][]byte { return nil }

// LocalState implements memberlist.Delegate.
func (d *delegate) LocalState(bool) []byte { return nil }

// MergeRemoteState implements memberlist.Delegate.
func (d *delegate) MergeRemoteState([]byte, bool) {}

// NotifyJoin implements memberlist.EventDelegate.
//
// This and its siblings run while memberlist holds the lock over the node it
// passes, which is the only moment the node's fields can be read safely. The
// copy taken here is what every later read sees.
func (d *delegate) NotifyJoin(node *memberlist.Node) {
	member := d.gossip.toMember(node, StateAlive)

	d.gossip.setMember(member)
	d.gossip.emit(Event{Type: EventJoin, Member: member})
}

// NotifyLeave implements memberlist.EventDelegate.
func (d *delegate) NotifyLeave(node *memberlist.Node) {
	member := d.gossip.toMember(node, StateFailed)

	d.gossip.removeMember(member.Name)
	d.gossip.emit(Event{Type: EventLeave, Member: member})
}

// NotifyUpdate implements memberlist.EventDelegate.
func (d *delegate) NotifyUpdate(node *memberlist.Node) {
	member := d.gossip.toMember(node, StateAlive)

	d.gossip.setMember(member)
	d.gossip.emit(Event{Type: EventUpdate, Member: member})
}

// slogWriter adapts memberlist's io.Writer logging onto slog.
type slogWriter struct{ logger *slog.Logger }

func (w *slogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))

	// memberlist prefixes lines with a level in square brackets. Honour the
	// ones that matter and bury the rest at debug.
	switch {
	case strings.Contains(line, "[ERR]"):
		w.logger.Error("gossip", slog.String("message", line))

	case strings.Contains(line, "[WARN]"):
		w.logger.Warn("gossip", slog.String("message", line))

	default:
		w.logger.Debug("gossip", slog.String("message", line))
	}

	return len(p), nil
}

// Compilation time check that slogWriter is an io.Writer.
var _ io.Writer = (*slogWriter)(nil)

// ParseSecretKey decodes a gossip key. An empty key means gossip runs in the
// clear.
//
// The key is base64 and nothing else. Accepting a raw string as a fallback
// looks friendlier and is a trap: a 32-character key like
// "0123456789abcdef0123456789abcdef" is *also* valid base64, so half the
// cluster would read it as 32 raw bytes and half as the 24 bytes it decodes
// to. One encoding means one interpretation.
func ParseSecretKey(key string) ([]byte, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return nil, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	}

	if err != nil {
		return nil, fmt.Errorf(
			"gossip secret must be base64 (generate one with `openssl rand -base64 32`): %w", err,
		)
	}

	if l := len(decoded); l != 16 && l != 24 && l != 32 {
		return nil, fmt.Errorf(
			"gossip secret decodes to %d bytes, want 16, 24 or 32 (`openssl rand -base64 32` gives 32)", l,
		)
	}

	return decoded, nil
}
