package gossip

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/maxatome/go-testdeep/td"
)

func TestMetaRoundTrip(t *testing.T) {
	meta := Meta{
		ID:       "node-1",
		RaftAddr: "10.0.0.1:8082",
		Role:     RoleVoter,
		Version:  "abc123",
		Tags:     map[string]string{"zone": "eu-west-1a"},
	}

	encoded, err := meta.Encode(512)
	td.Require(t).CmpNoError(err)

	decoded, decodeErr := DecodeMeta(encoded)
	td.Require(t).CmpNoError(decodeErr)

	td.Cmp(t, decoded, meta)
}

// The transport caps node metadata at 512 bytes. Dropping the optional tags
// keeps a node broadcasting at all, which matters far more than its labels.
func TestMetaShedsTagsToFitTheLimit(t *testing.T) {
	meta := Meta{
		ID:       "node-1",
		RaftAddr: "10.0.0.1:8082",
		Role:     RoleVoter,
		Tags:     map[string]string{"blob": strings.Repeat("x", 600)},
	}

	encoded, err := meta.Encode(512)
	td.Require(t).CmpNoError(err)

	decoded, decodeErr := DecodeMeta(encoded)
	td.Require(t).CmpNoError(decodeErr)

	td.Cmp(t, decoded.ID, "node-1", "the identity survives")
	td.Cmp(t, decoded.RaftAddr, "10.0.0.1:8082", "so does the address the cluster needs")
	td.Cmp(t, decoded.Tags, td.Nil(), "the labels are what gets dropped")
}

// Without the address there is nothing to fall back on, so an over-long
// mandatory payload is an error rather than a silent truncation.
func TestMetaRefusesToTruncateTheEssentials(t *testing.T) {
	meta := Meta{ID: strings.Repeat("n", 600), RaftAddr: "10.0.0.1:8082"}

	_, err := meta.Encode(512)
	td.CmpError(t, err)
}

func TestDecodeMetaHandlesEmpty(t *testing.T) {
	meta, err := DecodeMeta(nil)

	td.CmpNoError(t, err)
	td.Cmp(t, meta, Meta{})
}

func TestParseSecretKey(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")

	key, err := ParseSecretKey(base64.StdEncoding.EncodeToString(raw))
	td.Require(t).CmpNoError(err)
	td.Cmp(t, key, raw)

	// Unpadded base64 is what several key generators emit, so it decodes too.
	key, err = ParseSecretKey(base64.RawStdEncoding.EncodeToString(raw))
	td.Require(t).CmpNoError(err)
	td.Cmp(t, key, raw)

	// No key means gossip runs in the clear — an explicit choice, not an error.
	key, err = ParseSecretKey("")
	td.CmpNoError(t, err)
	td.Cmp(t, key, td.Nil())

	// The key is base64 and only base64. A 32-character string that is *also*
	// valid base64 must decode as base64 on every node, or half the cluster
	// would use a different key than the other half and never say why.
	key, err = ParseSecretKey("0123456789abcdef0123456789abcdef")
	td.Require(t).CmpNoError(err)
	td.Cmp(t, len(key), 24, "read as base64, not as 32 raw bytes")

	_, err = ParseSecretKey("not valid base64 !!")
	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("openssl rand -base64 32"), "the message says how to make one")

	_, err = ParseSecretKey(base64.StdEncoding.EncodeToString([]byte("twelve bytes")))
	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("12 bytes"))
}

// freePort returns a port nothing is listening on. Gossip binds TCP and UDP,
// and memberlist needs a concrete port rather than zero.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	td.Require(t).CmpNoError(err)

	port := listener.Addr().(*net.TCPAddr).Port //nolint:errcheck,forcetypeassert // test on a TCP listener.

	td.Require(t).CmpNoError(listener.Close())

	return port
}

func newTestGossip(t *testing.T, id string, secret []byte) *Memberlist {
	t.Helper()

	port := freePort(t)

	g, err := New(Config{
		NodeID:    id,
		BindAddr:  "127.0.0.1",
		BindPort:  port,
		SecretKey: secret,
		Profile:   ProfileLocal,
		Meta: Meta{
			ID:       id,
			RaftAddr: "127.0.0.1:" + itoa(port+1000),
			Role:     RoleVoter,
			Version:  "test",
		},
	})
	td.Require(t).CmpNoError(err)

	t.Cleanup(func() { _ = g.Close() })

	return g
}

// Two nodes finding each other, exchanging metadata, and agreeing they are
// both there — the whole membership layer in one test.
func TestTwoNodesFormAGossipPool(t *testing.T) {
	first := newTestGossip(t, "node-1", nil)
	second := newTestGossip(t, "node-2", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	contacted, err := second.Join(ctx, []string{first.Local().Addr})
	td.Require(t).CmpNoError(err)
	td.Cmp(t, contacted, 1)

	waitFor(t, 10*time.Second, func() bool {
		return len(first.Members()) == 2 && len(second.Members()) == 2
	}, "both nodes see two members")

	// The metadata a node gossips is how the cluster learns where its
	// consensus port is — without it a member is visible but unusable.
	var peer Member

	for _, member := range first.Members() {
		if member.ID == "node-2" {
			peer = member
		}
	}

	td.Cmp(t, peer.ID, "node-2")
	td.Cmp(t, peer.RaftAddr, td.Not(""), "the peer advertised its consensus address")
	td.Cmp(t, peer.Role, RoleVoter)
	td.Cmp(t, peer.Version, "test")
}

// A node promoted from replica to voter has to say so, or the leader keeps
// treating it as one.
func TestUpdateMetaIsBroadcast(t *testing.T) {
	first := newTestGossip(t, "node-1", nil)
	second := newTestGossip(t, "node-2", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := second.Join(ctx, []string{first.Local().Addr})
	td.Require(t).CmpNoError(err)

	waitFor(t, 10*time.Second, func() bool { return len(first.Members()) == 2 }, "the pool forms")

	updated := second.Local().Meta
	updated.Role = RoleNonVoter

	td.Require(t).CmpNoError(second.UpdateMeta(updated))

	waitFor(t, 10*time.Second, func() bool {
		for _, member := range first.Members() {
			if member.ID == "node-2" && member.Role == RoleNonVoter {
				return true
			}
		}

		return false
	}, "the change reaches the other node")
}

// A shared key is the difference between a cluster and anything that can reach
// the port. A node without it must not be able to join.
func TestGossipSecretKeepsStrangersOut(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	secured := newTestGossip(t, "node-1", secret)
	stranger := newTestGossip(t, "node-2", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := stranger.Join(ctx, []string{secured.Local().Addr})
	td.Cmp(t, err, td.Not(nil), "an unencrypted node cannot join an encrypted pool")

	td.Cmp(t, len(secured.Members()), 1, "the secured node is still alone")
}

func TestGossipRejectsABadKeyLength(t *testing.T) {
	_, err := New(Config{
		NodeID:    "node-1",
		BindAddr:  "127.0.0.1",
		BindPort:  freePort(t),
		SecretKey: []byte("nope"),
		Profile:   ProfileLocal,
	})

	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("16, 24 or 32"))
}

func TestGossipRequiresANodeID(t *testing.T) {
	_, err := New(Config{BindAddr: "127.0.0.1", BindPort: freePort(t)})
	td.CmpError(t, err)
}

func TestGossipRejectsAnUnknownProfile(t *testing.T) {
	_, err := New(Config{
		NodeID:   "node-1",
		BindAddr: "127.0.0.1",
		BindPort: freePort(t),
		Profile:  "interplanetary",
	})

	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("unknown profile"))
}

// Joining nobody is not a failure: the first node of a cluster has nobody to
// join, and treating that as an error would make every cluster fail to start.
func TestJoinWithNoAddressesSucceeds(t *testing.T) {
	g := newTestGossip(t, "node-1", nil)

	contacted, err := g.Join(context.Background(), nil)

	td.CmpNoError(t, err)
	td.Cmp(t, contacted, 0)
}

func TestCloseIsIdempotent(t *testing.T) {
	g := newTestGossip(t, "node-1", nil)

	td.CmpNoError(t, g.Close())
	td.CmpNoError(t, g.Close())
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, what string) {
	t.Helper()

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("timed out after %s waiting for: %s", timeout, what)
}

func itoa(v int) string { // strconv would do, but this keeps the test file dependency-free.
	digits := ""

	if v == 0 {
		return "0"
	}

	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}

	return digits
}
