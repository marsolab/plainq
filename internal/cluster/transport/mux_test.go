package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/maxatome/go-testdeep/td"
)

func newTestMux(t *testing.T) *Mux {
	t.Helper()

	mux, err := New(Config{BindAddr: "127.0.0.1:0"})
	td.Require(t).CmpNoError(err)

	t.Cleanup(func() { _ = mux.Close() })

	return mux
}

// The whole point of the mux: two protocols, one port, sorted out by the first
// byte the dialer writes.
func TestMuxRoutesByProtocol(t *testing.T) {
	mux := newTestMux(t)

	raftListener := mux.Listener(ProtoRaft)
	peerListener := mux.Listener(ProtoPeer)

	var wg sync.WaitGroup

	wg.Add(2)

	echo := func(listener net.Listener, label string) {
		defer wg.Done()

		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("%s accept: %v", label, err)

			return
		}

		defer func() { _ = conn.Close() }()

		buf := make([]byte, 5)

		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("%s read: %v", label, err)

			return
		}

		if _, err := conn.Write([]byte(label)); err != nil {
			t.Errorf("%s write: %v", label, err)
		}
	}

	go echo(raftListener, "raft")
	go echo(peerListener, "peer")

	for proto, want := range map[Protocol]string{ProtoRaft: "raft", ProtoPeer: "peer"} {
		conn, err := mux.Dial(proto, mux.BindAddr().String(), 5*time.Second)
		td.Require(t).CmpNoError(err)

		_, writeErr := conn.Write([]byte("hello"))
		td.Require(t).CmpNoError(writeErr)

		reply := make([]byte, len(want))

		_, readErr := io.ReadFull(conn, reply)
		td.Require(t).CmpNoError(readErr)

		td.Cmp(t, string(reply), want, "the connection reached the %q listener", want)

		_ = conn.Close()
	}

	wg.Wait()
}

// Asking twice for the same protocol must hand back the same listener, or the
// second caller silently gets a listener nothing is routed to.
func TestMuxListenerIsStable(t *testing.T) {
	mux := newTestMux(t)

	td.Cmp(t, mux.Listener(ProtoRaft), td.Shallow(mux.Listener(ProtoRaft)))
}

// A connection that names a protocol nobody is listening for is dropped
// rather than left hanging.
func TestMuxDropsUnhandledProtocol(t *testing.T) {
	mux := newTestMux(t)

	conn, err := net.Dial("tcp", mux.BindAddr().String())
	td.Require(t).CmpNoError(err)

	defer func() { _ = conn.Close() }()

	_, writeErr := conn.Write([]byte{99})
	td.Require(t).CmpNoError(writeErr)

	td.Require(t).CmpNoError(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))

	_, readErr := conn.Read(make([]byte, 1))
	td.Cmp(t, readErr, td.Not(nil), "the mux closes a connection it cannot route")
}

// A sub-listener must report the advertised address, because protocols built
// on it — Raft above all — announce that address to their peers.
func TestSubListenerReportsTheAdvertisedAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	td.Require(t).CmpNoError(err)

	port := listener.Addr().(*net.TCPAddr).Port //nolint:errcheck,forcetypeassert // test on a TCP listener.

	td.Require(t).CmpNoError(listener.Close())

	mux, muxErr := New(Config{
		BindAddr:      "127.0.0.1:0",
		AdvertiseAddr: "10.0.0.7:" + strconv.Itoa(port),
	})
	td.Require(t).CmpNoError(muxErr)

	defer func() { _ = mux.Close() }()

	td.Cmp(t, mux.Listener(ProtoRaft).Addr().String(), "10.0.0.7:"+strconv.Itoa(port))
	td.Cmp(t, mux.Addr().String(), "10.0.0.7:"+strconv.Itoa(port))
}

// Binding to 0.0.0.0 and advertising it is the classic cluster
// misconfiguration: every node tells the others to dial "anywhere". Catch it
// where the message can explain itself.
func TestMuxRejectsAdvertisingAnUnspecifiedAddress(t *testing.T) {
	_, err := New(Config{BindAddr: "0.0.0.0:0"})

	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("advertise"))

	_, err = New(Config{BindAddr: "127.0.0.1:0", AdvertiseAddr: "0.0.0.0:8082"})

	td.Require(t).CmpError(err)
	td.Cmp(t, err.Error(), td.Contains("unspecified"))
}

func TestMuxCloseIsIdempotent(t *testing.T) {
	mux, err := New(Config{BindAddr: "127.0.0.1:0"})
	td.Require(t).CmpNoError(err)

	listener := mux.Listener(ProtoPeer)

	td.CmpNoError(t, mux.Close())
	td.CmpNoError(t, mux.Close())

	_, acceptErr := listener.Accept()
	td.Cmp(t, errors.Is(acceptErr, ErrClosed), true)
}

// The peer RPC path is HTTP over a demuxed listener, so prove the whole stack
// composes: an http.Server on one side, an http.Client dialling through the
// mux on the other.
func TestMuxCarriesHTTP(t *testing.T) {
	mux := newTestMux(t)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("pong"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = server.Serve(mux.Listener(ProtoPeer)) }()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				return mux.Dial(ProtoPeer, addr, 5*time.Second)
			},
		},
	}

	resp, err := client.Get("http://" + mux.BindAddr().String() + "/ping")
	td.Require(t).CmpNoError(err)

	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(resp.Body)
	td.Require(t).CmpNoError(readErr)

	td.Cmp(t, string(body), "pong")
}
