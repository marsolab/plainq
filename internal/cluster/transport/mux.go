// Package transport carries every byte a PlainQ node sends to another node.
//
// A cluster needs two conversations: the consensus protocol, and the internal
// peer RPC a follower uses to hand a write to the leader. They could have a
// port each. They share one instead, demultiplexed by a byte the dialer writes
// before anything else — one port to open in a firewall, one address to
// advertise, one thing to get wrong.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/marsolab/servekit/logkit"
)

// Protocol identifies which conversation a connection belongs to. The value is
// the first byte on the wire: append, never renumber.
type Protocol byte

// The protocols carried on the cluster port.
const (
	// ProtoRaft carries the consensus protocol.
	ProtoRaft Protocol = 1

	// ProtoPeer carries internal peer RPC — write forwarding, join, status.
	ProtoPeer Protocol = 2
)

// handshakeTimeout bounds how long a connection may take to declare itself.
// A connection that opens and says nothing is a port scan or a stuck peer;
// either way it must not hold an accept slot indefinitely.
const handshakeTimeout = 10 * time.Second

// backlog is how many accepted connections wait for their protocol handler.
const backlog = 64

// ErrClosed is returned by a sub-listener after the mux is closed.
var ErrClosed = errors.New("transport: listener is closed")

// Mux accepts on one TCP listener and hands each connection to the protocol
// it names.
type Mux struct {
	listener net.Listener
	logger   *slog.Logger

	// advertise is the address peers should dial. It differs from the bind
	// address whenever the node is behind NAT, in a container with a
	// published port, or bound to 0.0.0.0.
	advertise net.Addr

	// tlsConfig, when set, wraps both directions.
	tlsConfig *tls.Config

	// sub holds one listener per protocol.
	subMu sync.RWMutex
	sub   map[Protocol]*subListener

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// Config configures a Mux.
type Config struct {
	// BindAddr is the local address to listen on.
	BindAddr string

	// AdvertiseAddr is what peers are told to dial. Empty uses the bind
	// address, which is only correct when it is a routable address.
	AdvertiseAddr string

	// TLSConfig, when set, encrypts cluster traffic. Both the server and the
	// client side use it, so it needs a certificate and a root pool.
	TLSConfig *tls.Config

	// Logger receives transport diagnostics.
	Logger *slog.Logger
}

// New binds the cluster port and starts accepting.
func New(cfg Config) (*Mux, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = logkit.NewNop()
	}

	var listenConfig net.ListenConfig

	listener, listenErr := listenConfig.Listen(context.Background(), "tcp", cfg.BindAddr)
	if listenErr != nil {
		return nil, fmt.Errorf("listen on cluster address %q: %w", cfg.BindAddr, listenErr)
	}

	advertise, advertiseErr := resolveAdvertise(cfg.AdvertiseAddr, listener.Addr())
	if advertiseErr != nil {
		_ = listener.Close()

		return nil, advertiseErr
	}

	m := Mux{
		listener:  listener,
		logger:    logger,
		advertise: advertise,
		tlsConfig: cfg.TLSConfig,
		sub:       make(map[Protocol]*subListener, 2),
		done:      make(chan struct{}),
	}

	m.wg.Add(1)

	go m.accept()

	return &m, nil
}

// Addr returns the address peers should dial.
func (m *Mux) Addr() net.Addr { return m.advertise }

// BindAddr returns the address actually bound, which is what a test needs when
// it asked for port 0.
func (m *Mux) BindAddr() net.Addr { return m.listener.Addr() }

// Listener returns the listener for one protocol. Calling it twice for the
// same protocol returns the same listener.
func (m *Mux) Listener(proto Protocol) net.Listener {
	m.subMu.Lock()
	defer m.subMu.Unlock()

	if existing, ok := m.sub[proto]; ok {
		return existing
	}

	sub := &subListener{
		proto:  proto,
		addr:   m.advertise,
		conns:  make(chan net.Conn, backlog),
		closed: make(chan struct{}),
	}

	m.sub[proto] = sub

	return sub
}

// Dial opens a connection to a peer and declares the protocol on it.
func (m *Mux) Dial(proto Protocol, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}

	conn, dialErr := dialer.Dial("tcp", addr)
	if dialErr != nil {
		return nil, fmt.Errorf("dial peer %q: %w", addr, dialErr)
	}

	if m.tlsConfig != nil {
		tlsConn := tls.Client(conn, m.tlsConfig)

		handshakeCtx, cancelHandshake := context.WithTimeout(context.Background(), handshakeTimeout)
		defer cancelHandshake()

		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("tls handshake with peer %q: %w", addr, err)
		}

		conn = tlsConn
	}

	// The protocol byte goes out before anything the caller writes, and under
	// the same deadline as the dial: a peer that accepts the TCP connection
	// but never reads must not strand us here.
	if timeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("set write deadline for peer %q: %w", addr, err)
		}
	}

	if _, err := conn.Write([]byte{byte(proto)}); err != nil {
		_ = conn.Close()

		return nil, fmt.Errorf("write protocol header to peer %q: %w", addr, err)
	}

	if timeout > 0 {
		if err := conn.SetWriteDeadline(time.Time{}); err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("clear write deadline for peer %q: %w", addr, err)
		}
	}

	return conn, nil
}

// Close stops accepting and closes every sub-listener.
func (m *Mux) Close() error {
	var err error

	m.closeOnce.Do(func() {
		close(m.done)

		err = m.listener.Close()

		m.subMu.Lock()

		for _, sub := range m.sub {
			sub.close()
		}

		m.subMu.Unlock()

		m.wg.Wait()
	})

	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close cluster listener: %w", err)
	}

	return nil
}

func (m *Mux) accept() {
	defer m.wg.Done()

	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.done:
				return

			default:
			}

			// A transient accept error (out of file descriptors, a connection
			// reset between accept and return) must not kill the whole cluster
			// port. Back off a little and carry on.
			if netErr := net.Error(nil); errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}

			m.logger.Error("Cluster listener accept failed",
				slog.String("error", err.Error()),
			)

			select {
			case <-m.done:
				return

			case <-time.After(100 * time.Millisecond):
				continue
			}
		}

		m.wg.Add(1)

		// The protocol byte is read off the accept path. Reading it inline
		// would let one slow peer stall every other connection.
		go m.route(conn)
	}
}

func (m *Mux) route(conn net.Conn) {
	defer m.wg.Done()

	if m.tlsConfig != nil {
		tlsConn := tls.Server(conn, m.tlsConfig)

		handshakeCtx, cancelHandshake := context.WithTimeout(context.Background(), handshakeTimeout)

		err := tlsConn.HandshakeContext(handshakeCtx)

		cancelHandshake()

		if err != nil {
			m.logger.Debug("Cluster TLS handshake failed",
				slog.String("remote", conn.RemoteAddr().String()),
				slog.String("error", err.Error()),
			)

			_ = conn.Close()

			return
		}

		conn = tlsConn
	}

	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		_ = conn.Close()

		return
	}

	var header [1]byte

	if _, err := io.ReadFull(conn, header[:]); err != nil {
		m.logger.Debug("Cluster connection closed before declaring a protocol",
			slog.String("remote", conn.RemoteAddr().String()),
			slog.String("error", err.Error()),
		)

		_ = conn.Close()

		return
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()

		return
	}

	proto := Protocol(header[0])

	m.subMu.RLock()
	sub, ok := m.sub[proto]
	m.subMu.RUnlock()

	if !ok {
		m.logger.Warn("Cluster connection named an unhandled protocol",
			slog.String("remote", conn.RemoteAddr().String()),
			slog.Int("protocol", int(header[0])),
		)

		_ = conn.Close()

		return
	}

	if !sub.offer(conn, m.done) {
		_ = conn.Close()
	}
}

// subListener is the net.Listener handed to one protocol.
type subListener struct {
	proto Protocol
	addr  net.Addr
	conns chan net.Conn

	closeOnce sync.Once
	closed    chan struct{}
}

// Accept implements net.Listener.
func (s *subListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-s.conns:
		if !ok {
			return nil, ErrClosed
		}

		return conn, nil

	case <-s.closed:
		return nil, ErrClosed
	}
}

// Close implements net.Listener. It closes only this protocol's listener; the
// mux keeps serving the others.
func (s *subListener) Close() error {
	s.close()

	return nil
}

// Addr implements net.Listener, reporting the advertised cluster address so a
// protocol that announces its own address announces a reachable one.
func (s *subListener) Addr() net.Addr { return s.addr }

func (s *subListener) close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

// offer hands a connection to the protocol, or reports that it could not.
func (s *subListener) offer(conn net.Conn, done <-chan struct{}) bool {
	select {
	case s.conns <- conn:
		return true

	case <-s.closed:
		return false

	case <-done:
		return false
	}
}

// resolveAdvertise decides what address to tell peers about.
//
// Binding to 0.0.0.0 and advertising it is the classic cluster misconfiguration:
// every node tells every other node to dial "everywhere", and nothing connects.
// Catch it here, where the error can say so, rather than in a peer's dial
// failure an hour later.
func resolveAdvertise(advertise string, bound net.Addr) (net.Addr, error) {
	if advertise == "" {
		tcpAddr, ok := bound.(*net.TCPAddr)
		if !ok {
			return bound, nil
		}

		if tcpAddr.IP.IsUnspecified() {
			return nil, errors.New(
				"cluster bind address is unspecified (0.0.0.0 or ::) and no advertise address is set — " +
					"peers cannot dial 'any address', so set the advertise address to this node's routable address",
			)
		}

		return bound, nil
	}

	resolved, err := net.ResolveTCPAddr("tcp", advertise)
	if err != nil {
		return nil, fmt.Errorf("resolve cluster advertise address %q: %w", advertise, err)
	}

	if resolved.IP != nil && resolved.IP.IsUnspecified() {
		return nil, fmt.Errorf("cluster advertise address %q is unspecified; peers cannot dial it", advertise)
	}

	return resolved, nil
}
