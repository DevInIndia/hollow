// Package server answers DNS queries over UDP and TCP.
//
// The concurrency model is fixed, not adaptive, and it is different on each
// transport because the transports are different. UDP has one goroutine reading
// the socket and a bounded pool of workers behind it, because a datagram carries
// no connection to account against and spawning a goroutine per packet is a
// memory amplification anyone can aim at us. TCP has one goroutine per accepted
// connection, capped, because a connection is something a client had to
// establish and can be counted, closed, and timed out.
//
// Where that breaks is written down in the README rather than discovered: when
// the UDP queue fills, packets are dropped and not answered.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DevInIndia/hollow/internal/rrl"
	"github.com/DevInIndia/hollow/internal/wire"
)

// Defaults for the knobs below. They are sized for a laptop serving a handful
// of clients, which is what this is: 64 workers is more than enough to keep
// several resolutions in flight, and a 1024-packet queue absorbs a burst
// without letting a flood consume memory without limit.
const (
	DefaultWorkers     = 64
	DefaultQueue       = 1024
	DefaultTimeout     = 5 * time.Second
	DefaultIdleTimeout = 10 * time.Second
	DefaultMaxConns    = 256
)

// readBuffer is what a UDP read is given. Larger than the 1232 octets we
// advertise, so a client that ignores the advertisement and sends more is
// rejected on its merits rather than silently truncated by the kernel.
const readBuffer = 4096

// Handler answers one query. It is given the decoded query and the address it
// came from, and returns the message to send back, or nil to send nothing at
// all.
//
// Returning nil is not the same as returning SERVFAIL. It means this packet
// deserves no reply, which is the right answer for anything that would turn the
// server into a participant in someone else's traffic.
//
// The client address is a parameter rather than a context value because more
// than one thing needs it and none of them are optional extras: statistics
// attribute queries to a client, and per-client rate limiting and access control
// cannot be written at all without it. A context value would make a required
// input look like an optional one and would lose its type on the way through.
//
// It may be the zero Addr. That is not a client at 0.0.0.0, it means the
// transport could not report one, and a handler that uses the address for a
// decision has to say what it does in that case.
type Handler interface {
	ServeDNS(ctx context.Context, query *wire.Message, from netip.Addr) *wire.Message
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(context.Context, *wire.Message, netip.Addr) *wire.Message

// ServeDNS calls f.
func (f HandlerFunc) ServeDNS(ctx context.Context, q *wire.Message, from netip.Addr) *wire.Message {
	return f(ctx, q, from)
}

// clientAddr extracts the address a query came from.
//
// The port is dropped: it is a different number on every query from the same
// client and is of no use to anything that wants to know who is asking. The
// address is unmapped, so a client reaching a dual-stack listener over IPv4
// counts as that IPv4 address rather than as a separate ::ffff: client, which
// would otherwise split one client across two rows of a top-clients list.
//
// An address this does not recognise comes back as the zero Addr rather than as
// a guess.
func clientAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return v.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// Server serves DNS on one address, over both transports.
//
// The zero value is not usable: Handler must be set. Everything else has a
// default.
type Server struct {
	// Handler answers each query. It is called from many goroutines at once and
	// must be safe for that.
	Handler Handler

	// Workers is the size of the UDP worker pool. Zero means DefaultWorkers.
	Workers int

	// Queue is how many read packets may wait for a worker. Zero means
	// DefaultQueue. Once it is full, further packets are dropped.
	Queue int

	// Timeout bounds answering one query, and bounds each read and write of a
	// TCP message. Zero means DefaultTimeout.
	Timeout time.Duration

	// IdleTimeout is how long a TCP connection may sit between queries before
	// it is closed. Zero means DefaultIdleTimeout.
	IdleTimeout time.Duration

	// MaxConns caps concurrent TCP connections. Zero means DefaultMaxConns.
	// A connection arriving over the cap is closed immediately rather than
	// queued, so a client finds out instead of waiting.
	MaxConns int

	// Log receives operational events. Nil means slog.Default.
	Log *slog.Logger

	// Limiter, when set, bounds how many responses go to one client network.
	// Nil disables it and is the zero value.
	//
	// It lives here rather than in the handler because it is a property of the
	// transport rather than of resolution: what it needs to know is that this
	// query arrived over UDP, where the source address is a claim rather than a
	// fact, and the handler is deliberately not told which transport it is
	// answering on. TCP is exempt for the same reason, and the exemption is the
	// mechanism rather than a shortcut: completing a handshake proves the
	// source address is real.
	Limiter *rrl.Limiter

	// pool holds read buffers. One 4096-octet buffer per packet in flight, not
	// per packet received, which is the difference between steady memory under
	// load and a garbage collector following the query rate.
	pool sync.Pool

	// dropped counts UDP packets discarded because the queue was full, over the
	// life of the server.
	dropped atomic.Uint64

	// warnedDrop makes the first drop log and the rest stay quiet. A full queue
	// means we are already behind, and logging every dropped packet turns a
	// flood of datagrams into a flood of disk writes, which is the same attack
	// with a different target. The total is reported at shutdown.
	warnedDrop atomic.Bool
}

// Conns is a bound pair of listeners, one per transport.
type Conns struct {
	UDP net.PacketConn
	TCP net.Listener
}

// Close closes both listeners, reporting the first failure.
func (c *Conns) Close() error {
	err := c.UDP.Close()
	if terr := c.TCP.Close(); err == nil {
		err = terr
	}
	return err
}

// Addr is the address both listeners hold.
func (c *Conns) Addr() net.Addr { return c.UDP.LocalAddr() }

// Listen binds UDP and TCP on addr, or neither.
//
// A partial bind is fatal here rather than survivable, and the order is
// deliberate. UDP is bound first because it is the one that fails: on port 5353
// a TCP bind succeeds while the UDP bind loses to avahi-daemon on Linux and
// mDNSResponder on macOS. A server that opened TCP first would come up looking
// healthy and then serve one transport, which reads to a user as DNS being
// broken rather than as the server being half started.
//
// When addr names port 0 the port is chosen by the UDP bind and the TCP
// listener is told to use that same port, so a caller asking for any port still
// gets one address rather than two.
func Listen(addr string) (*Conns, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("server: binding udp on %s: %w", addr, err)
	}

	// Not addr: with port 0 that would ask for a second arbitrary port.
	bound := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", bound)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("server: binding tcp on %s, after udp bound: %w", bound, err)
	}
	return &Conns{UDP: pc, TCP: ln}, nil
}

// ListenAndServe binds addr and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	c, err := Listen(addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, c)
}

// Serve answers queries on both listeners until ctx is cancelled, then closes
// them and waits for the work already accepted to finish.
//
// It returns nil on a clean shutdown. A listener that fails for any reason
// other than having been closed by the shutdown is returned as an error, since
// continuing to serve one transport is the state Listen exists to prevent.
func (s *Server) Serve(ctx context.Context, c *Conns) error {
	if s.Handler == nil {
		return errors.New("server: no handler")
	}

	// Cancelled when either transport fails, so the other stops too rather than
	// leaving the process half serving.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	queue := make(chan packet, s.queue())
	var workers sync.WaitGroup
	for range s.workers() {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s.udpWorker(ctx, c.UDP, queue)
		}()
	}

	var listeners sync.WaitGroup
	errs := make([]error, 2)
	listeners.Add(2)
	go func() {
		defer listeners.Done()
		defer cancel()
		errs[0] = s.serveUDP(ctx, c.UDP, queue)
	}()
	go func() {
		defer listeners.Done()
		defer cancel()
		errs[1] = s.serveTCP(ctx, c.TCP)
	}()

	<-ctx.Done()

	// Closing the listeners is what unblocks the reader parked in ReadFrom and
	// the acceptor parked in Accept. There is no deadline that would do it:
	// a listener with no traffic has nothing to time out.
	c.Close()
	listeners.Wait()

	// Only now, with the reader gone, can the queue be closed. Closing it while
	// the reader still holds it would panic on the next send, and a shutdown
	// that panics is worse than one that takes an extra moment.
	close(queue)
	workers.Wait()

	if n := s.dropped.Load(); n > 0 {
		s.log().Warn("udp packets dropped, queue full", "count", n)
	}

	// errors.Join rather than the first error: both transports can fail, and
	// which one is reported should not depend on which goroutine was scheduled
	// first. Nils drop out, so a clean shutdown still returns nil.
	return errors.Join(errs[0], errs[1])
}

// answer decodes a query, hands it to the handler, and encodes the reply.
// It returns nil when nothing should be sent.
func (s *Server) answer(ctx context.Context, raw []byte, from netip.Addr, overTCP bool) []byte {
	query, err := wire.Unpack(raw)
	if err != nil {
		// A message we cannot decode may still have a usable header, and RFC
		// 1035 section 4.1.1 wants FORMERR rather than silence so the client
		// stops waiting. Below a header there is nothing to echo and nothing to
		// say.
		if id, ok := peekID(raw); ok {
			return s.encode(formErr(id), minUDPSize)
		}
		s.log().Debug("undecodable query", "octets", len(raw), "err", err)
		return nil
	}

	// A response is not a query. Answering one is how two servers pointed at
	// each other trade a packet forever, and how an attacker gets us to send
	// traffic to a victim by putting the victim's address in the source. Drop
	// it without a word.
	if query.Header.Response {
		return nil
	}

	// Rate limiting decides before the query is resolved, not after. An answer
	// that will not be sent is not worth a walk from the root, and the work
	// saved is the second half of what this defends against.
	if !overTCP {
		switch s.Limiter.Allow(from) {
		case rrl.Drop:
			return nil
		case rrl.Truncate:
			return s.encode(truncated(query), minUDPSize)
		}
	}

	reply := s.Handler.ServeDNS(ctx, query, from)
	if reply == nil {
		return nil
	}
	return s.encode(reply, replyLimit(query, overTCP))
}

// Bounds on how large a UDP reply may be. The floor is the 512 octets RFC 1035
// section 4.2.1 requires every implementation to handle. The ceiling is not the
// 65535 a client may advertise: a reply that large is fragmented by IP, and
// fragments are both lost more often and easier to forge than whole datagrams.
// Past the ceiling the client is sent a truncated reply and asks again over TCP,
// which is the mechanism that exists for exactly this.
const (
	minUDPSize = 512
	maxUDPSize = 4096
)

// replyLimit is the largest reply this transport will carry. TCP gets the whole
// range the two-octet length prefix can express. UDP gets what the client asked
// for in its own OPT record, clamped, because the client is the one that has to
// receive it.
func replyLimit(query *wire.Message, overTCP bool) int {
	if overTCP {
		return 65535
	}
	limit := minUDPSize
	if e, ok, err := query.EDNS(); err == nil && ok {
		limit = int(e.UDPSize)
	}
	return min(max(limit, minUDPSize), maxUDPSize)
}

// encode packs a reply, truncating it if it does not fit.
func (s *Server) encode(m *wire.Message, limit int) []byte {
	buf, err := m.Pack()
	if err != nil {
		// The handler produced something unencodable, which is our bug, not the
		// client's. SERVFAIL is the honest report of it.
		s.log().Error("encoding a reply", "err", err)
		if buf, err = s.servFail(m).Pack(); err != nil {
			return nil
		}
		return buf
	}
	if len(buf) <= limit {
		return buf
	}

	// Too big for this transport. RFC 1035 section 4.2.1: set TC and send what
	// fits, which the client answers by asking again over TCP. The records are
	// dropped rather than partly included, because a client that ignored TC
	// would otherwise act on an answer with a piece missing and no way to know.
	short := &wire.Message{
		Header:    m.Header,
		Questions: m.Questions,
	}
	short.Header.Truncated = true
	if e, ok, err := m.EDNS(); err == nil && ok {
		short.SetEDNS(e)
	}
	buf, err = short.Pack()
	if err != nil || len(buf) > limit {
		return nil
	}
	return buf
}

func (s *Server) servFail(m *wire.Message) *wire.Message {
	out := &wire.Message{
		Header: wire.Header{
			ID:                 m.Header.ID,
			Response:           true,
			Opcode:             m.Header.Opcode,
			RecursionDesired:   m.Header.RecursionDesired,
			RecursionAvailable: true,
			Rcode:              wire.RcodeServFail,
		},
		Questions: m.Questions,
	}
	return out
}

// formErr builds the reply to a message that could not be decoded. It echoes
// nothing but the transaction ID, since nothing else was understood.
// truncated is the slip response: a header with TC set, the question echoed,
// and nothing else. A real client reads it as "ask again over TCP" and does,
// which succeeds because TCP is exempt from the limit. A spoofed source cannot
// complete the handshake, so this costs an attacker a connection they cannot
// open and costs their victim nothing but a few dozen octets.
func truncated(query *wire.Message) *wire.Message {
	return &wire.Message{
		Header: wire.Header{
			ID:                 query.Header.ID,
			Response:           true,
			Opcode:             query.Header.Opcode,
			Truncated:          true,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: query.Questions,
	}
}

func formErr(id uint16) *wire.Message {
	return &wire.Message{
		Header: wire.Header{
			ID:       id,
			Response: true,
			Rcode:    wire.RcodeFormErr,
		},
	}
}

// peekID reads the transaction ID out of a message too malformed to decode.
// Anything shorter than a header has no ID to read.
func peekID(raw []byte) (uint16, bool) {
	if len(raw) < 12 {
		return 0, false
	}
	return uint16(raw[0])<<8 | uint16(raw[1]), true
}

// queryContext bounds one query by the timeout, detached from the server's
// shutdown.
//
// Detached is the deliberate part. A resolution in flight when SIGINT arrives
// would otherwise be cancelled mid-walk and the client would get nothing, for
// the sake of shutting down a few hundred milliseconds sooner. Work already
// begun finishes; work not yet begun is dropped, and Serve waits for the
// difference. That bounds shutdown by one timeout rather than by the queue.
func (s *Server) queryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), s.timeout())
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) workers() int {
	if s.Workers > 0 {
		return s.Workers
	}
	return DefaultWorkers
}

func (s *Server) queue() int {
	if s.Queue > 0 {
		return s.Queue
	}
	return DefaultQueue
}

func (s *Server) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultTimeout
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return DefaultIdleTimeout
}

func (s *Server) maxConns() int {
	if s.MaxConns > 0 {
		return s.MaxConns
	}
	return DefaultMaxConns
}
