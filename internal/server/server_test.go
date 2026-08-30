package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

// The tests run against real loopback sockets rather than a fake network. What
// is under test here is mostly the behaviour of sockets under shutdown, caps and
// deadlines, and a fake that reproduced all of that faithfully would be the
// thing that needed testing.

func TestListenBindsBothTransportsOnOnePort(t *testing.T) {
	c, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	defer c.Close()

	udp := c.UDP.LocalAddr().String()
	tcp := c.TCP.Addr().String()
	if udp != tcp {
		t.Errorf("udp bound %s but tcp bound %s, want one address", udp, tcp)
	}
}

// The failure CLAUDE.md calls the most dangerous one: TCP unavailable while UDP
// is free. A server that took the UDP bind and carried on would look healthy and
// serve one transport.
func TestListenRefusesAPartialBind(t *testing.T) {
	// Hold the TCP side of a port, leaving its UDP side free.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("holding a tcp port: %v", err)
	}
	defer held.Close()
	addr := held.Addr().String()

	c, err := Listen(addr)
	if err == nil {
		c.Close()
		t.Fatal("Listen() succeeded with the tcp port already held")
	}
	if !strings.Contains(err.Error(), "tcp") {
		t.Errorf("Listen() = %v, want an error naming the transport that failed", err)
	}

	// The UDP socket it opened on the way to failing must be closed, or the
	// port is leaked for the life of the process and a retry cannot succeed.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the udp socket was not released after the tcp bind failed: %v", err)
	}
	pc.Close()
}

func TestServeAnswersOverUDP(t *testing.T) {
	addr := serve(t, &Server{Handler: answerA("192.0.2.1")})

	reply := askUDP(t, addr, query(t, "example.com.", wire.TypeA), 0)
	if len(reply.Answers) != 1 {
		t.Fatalf("reply carries %d answers, want 1", len(reply.Answers))
	}
	if a, ok := reply.Answers[0].Data.(wire.A); !ok || a.Addr.String() != "192.0.2.1" {
		t.Errorf("reply carries %v, want 192.0.2.1", reply.Answers[0].Data)
	}
	if !reply.Header.Response {
		t.Error("reply has the response bit clear")
	}
}

func TestServeAnswersOverTCP(t *testing.T) {
	addr := serve(t, &Server{Handler: answerA("192.0.2.1")})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialing tcp: %v", err)
	}
	defer conn.Close()

	reply := exchangeTCP(t, conn, query(t, "example.com.", wire.TypeA))
	if len(reply.Answers) != 1 {
		t.Fatalf("reply carries %d answers, want 1", len(reply.Answers))
	}
}

// RFC 7766: a TCP connection carries more than one query. Closing after the
// first is a common bug and shows up as a client that works but is slow.
func TestTCPCarriesSeveralQueriesOnOneConnection(t *testing.T) {
	addr := serve(t, &Server{Handler: answerA("192.0.2.1")})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialing tcp: %v", err)
	}
	defer conn.Close()

	for i := range 3 {
		q := query(t, "example.com.", wire.TypeA)
		q.Header.ID = uint16(1000 + i)
		reply := exchangeTCP(t, conn, q)
		if reply.Header.ID != q.Header.ID {
			t.Fatalf("query %d: reply id %d, want %d", i, reply.Header.ID, q.Header.ID)
		}
	}
}

// A reply past what the client can receive comes back with TC set and no
// records, so the client asks again over TCP and gets the whole thing. Sending
// a partial answer without TC is the failure worth testing against: the client
// would act on it and never know a piece was missing.
func TestUDPTruncatesWhatDoesNotFit(t *testing.T) {
	addr := serve(t, &Server{Handler: bulky()})

	udp := askUDP(t, addr, query(t, "example.com.", wire.TypeTXT), 0)
	if !udp.Header.Truncated {
		t.Error("an oversized reply came back over udp without TC set")
	}
	if len(udp.Answers) != 0 {
		t.Errorf("a truncated reply carries %d answers, want none", len(udp.Answers))
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialing tcp: %v", err)
	}
	defer conn.Close()

	tcp := exchangeTCP(t, conn, query(t, "example.com.", wire.TypeTXT))
	if tcp.Header.Truncated {
		t.Error("the tcp reply is truncated, which defeats the fallback")
	}
	if len(tcp.Answers) == 0 {
		t.Error("the tcp reply carries no answers")
	}
}

// A client that advertises a larger buffer gets the whole reply over UDP.
func TestUDPHonoursTheAdvertisedSize(t *testing.T) {
	addr := serve(t, &Server{Handler: bulky()})

	q := query(t, "example.com.", wire.TypeTXT)
	q.SetEDNS(wire.EDNS{UDPSize: 4096})

	reply := askUDP(t, addr, q, 4096)
	if reply.Header.Truncated {
		t.Error("reply truncated despite a 4096-octet advertisement")
	}
	if len(reply.Answers) == 0 {
		t.Error("reply carries no answers")
	}
}

// Answering a response is how two servers aimed at each other trade a packet
// forever, and how a spoofed source turns us into someone else's traffic.
func TestServerIgnoresResponses(t *testing.T) {
	addr := serve(t, &Server{Handler: answerA("192.0.2.1")})

	q := query(t, "example.com.", wire.TypeA)
	q.Header.Response = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("packing: %v", err)
	}

	conn := dialUDP(t, addr)
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("writing: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 512)
	if n, err := conn.Read(buf); err == nil {
		t.Errorf("the server replied to a response with %d octets, want silence", n)
	}
}

// A message we cannot decode still gets FORMERR when it has a header to echo,
// so the client stops waiting rather than timing out.
func TestUndecodableQueryGetsFormErr(t *testing.T) {
	addr := serve(t, &Server{Handler: answerA("192.0.2.1")})

	// A well-formed 12-octet header claiming one question, with no question.
	raw := make([]byte, 12)
	binary.BigEndian.PutUint16(raw[0:], 0xBEEF)
	binary.BigEndian.PutUint16(raw[4:], 1)

	conn := dialUDP(t, addr)
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("writing: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	reply, err := wire.Unpack(buf[:n])
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	if reply.Header.Rcode != wire.RcodeFormErr {
		t.Errorf("rcode %d, want FORMERR (%d)", reply.Header.Rcode, wire.RcodeFormErr)
	}
	if reply.Header.ID != 0xBEEF {
		t.Errorf("reply id %#04x, want 0xbeef echoed back", reply.Header.ID)
	}
}

// Anything shorter than a header has no ID to echo, so there is nothing to
// answer with and the packet is dropped.
func TestRuntQueryIsDropped(t *testing.T) {
	addr := serve(t, &Server{Handler: answerA("192.0.2.1")})

	conn := dialUDP(t, addr)
	if _, err := conn.Write([]byte{1, 2, 3}); err != nil {
		t.Fatalf("writing: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 512)
	if n, err := conn.Read(buf); err == nil {
		t.Errorf("the server replied to a 3-octet packet with %d octets, want silence", n)
	}
}

// Shutdown must return, and must return cleanly, with a connection open. A
// server that hangs here is one a judge sees hang.
func TestShutdownReturnsWithAConnectionOpen(t *testing.T) {
	c, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{Handler: answerA("192.0.2.1"), Log: quiet()}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, c) }()

	conn, err := net.Dial("tcp", c.TCP.Addr().String())
	if err != nil {
		t.Fatalf("dialing tcp: %v", err)
	}
	defer conn.Close()
	// One exchange, so the connection is established and parked in a read
	// rather than merely accepted.
	exchangeTCP(t, conn, query(t, "example.com.", wire.TypeA))

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() = %v, want nil on a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return within 5s of cancellation")
	}
}

// A resolution already under way when shutdown starts is finished rather than
// abandoned. Serve waits for it, which is what bounds shutdown by one timeout
// instead of by the queue.
func TestShutdownWaitsForAQueryInFlight(t *testing.T) {
	c, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	finish := make(chan struct{})
	var answered bool

	s := &Server{
		Log: quiet(),
		Handler: HandlerFunc(func(qctx context.Context, q *wire.Message, _ netip.Addr) *wire.Message {
			close(started)
			<-finish
			// The detached context must still be live here. If shutdown had
			// cancelled it, this is where the difference shows.
			answered = qctx.Err() == nil
			return replyTo(q, wire.A{Addr: netip.MustParseAddr("192.0.2.1")})
		}),
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, c) }()

	conn := dialUDP(t, c.UDP.LocalAddr().String())
	raw, err := query(t, "example.com.", wire.TypeA).Pack()
	if err != nil {
		t.Fatalf("packing: %v", err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("writing: %v", err)
	}

	<-started
	cancel()

	// Shutdown is now under way with the handler still inside. Release it and
	// require that Serve waited.
	time.Sleep(50 * time.Millisecond)
	close(finish)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return within 5s")
	}
	if !answered {
		t.Error("the query in flight had its context cancelled by shutdown")
	}
}

// Over the cap a connection is closed rather than held unserved, so the client
// learns immediately instead of waiting out its own timeout.
func TestTCPRefusesConnectionsOverTheCap(t *testing.T) {
	addr := serve(t, &Server{Handler: answerA("192.0.2.1"), MaxConns: 1, Log: quiet()})

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialing the first connection: %v", err)
	}
	defer first.Close()
	// Force it through a query, so the slot is certainly taken before the
	// second connection is made.
	exchangeTCP(t, first, query(t, "example.com.", wire.TypeA))

	second, err := net.Dial("tcp", addr)
	if err != nil {
		// A refused dial is also an acceptable outcome of the cap.
		return
	}
	defer second.Close()

	second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(second, make([]byte, 1)); err == nil {
		t.Error("the connection over the cap was served, want it closed")
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return // closed, which is the point
	} else if !isTimeout(err) {
		return // reset, also closed
	} else {
		t.Errorf("the connection over the cap was left open: %v", err)
	}
}

// A client that sends a length prefix and then stalls is holding a slot against
// the cap for free. The read deadline is what takes it back.
func TestTCPTimesOutAStalledMessage(t *testing.T) {
	addr := serve(t, &Server{
		Handler: answerA("192.0.2.1"),
		Timeout: 150 * time.Millisecond,
		Log:     quiet(),
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialing tcp: %v", err)
	}
	defer conn.Close()

	// Promise 100 octets, send none.
	if _, err := conn.Write([]byte{0, 100}); err != nil {
		t.Fatalf("writing the prefix: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err == nil {
		t.Error("the stalled connection was served")
	} else if isTimeout(err) {
		t.Error("the server left a stalled connection open past its read deadline")
	}
}

// A full queue drops rather than blocking the reader. Proved with one worker
// held inside the handler, so every further packet has nowhere to go.
func TestUDPDropsWhenTheQueueIsFull(t *testing.T) {
	c, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	release := make(chan struct{})
	var once sync.Once

	s := &Server{
		Workers: 1,
		Queue:   1,
		Log:     quiet(),
		Handler: HandlerFunc(func(_ context.Context, q *wire.Message, _ netip.Addr) *wire.Message {
			// Only the first query blocks; the rest run once released, so the
			// shutdown at the end of the test is not held up.
			once.Do(func() { <-release })
			return replyTo(q, wire.A{Addr: netip.MustParseAddr("192.0.2.1")})
		}),
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, c) }()

	conn := dialUDP(t, c.UDP.LocalAddr().String())
	raw, err := query(t, "example.com.", wire.TypeA).Pack()
	if err != nil {
		t.Fatalf("packing: %v", err)
	}
	// One to occupy the worker, one to fill the queue, and the rest to be
	// dropped. Sent with a pause so the reader keeps up with them.
	for range 40 {
		if _, err := conn.Write(raw); err != nil {
			t.Fatalf("writing: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	if got := s.dropped.Load(); got == 0 {
		t.Error("no packets dropped with one worker held and a queue of one")
	}

	close(release)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return within 5s")
	}
}

func TestServeRejectsAServerWithNoHandler(t *testing.T) {
	c, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	defer c.Close()

	if err := (&Server{}).Serve(context.Background(), c); err == nil {
		t.Error("Serve() = nil with no handler, want an error")
	}
}

// serve starts a server on a loopback address and returns it, stopping the
// server when the test ends.
func serve(t *testing.T, s *Server) string {
	t.Helper()

	if s.Log == nil {
		s.Log = quiet()
	}
	c, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, c) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve() did not return within 5s of cancellation")
		}
	})
	return c.UDP.LocalAddr().String()
}

func query(t *testing.T, name string, typ wire.Type) *wire.Message {
	t.Helper()

	n, err := wire.ParseName(name)
	if err != nil {
		t.Fatalf("parsing %q: %v", name, err)
	}
	return &wire.Message{
		Header:    wire.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []wire.Question{{Name: n, Type: typ, Class: wire.ClassIN}},
	}
}

// answerA is a handler that answers every question with one A record.
func answerA(addr string) Handler {
	return HandlerFunc(func(_ context.Context, q *wire.Message, _ netip.Addr) *wire.Message {
		return replyTo(q, wire.A{Addr: netip.MustParseAddr(addr)})
	})
}

// bulky is a handler whose reply does not fit in 512 octets.
func bulky() Handler {
	return HandlerFunc(func(_ context.Context, q *wire.Message, _ netip.Addr) *wire.Message {
		m := replyTo(q)
		for range 12 {
			m.Answers = append(m.Answers, wire.RR{
				Name:  q.Questions[0].Name,
				Type:  wire.TypeTXT,
				Class: wire.ClassIN,
				TTL:   300,
				Data:  wire.TXT{Strings: []string{strings.Repeat("x", 200)}},
			})
		}
		return m
	})
}

func replyTo(q *wire.Message, data ...wire.RData) *wire.Message {
	m := &wire.Message{
		Header: wire.Header{
			ID:                 q.Header.ID,
			Response:           true,
			RecursionDesired:   q.Header.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: q.Questions,
	}
	for _, d := range data {
		m.Answers = append(m.Answers, wire.RR{
			Name:  q.Questions[0].Name,
			Type:  d.Type(),
			Class: wire.ClassIN,
			TTL:   300,
			Data:  d,
		})
	}
	return m
}

func dialUDP(t *testing.T, addr string) net.Conn {
	t.Helper()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dialing udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// askUDP sends one query and decodes the reply. size is the buffer to read
// into, defaulting to 512 when zero, so a caller testing truncation reads
// exactly what a client of that size would.
func askUDP(t *testing.T, addr string, q *wire.Message, size int) *wire.Message {
	t.Helper()

	if size == 0 {
		size = 512
	}
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("packing the query: %v", err)
	}

	conn := dialUDP(t, addr)
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("writing the query: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, size)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	reply, err := wire.Unpack(buf[:n])
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	return reply
}

// exchangeTCP sends one length-prefixed query and reads the length-prefixed
// reply.
func exchangeTCP(t *testing.T, conn net.Conn, q *wire.Message) *wire.Message {
	t.Helper()

	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("packing the query: %v", err)
	}
	framed := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(framed, uint16(len(raw)))
	copy(framed[2:], raw)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(framed); err != nil {
		t.Fatalf("writing the query: %v", err)
	}

	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("reading the length prefix: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	reply, err := wire.Unpack(body)
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	return reply
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// quiet discards the server's operational logging. The tests that provoke drops
// and refusals would otherwise print warnings that read as failures.
func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The handler is told who asked, over both transports. Statistics attribute
// queries to a client with this, and per-client limiting will refuse them with
// it, so a transport that reported the wrong address or none at all would break
// both in a way neither could detect.
func TestHandlerIsToldWhoAsked(t *testing.T) {
	seen := make(chan netip.Addr, 4)
	h := HandlerFunc(func(_ context.Context, q *wire.Message, from netip.Addr) *wire.Message {
		seen <- from
		return replyTo(q, wire.A{Addr: netip.MustParseAddr("192.0.2.1")})
	})
	addr := serve(t, &Server{Handler: h})

	t.Run("udp", func(t *testing.T) {
		askUDP(t, addr, query(t, "example.com.", wire.TypeA), 512)
		assertLoopback(t, <-seen)
	})

	t.Run("tcp", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dialing tcp: %v", err)
		}
		defer conn.Close()
		exchangeTCP(t, conn, query(t, "example.com.", wire.TypeA))
		assertLoopback(t, <-seen)
	})
}

func assertLoopback(t *testing.T, got netip.Addr) {
	t.Helper()
	if !got.IsValid() {
		t.Fatal("the handler was given the zero Addr, so it cannot tell who asked")
	}
	if !got.IsLoopback() {
		t.Errorf("the handler was told the client is %v, want a loopback address", got)
	}
	// Unmapped, so a client reaching a dual-stack listener over IPv4 is that
	// IPv4 address rather than a ::ffff: form that would count as a different
	// client in a top-clients list.
	if got.Is4In6() {
		t.Errorf("the client address is %v, want it unmapped", got)
	}
}

// An address the transports do not recognise yields the zero Addr rather than a
// guess, which is what lets a handler tell "nobody told me" from "0.0.0.0".
func TestClientAddrOnAnUnknownAddressType(t *testing.T) {
	if got := clientAddr(&net.UnixAddr{Name: "/tmp/x", Net: "unix"}); got.IsValid() {
		t.Errorf("clientAddr() = %v on a unix address, want the zero Addr", got)
	}
	if got := clientAddr(nil); got.IsValid() {
		t.Errorf("clientAddr(nil) = %v, want the zero Addr", got)
	}
}
