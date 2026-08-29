package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

// handler answers one query. It returns the datagrams to send back, so a test
// can answer twice, or not at all, as easily as once. proto is "udp" or "tcp",
// which is how the truncation tests give the two transports different answers.
type handler func(t *testing.T, query []byte, proto string) [][]byte

// serve starts a DNS server on loopback speaking both UDP and TCP on one port,
// and returns its address. Both listeners close when the test ends.
func serve(t *testing.T, h handler) netip.AddrPort {
	t.Helper()

	pc, ln := listenBoth(t)
	t.Cleanup(func() {
		pc.Close()
		ln.Close()
	})

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("parsing the listener address: %v", err)
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return // the listener closed
			}
			query := append([]byte(nil), buf[:n]...)
			for _, out := range h(t, query, "udp") {
				if _, err := pc.WriteTo(out, from); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTCP(t, h, conn)
		}
	}()

	return addr
}

func serveTCP(t *testing.T, h handler, conn net.Conn) {
	defer conn.Close()
	for {
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		for _, out := range h(t, query, "tcp") {
			framed := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(framed, uint16(len(out)))
			copy(framed[2:], out)
			if _, err := conn.Write(framed); err != nil {
				return
			}
		}
	}
}

// listenBoth binds UDP and TCP to the same loopback port. The port comes from
// the kernel by way of the UDP bind, so TCP can lose a race against an
// unrelated process; retrying is cheaper than reserving a fixed port and
// flaking when two runs of the suite overlap.
func listenBoth(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for range 10 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("binding udp: %v", err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln
		}
		pc.Close()
	}
	t.Fatal("could not bind the same port on udp and tcp after ten attempts")
	return nil, nil
}

// answer builds a well-formed reply to query, then hands it to fix so a test
// can break it in the one specific way it is about.
func answer(t *testing.T, query []byte, fix func(*wire.Message)) []byte {
	t.Helper()

	q, err := wire.Unpack(query)
	if err != nil {
		t.Errorf("the server could not decode the query: %v", err)
		return nil
	}
	m := &wire.Message{
		Header: wire.Header{
			ID:                 q.Header.ID,
			Response:           true,
			RecursionAvailable: true,
		},
		Questions: q.Questions,
		Answers: []wire.RR{{
			Name:  q.Questions[0].Name,
			Type:  wire.TypeA,
			Class: wire.ClassIN,
			TTL:   300,
			Data:  wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
		}},
	}
	m.SetEDNS(wire.EDNS{UDPSize: wire.DefaultUDPSize})
	if fix != nil {
		fix(m)
	}
	buf, err := m.Pack()
	if err != nil {
		t.Errorf("the server could not encode its reply: %v", err)
		return nil
	}
	return buf
}

// plain answers every query correctly over either protocol.
func plain(t *testing.T, query []byte, _ string) [][]byte {
	return [][]byte{answer(t, query, nil)}
}

func exampleCom() wire.Question {
	return wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN}
}

func TestExchangeOverUDP(t *testing.T) {
	addr := serve(t, plain)

	tr := &Transport{Timeout: 2 * time.Second}
	reply, err := tr.Exchange(t.Context(), addr, exampleCom())
	if err != nil {
		t.Fatalf("Exchange() = %v", err)
	}

	if reply.Protocol != "udp" {
		t.Errorf("Protocol = %q, want udp", reply.Protocol)
	}
	if reply.Server != addr {
		t.Errorf("Server = %v, want %v", reply.Server, addr)
	}
	if reply.Size <= 0 {
		t.Errorf("Size = %d, want the length of the reply", reply.Size)
	}
	if reply.RTT <= 0 {
		t.Errorf("RTT = %v, want a positive duration", reply.RTT)
	}
	if got := len(reply.Msg.Answers); got != 1 {
		t.Fatalf("got %d answers, want 1", got)
	}
	if got, ok := reply.Msg.Answers[0].Data.(wire.A); !ok || got.Addr.String() != "192.0.2.1" {
		t.Errorf("answer rdata = %#v, want the A record the server sent", reply.Msg.Answers[0].Data)
	}
}

// The query is as much of the protocol as the reply, and nothing else in the
// suite would notice if the RD bit or the OPT record went missing.
func TestExchangeQueryShape(t *testing.T) {
	queries := make(chan []byte, 4)
	addr := serve(t, func(t *testing.T, query []byte, proto string) [][]byte {
		queries <- query
		return plain(t, query, proto)
	})

	tr := &Transport{Timeout: 2 * time.Second, RecursionDesired: true}
	var ids []uint16
	for range 2 {
		if _, err := tr.Exchange(t.Context(), addr, exampleCom()); err != nil {
			t.Fatalf("Exchange() = %v", err)
		}
		m, err := wire.Unpack(<-queries)
		if err != nil {
			t.Fatalf("decoding the query the server saw: %v", err)
		}

		if m.Header.Response {
			t.Error("query has the response bit set")
		}
		if !m.Header.RecursionDesired {
			t.Error("query has RD clear despite RecursionDesired")
		}
		if got := len(m.Questions); got != 1 {
			t.Fatalf("query carries %d questions, want 1", got)
		}
		if got := m.Questions[0]; got != exampleCom() {
			t.Errorf("question = %+v, want %+v", got, exampleCom())
		}
		e, ok, err := m.EDNS()
		if err != nil || !ok {
			t.Fatalf("query carries no usable OPT record: ok=%v err=%v", ok, err)
		}
		if e.UDPSize != wire.DefaultUDPSize {
			t.Errorf("advertised udp size = %d, want %d", e.UDPSize, wire.DefaultUDPSize)
		}
		ids = append(ids, m.Header.ID)
	}

	// Not a randomness test, which two samples cannot be. It catches the ID
	// being computed once and reused, which would make every query after the
	// first forgeable by anyone who saw the one before it.
	if ids[0] == ids[1] {
		t.Errorf("two queries share transaction id %#04x", ids[0])
	}
}

func TestExchangeFallsBackToTCP(t *testing.T) {
	addr := serve(t, func(t *testing.T, query []byte, proto string) [][]byte {
		if proto == "udp" {
			// What a real server sends when the answer will not fit: the TC bit
			// and nothing worth having.
			return [][]byte{answer(t, query, func(m *wire.Message) {
				m.Header.Truncated = true
				m.Answers = nil
			})}
		}
		return plain(t, query, proto)
	})

	tr := &Transport{Timeout: 2 * time.Second}
	reply, err := tr.Exchange(t.Context(), addr, exampleCom())
	if err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if reply.Protocol != "tcp" {
		t.Fatalf("Protocol = %q, want tcp after a truncated reply", reply.Protocol)
	}
	if got := len(reply.Msg.Answers); got != 1 {
		t.Errorf("got %d answers over tcp, want the 1 that did not fit in udp", got)
	}
}

func TestExchangeForceTCP(t *testing.T) {
	var overUDP bool
	addr := serve(t, func(t *testing.T, query []byte, proto string) [][]byte {
		if proto == "udp" {
			overUDP = true
		}
		return plain(t, query, proto)
	})

	tr := &Transport{Timeout: 2 * time.Second, ForceTCP: true}
	reply, err := tr.Exchange(t.Context(), addr, exampleCom())
	if err != nil {
		t.Fatalf("Exchange() = %v", err)
	}
	if reply.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", reply.Protocol)
	}
	if overUDP {
		t.Error("ForceTCP still sent a datagram over udp")
	}
}

// A reply that does not match the query is what an injected packet looks like,
// so the exchange must keep listening rather than take it or give up.
func TestExchangeIgnoresMismatchedReplies(t *testing.T) {
	tests := map[string]func(*wire.Message){
		"wrong transaction id": func(m *wire.Message) { m.Header.ID++ },
		"query bit clear":      func(m *wire.Message) { m.Header.Response = false },
		"wrong opcode":         func(m *wire.Message) { m.Header.Opcode = 4 },
		"wrong question name": func(m *wire.Message) {
			m.Questions[0].Name = "attacker.example."
		},
		"wrong question type": func(m *wire.Message) {
			m.Questions[0].Type = wire.TypeMX
		},
		"no question echoed": func(m *wire.Message) { m.Questions = nil },
	}

	for name, spoof := range tests {
		t.Run(name, func(t *testing.T) {
			addr := serve(t, func(t *testing.T, query []byte, proto string) [][]byte {
				return [][]byte{
					answer(t, query, spoof),
					answer(t, query, nil),
				}
			})

			tr := &Transport{Timeout: 2 * time.Second}
			reply, err := tr.Exchange(t.Context(), addr, exampleCom())
			if err != nil {
				t.Fatalf("Exchange() = %v, want the second reply to be accepted", err)
			}
			if got := len(reply.Msg.Answers); got != 1 {
				t.Errorf("got %d answers, want the 1 from the matching reply", got)
			}
		})
	}
}

// The same mismatch on TCP is the server being wrong, not someone else talking,
// and there is no second reply coming on a stream we opened.
func TestExchangeRejectsMismatchOverTCP(t *testing.T) {
	addr := serve(t, func(t *testing.T, query []byte, _ string) [][]byte {
		return [][]byte{answer(t, query, func(m *wire.Message) { m.Header.ID++ })}
	})

	tr := &Transport{Timeout: 2 * time.Second, ForceTCP: true}
	if _, err := tr.Exchange(t.Context(), addr, exampleCom()); err == nil {
		t.Fatal("Exchange() = nil, want an error for a reply with the wrong id")
	} else if !strings.Contains(err.Error(), "transaction id") {
		t.Errorf("Exchange() = %v, want the error to name the transaction id", err)
	}
}

// A server that only ever answers unusably is reported as broken rather than as
// silent, so the reason survives the deadline.
func TestExchangeReportsUnusableReply(t *testing.T) {
	addr := serve(t, func(t *testing.T, _ []byte, _ string) [][]byte {
		return [][]byte{{0x00, 0x01, 0x02}} // shorter than a header
	})

	tr := &Transport{Timeout: 300 * time.Millisecond}
	_, err := tr.Exchange(t.Context(), addr, exampleCom())
	if !errors.Is(err, wire.ErrTruncated) {
		t.Fatalf("Exchange() = %v, want it to carry wire.ErrTruncated", err)
	}
	if errors.Is(err, ErrNoReply) {
		t.Error("a server that replied badly was reported as one that did not reply")
	}
}

func TestExchangeSilentServer(t *testing.T) {
	addr := serve(t, func(*testing.T, []byte, string) [][]byte { return nil })

	tr := &Transport{Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := tr.Exchange(t.Context(), addr, exampleCom())
	if !errors.Is(err, ErrNoReply) {
		t.Fatalf("Exchange() = %v, want ErrNoReply", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Exchange() took %v to give up on a 200ms timeout", elapsed)
	}
}

// A server that ignores the advertised payload size gets its reply discarded.
// The alternative is parsing whatever survived the kernel's truncation, which
// is a decode error that names the wrong cause.
func TestExchangeOversizedReply(t *testing.T) {
	addr := serve(t, func(t *testing.T, query []byte, _ string) [][]byte {
		return [][]byte{answer(t, query, func(m *wire.Message) {
			for range 4 {
				m.Answers = append(m.Answers, wire.RR{
					Name:  m.Questions[0].Name,
					Type:  wire.TypeTXT,
					Class: wire.ClassIN,
					TTL:   300,
					Data:  wire.TXT{Strings: []string{strings.Repeat("x", 255)}},
				})
			}
		})}
	})

	tr := &Transport{Timeout: time.Second, UDPSize: 512}
	if _, err := tr.Exchange(t.Context(), addr, exampleCom()); !errors.Is(err, ErrOversized) {
		t.Fatalf("Exchange() = %v, want ErrOversized", err)
	}
}

func TestExchangeHonoursCancellation(t *testing.T) {
	addr := serve(t, func(*testing.T, []byte, string) [][]byte { return nil })

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)

	// A timeout long enough that returning on it instead of on the cancel would
	// be unmistakable.
	tr := &Transport{Timeout: 30 * time.Second}
	start := time.Now()
	_, err := tr.Exchange(ctx, addr, exampleCom())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange() = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Exchange() took %v to notice a cancelled context", elapsed)
	}
}

// A TCP peer that announces a length and then hangs up is a distinct failure
// from one that says nothing, and io.ReadFull is what draws the line.
func TestExchangeTCPTruncatedStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding tcp: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Drain the query first. Closing a socket that still holds unread data
		// sends a reset rather than a FIN, and the client would see the
		// connection torn down instead of the short read this is about.
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, binary.BigEndian.Uint16(prefix[:]))); err != nil {
			return
		}

		conn.Write([]byte{0x01, 0x00, 0xab, 0xcd}) // 256 octets promised, two sent
	}()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the listener address: %v", err)
	}

	tr := &Transport{Timeout: time.Second, ForceTCP: true}
	if _, err := tr.Exchange(t.Context(), addr, exampleCom()); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Exchange() = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestExchangeRejectsInvalidServer(t *testing.T) {
	tr := &Transport{}
	if _, err := tr.Exchange(t.Context(), netip.AddrPort{}, exampleCom()); err == nil {
		t.Fatal("Exchange() = nil, want an error for the zero address")
	}
}

func TestUDPSizeFloor(t *testing.T) {
	tests := map[uint16]uint16{
		0:    wire.DefaultUDPSize,
		511:  wire.DefaultUDPSize,
		512:  512,
		4096: 4096,
	}
	for in, want := range tests {
		if got := (&Transport{UDPSize: in}).udpSize(); got != want {
			t.Errorf("udpSize(%d) = %d, want %d", in, got, want)
		}
	}
}

// The two tests below run inside a synctest bubble, where the time package uses
// a fake clock that advances only when every goroutine is durably blocked. That
// makes a deadline assertion exact rather than a tolerance window.
//
// The bubble cannot be pushed further up. A goroutine parked in a read on a real
// socket can be woken by a packet from outside the bubble, so it is not durably
// blocked, the clock never advances and the test hangs. Verified: wrapping
// TestExchangeHonoursCancellation in synctest.Test times out rather than
// failing. net.Pipe blocks on channels created inside the bubble, which is why
// it works here and a UDP socket does not.

func TestWatchUnblocksOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stop := watch(ctx, conn)
		defer stop()

		read := make(chan error, 1)
		go func() {
			_, err := conn.Read(make([]byte, 1))
			read <- err
		}()

		// Returns once the read is parked, so the cancel below is unambiguously
		// interrupting a blocked read rather than racing to get there first.
		synctest.Wait()

		cancel()
		if err := <-read; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read() = %v, want the read to be unblocked by the cancel", err)
		}
	})
}

func TestWatchUnblocksOnDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn, peer := net.Pipe()
		defer conn.Close()
		defer peer.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stop := watch(ctx, conn)
		defer stop()

		start := time.Now()
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read() = %v, want a deadline error", err)
		}
		// Exactly, not approximately. The context's deadline is the socket's.
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("the read unblocked after %v, want 3s", got)
		}
	})
}

// The defect this pins: the context's timer and the socket deadline derived from
// it expire at the same instant and race, so a read can report a timeout a
// moment before ctx.Err() is set. Whichever wins, the caller must see the same
// error. Reproducing the race takes go test -count and luck; calling failure
// with each outcome takes neither.
func TestFailureDoesNotDependOnWhichTimerWon(t *testing.T) {
	server := netip.MustParseAddrPort("192.0.2.53:53")

	expired, cancelExpired := context.WithTimeout(context.Background(), 0)
	defer cancelExpired()
	<-expired.Done()

	live, cancelLive := context.WithTimeout(context.Background(), time.Hour)
	defer cancelLive()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := map[string]struct {
		ctx  context.Context
		err  error
		want error
	}{
		// The socket noticed the deadline; the context has not caught up.
		"socket first":  {live, os.ErrDeadlineExceeded, ErrNoReply},
		"context first": {expired, os.ErrDeadlineExceeded, ErrNoReply},
		// A cancel sets ctx.Err() before it wakes anything, so there is no race
		// here and the caller gets its own error back rather than ErrNoReply.
		"cancelled":  {cancelled, os.ErrDeadlineExceeded, context.Canceled},
		"other read": {live, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := failure(tc.ctx, tc.err, server, "udp", "reading the reply"); !errors.Is(got, tc.want) {
				t.Errorf("failure() = %v, want it to carry %v", got, tc.want)
			}
		})
	}
}
