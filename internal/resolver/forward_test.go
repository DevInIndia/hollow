package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/cache"
	"github.com/DevInIndia/hollow/internal/wire"
)

// A forwarder handler sees the whole query rather than just the question,
// because the thing that distinguishes forwarding from the iterative walk is a
// header bit and there is no way to assert it from the question alone.
type upstreamFunc func(query *wire.Message) *wire.Message

// startUpstreams binds one fake resolver per address on a shared port,
// mirroring startNet for handlers that need the header.
func startUpstreams(t *testing.T, hs map[netip.Addr]upstreamFunc) uint16 {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		port := freePort(t)
		conns := make(map[netip.Addr]net.PacketConn, len(hs))
		ok := true
		for addr := range hs {
			c, err := net.ListenPacket("udp", netip.AddrPortFrom(addr, port).String())
			if err != nil {
				ok = false
				break
			}
			conns[addr] = c
		}
		if !ok {
			for _, c := range conns {
				c.Close()
			}
			continue
		}
		for addr, c := range conns {
			t.Cleanup(func() { c.Close() })
			go serveUpstream(c, hs[addr])
		}
		return port
	}
	t.Fatal("could not bind every fake upstream on one shared port")
	return 0
}

func serveUpstream(conn net.PacketConn, h upstreamFunc) {
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query, err := wire.Unpack(buf[:n])
		if err != nil || len(query.Questions) != 1 {
			continue
		}
		reply := h(query)
		if reply == nil {
			continue // a server that hears the question and says nothing
		}
		reply.Header.ID = query.Header.ID
		reply.Header.Response = true
		reply.Header.RecursionAvailable = true
		if len(reply.Questions) == 0 {
			reply.Questions = query.Questions
		}
		out, err := reply.Pack()
		if err != nil {
			continue
		}
		conn.WriteTo(out, from)
	}
}

func ask(t *testing.T, f *Forwarder, name string) (*Result, error) {
	t.Helper()
	return f.Resolve(context.Background(), wire.Question{Name: wire.Name(name), Type: wire.TypeA, Class: wire.ClassIN})
}

func addr(t *testing.T, ip string, port uint16) netip.AddrPort {
	t.Helper()
	return netip.AddrPortFrom(netip.MustParseAddr(ip), port)
}

// The whole point of forwarding: the other end is asked to do the work, so RD
// is set. The iterative path clears it, and a forwarder that cleared it would
// be asking a recursive resolver for a referral it does not have.
func TestAForwardedQueryAsksForRecursion(t *testing.T) {
	var sawRD atomic.Bool
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			sawRD.Store(q.Header.RecursionDesired)
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	})

	f := &Forwarder{
		// RecursionDesired deliberately left false here, to prove Resolve sets
		// it rather than relying on the caller having done so.
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port)},
	}
	res, err := ask(t, f, "example.com.")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !sawRD.Load() {
		t.Error("the upstream was asked without RD, so it has no reason to resolve anything")
	}
	if got := res.Reply.Msg.Answers[0].Data.(wire.A).Addr; got != netip.MustParseAddr("93.184.216.34") {
		t.Errorf("address = %v, want the upstream's answer", got)
	}
	if res.Queries != 1 {
		t.Errorf("Queries = %d, want 1; forwarding is one exchange", res.Queries)
	}
	if res.CacheHit || res.Stale {
		t.Error("a fresh forwarded answer reported itself as cached")
	}
}

// SERVFAIL and REFUSED both mean ask the next one. This is the case that makes
// listing two forwarders worth anything.
func TestAFailingForwarderFallsThroughToTheNext(t *testing.T) {
	var asked atomic.Int64
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			asked.Add(1)
			return &wire.Message{Header: wire.Header{Rcode: wire.RcodeServFail}}
		},
		netip.MustParseAddr("127.0.0.2"): func(q *wire.Message) *wire.Message {
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port), addr(t, "127.0.0.2", port)},
	}
	res, err := ask(t, f, "example.com.")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if asked.Load() != 1 {
		t.Errorf("the failing server was asked %d times, want 1; it is not retried", asked.Load())
	}
	if res.Queries != 2 {
		t.Errorf("Queries = %d, want 2, one per server tried", res.Queries)
	}
}

// A server that never answers must not stop the next one being tried. This is
// the failure mode a home network actually produces, where the configured
// resolver is simply gone.
func TestASilentForwarderIsAbandonedForTheNext(t *testing.T) {
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message { return nil },
		netip.MustParseAddr("127.0.0.2"): func(q *wire.Message) *wire.Message {
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 200 * time.Millisecond},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port), addr(t, "127.0.0.2", port)},
	}
	if _, err := ask(t, f, "example.com."); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
}

func TestEveryForwarderFailingIsReportedAsSuch(t *testing.T) {
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			return &wire.Message{Header: wire.Header{Rcode: wire.RcodeRefused}}
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port)},
	}
	_, err := ask(t, f, "example.com.")
	if !errors.Is(err, ErrNoNameserver) {
		t.Errorf("error = %v, want it to wrap ErrNoNameserver", err)
	}
}

// NXDOMAIN is an answer, not a failure. A forwarder that fell through to the
// next server on it would ask everybody about every name that does not exist.
func TestNXDomainIsAnAnswerAndNotAFailover(t *testing.T) {
	var second atomic.Int64
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			return &wire.Message{Header: wire.Header{Rcode: wire.RcodeNXDomain}}
		},
		netip.MustParseAddr("127.0.0.2"): func(q *wire.Message) *wire.Message {
			second.Add(1)
			return answerMsg(aRR("nope.example.", "203.0.113.1"))
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port), addr(t, "127.0.0.2", port)},
	}
	res, err := ask(t, f, "nope.example.")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if res.Reply.Msg.Header.Rcode != wire.RcodeNXDomain {
		t.Errorf("rcode = %d, want NXDOMAIN passed through", res.Reply.Msg.Header.Rcode)
	}
	if second.Load() != 0 {
		t.Error("the second forwarder was asked about a name the first said does not exist")
	}
}

func TestAForwarderWithNoServersSaysSo(t *testing.T) {
	_, err := ask(t, &Forwarder{}, "example.com.")
	if !errors.Is(err, ErrNoForwarder) {
		t.Errorf("error = %v, want ErrNoForwarder", err)
	}
}

// The cache is shared with the recursive path and works the same way here: the
// second query for a name costs no exchange at all.
func TestAForwardedAnswerIsCached(t *testing.T) {
	var asked atomic.Int64
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			asked.Add(1)
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port)},
		Cache:     cache.New(cache.Config{}),
	}
	if _, err := ask(t, f, "example.com."); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	res, err := ask(t, f, "example.com.")
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if asked.Load() != 1 {
		t.Errorf("the upstream was asked %d times, want 1", asked.Load())
	}
	if !res.CacheHit || res.Queries != 0 {
		t.Errorf("second answer: CacheHit %v, Queries %d; want true and 0", res.CacheHit, res.Queries)
	}
	if res.Reply.Protocol != ProtocolCache {
		t.Errorf("Protocol = %q, want %q", res.Reply.Protocol, ProtocolCache)
	}
}

// Serve-stale matters more in forwarding mode than in the walk: when the only
// route off this network is the forwarder and the forwarder is down, an expired
// answer is the only answer there is. Real sockets rule out a fake clock, so
// the TTL is squeezed to one second.
func TestAnExpiredAnswerIsServedWhenEveryForwarderIsDown(t *testing.T) {
	var down atomic.Bool
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			if down.Load() {
				return &wire.Message{Header: wire.Header{Rcode: wire.RcodeServFail}}
			}
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port)},
		Cache:     cache.New(cache.Config{MaxTTL: 1, StaleFor: time.Hour}),
	}
	if _, err := ask(t, f, "example.com."); err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	down.Store(true)

	res, err := ask(t, f, "example.com.")
	if err != nil {
		t.Fatalf("Resolve() error = %v, want the stale answer", err)
	}
	if !res.Stale || !res.CacheHit {
		t.Errorf("Stale %v, CacheHit %v; want both true", res.Stale, res.CacheHit)
	}
	if got := res.Reply.Msg.Answers[0].Data.(wire.A).Addr; got != netip.MustParseAddr("93.184.216.34") {
		t.Errorf("stale address = %v, want the last known answer", got)
	}
}

// A cancelled context is the client leaving, not the server failing. Trying the
// next forwarder would ignore a deadline that has already passed and report the
// wrong cause.
func TestACancelledContextStopsAtTheFirstForwarder(t *testing.T) {
	var asked atomic.Int64
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			asked.Add(1)
			return nil
		},
		netip.MustParseAddr("127.0.0.2"): func(q *wire.Message) *wire.Message {
			asked.Add(1)
			return nil
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port), addr(t, "127.0.0.2", port)},
		Cache:     cache.New(cache.Config{StaleFor: time.Hour}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := f.Resolve(ctx, wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if err == nil {
		t.Fatal("Resolve() returned no error after its context expired")
	}
	if asked.Load() != 1 {
		t.Errorf("%d servers were asked, want 1; the context had already gone", asked.Load())
	}
}

// The class defaults the same way Resolve does, so a caller that built a
// Question without one gets IN rather than a query for class zero.
func TestAQuestionWithNoClassIsInternet(t *testing.T) {
	var got atomic.Uint32
	port := startUpstreams(t, map[netip.Addr]upstreamFunc{
		netip.MustParseAddr("127.0.0.1"): func(q *wire.Message) *wire.Message {
			got.Store(uint32(q.Questions[0].Class))
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	})

	f := &Forwarder{
		Transport: Transport{Timeout: 2 * time.Second},
		Servers:   []netip.AddrPort{addr(t, "127.0.0.1", port)},
	}
	if _, err := f.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA}); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got.Load() != uint32(wire.ClassIN) {
		t.Errorf("class on the wire = %d, want %d", got.Load(), wire.ClassIN)
	}
}
