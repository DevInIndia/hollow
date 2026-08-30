package cli

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/wire"
)

// The claim coalescing makes, at the level a client actually meets it: a
// hundred clients asking for one cold name at the same instant cause one
// resolution, not a hundred.
//
// The cache cannot make this claim. Nothing is cached until the first walk
// finishes, and all hundred of these arrive before it does, so this test runs
// with no cache at all. That is deliberate: it isolates the thing being
// measured. If a cache were attached, a passing test would not distinguish
// coalescing from a lucky interleaving that let the cache fill early.
func TestConcurrentIdenticalQueriesResolveOnce(t *testing.T) {
	const clients = 100

	var exchanges atomic.Int64
	var queued atomic.Bool
	rc := &recursor{log: discard()}

	// The upstream holds its answer until every other client has queued behind
	// the one that went to get it. Answering immediately would let the first
	// resolution finish before the hundredth client had even called ServeDNS,
	// and the hundredth would then correctly start a second walk: real
	// behaviour that looks exactly like a coalescing failure.
	//
	// The wait is bounded rather than unbounded, because if coalescing is
	// broken the other queries pile up behind this handler in the socket
	// buffer and never register as waiters. Giving up and answering turns that
	// deadlock into the assertion failure it should be.
	answer := func(q wire.Question) *wire.Message {
		exchanges.Add(1)
		queued.Store(awaitWaiting(rc, clients-1))
		return &wire.Message{
			Header: wire.Header{Authoritative: true},
			Answers: []wire.RR{{
				Name: q.Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
				Data: wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
			}},
		}
	}
	rc.resolver = oneServerResolver(t, answer)

	name := wire.Name("example.com.")
	var wg sync.WaitGroup
	replies := make([]*wire.Message, clients)
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each client brings its own message, carrying its own ID, because
			// the reply has to echo the asker rather than the leader.
			query := &wire.Message{
				Header:    wire.Header{ID: uint16(i + 1), RecursionDesired: true},
				Questions: []wire.Question{{Name: name, Type: wire.TypeA, Class: wire.ClassIN}},
			}
			replies[i] = rc.ServeDNS(context.Background(), query, testClient)
		}()
	}
	wg.Wait()

	// Asserted before the exchange count, because without the barrier that
	// count proves nothing: one resolution finishing before the others arrived
	// would also report one exchange, for a reason that has nothing to do with
	// coalescing.
	if !queued.Load() {
		t.Fatalf("only some of the %d clients ever queued behind the resolution", clients)
	}
	if n := exchanges.Load(); n != 1 {
		t.Errorf("%d clients caused %d upstream exchanges, want 1", clients, n)
	}
	for i, reply := range replies {
		switch {
		case reply == nil:
			t.Fatalf("client %d got no reply", i)
		case reply.Header.ID != uint16(i+1):
			t.Errorf("client %d got a reply carrying id %d", i, reply.Header.ID)
		case reply.Header.Rcode != wire.RcodeSuccess:
			t.Errorf("client %d got rcode %d, want success", i, reply.Header.Rcode)
		case len(reply.Answers) != 1:
			t.Errorf("client %d got %d answers, want 1", i, len(reply.Answers))
		}
	}
	if rc.inflight.Len() != 0 {
		t.Errorf("%d calls still registered after every client was answered", rc.inflight.Len())
	}
}

// Two different names must not wait on each other. A group that serialised on
// the wrong thing would still pass the test above, because one call collapsing
// into one call is what that test asks for.
func TestDifferentNamesDoNotWaitOnEachOther(t *testing.T) {
	// Both handlers block until the other has been reached, so a resolver that
	// let one name's walk hold up another's would hang here rather than fail an
	// assertion. Bounded, so a failure is reported rather than waited out.
	reached := make(chan struct{}, 2)
	both := make(chan struct{})
	var once sync.Once

	rc := &recursor{log: discard()}
	rc.resolver = oneServerResolver(t, func(q wire.Question) *wire.Message {
		reached <- struct{}{}
		if len(reached) == 2 {
			once.Do(func() { close(both) })
		}
		select {
		case <-both:
		case <-time.After(5 * time.Second):
		}
		return &wire.Message{
			Header: wire.Header{Authoritative: true},
			Answers: []wire.RR{{
				Name: q.Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
				Data: wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
			}},
		}
	})

	var wg sync.WaitGroup
	for i, host := range []string{"a.example.com.", "b.example.com."} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			query := &wire.Message{
				Header:    wire.Header{ID: uint16(i + 1), RecursionDesired: true},
				Questions: []wire.Question{{Name: wire.Name(host), Type: wire.TypeA, Class: wire.ClassIN}},
			}
			if reply := rc.ServeDNS(context.Background(), query, testClient); reply.Header.Rcode != wire.RcodeSuccess {
				t.Errorf("%s got rcode %d, want success", host, reply.Header.Rcode)
			}
		}()
	}
	wg.Wait()

	select {
	case <-both:
	default:
		t.Error("the two names were never in flight at once, so they were serialised")
	}
}

// Two clients spelling one name differently share a walk. The key is folded,
// and each client still gets a reply echoing the question it asked.
func TestCaseVariantsShareOneResolution(t *testing.T) {
	var exchanges atomic.Int64
	rc := &recursor{log: discard()}
	rc.resolver = oneServerResolver(t, func(q wire.Question) *wire.Message {
		exchanges.Add(1)
		awaitWaiting(rc, 1)
		return &wire.Message{
			Header: wire.Header{Authoritative: true},
			Answers: []wire.RR{{
				Name: q.Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
				Data: wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
			}},
		}
	})

	spellings := []string{"Example.COM.", "eXaMpLe.com."}
	var wg sync.WaitGroup
	got := make([]wire.Name, len(spellings))
	for i, spelling := range spellings {
		wg.Add(1)
		go func() {
			defer wg.Done()
			query := &wire.Message{
				Header:    wire.Header{ID: uint16(i + 1), RecursionDesired: true},
				Questions: []wire.Question{{Name: wire.Name(spelling), Type: wire.TypeA, Class: wire.ClassIN}},
			}
			reply := rc.ServeDNS(context.Background(), query, testClient)
			if len(reply.Questions) == 1 {
				got[i] = reply.Questions[0].Name
			}
		}()
	}
	wg.Wait()

	if n := exchanges.Load(); n != 1 {
		t.Errorf("two spellings of one name caused %d exchanges, want 1", n)
	}
	for i, spelling := range spellings {
		if string(got[i]) != spelling {
			t.Errorf("client %d asked %q and was answered for %q", i, spelling, got[i])
		}
	}
}

// awaitWaiting blocks until at least n callers are queued behind an in-flight
// resolution, and reports whether they arrived. It runs on the goroutine that
// owns the call, so it cannot fail the test itself; the caller asserts on the
// exchange count instead.
func awaitWaiting(rc *recursor, n int) bool {
	for range 2000 {
		if rc.inflight.Waiting() >= n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// oneServerResolver points a resolver at a single fake nameserver on loopback
// that answers everything authoritatively. One server is enough here: these
// tests are about how many times the resolver is entered, not about the walk.
func oneServerResolver(t *testing.T, h func(wire.Question) *wire.Message) *resolver.Resolver {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	go func() {
		for {
			// A fresh buffer per read. The handler below runs on its own
			// goroutine and outlives this iteration, and an unpacked message
			// can still point into the bytes it came from.
			buf := make([]byte, 4096)
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := wire.Unpack(buf[:n])
			if err != nil || len(query.Questions) != 1 {
				continue
			}
			// Handled on its own goroutine so that one blocked answer does not
			// stop this server hearing the next question. A serial loop would
			// make "these two names overlapped" untestable.
			go func(query *wire.Message, from net.Addr) {
				reply := h(query.Questions[0])
				reply.Header.ID = query.Header.ID
				reply.Header.Response = true
				reply.Questions = query.Questions
				out, err := reply.Pack()
				if err != nil {
					return
				}
				conn.WriteTo(out, from)
			}(query, from)
		}
	}()

	return &resolver.Resolver{
		Transport: resolver.Transport{Timeout: 10 * time.Second},
		Hints:     []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
		Port:      port,
		Shuffle:   func(n int, swap func(i, j int)) {},
	}
}
