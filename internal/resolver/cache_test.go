package resolver

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/cache"
	"github.com/DevInIndia/hollow/internal/wire"
)

// counted wraps a zone so a test can assert which servers were spared, which is
// the only direct evidence that a cached delegation shortened the walk.
func counted(n *atomic.Int64, f zoneFunc) zoneFunc {
	return func(q wire.Question) *wire.Message {
		n.Add(1)
		return f(q)
	}
}

// hostZones is threeZones with an example.com server that answers for any host
// under the zone, so that two sibling names can be resolved.
func hostZones(root, tld, auth *atomic.Int64) map[netip.Addr]zoneFunc {
	return map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): counted(root, func(q wire.Question) *wire.Message {
			return referral("com.", "a.gtld-servers.test.", "127.0.0.2")
		}),
		netip.MustParseAddr("127.0.0.2"): counted(tld, func(q wire.Question) *wire.Message {
			return referral("example.com.", "ns1.example.com.", "127.0.0.3")
		}),
		netip.MustParseAddr("127.0.0.3"): counted(auth, func(q wire.Question) *wire.Message {
			if q.Name == "nope.example.com." {
				m := &wire.Message{Header: wire.Header{Authoritative: true, Rcode: wire.RcodeNXDomain}}
				m.Authority = []wire.RR{soaRR("example.com.")}
				return m
			}
			return answerMsg(aRR(q.Name.String(), "93.184.216.34"))
		}),
	}
}

func TestRepeatQueryIsAnsweredFromCache(t *testing.T) {
	var root, tld, auth atomic.Int64
	r := testResolver(t, hostZones(&root, &tld, &auth))
	r.Cache = cache.New(cache.Config{})

	first := mustResolve(t, r, "example.com.", wire.TypeA)
	if first.Queries != 3 {
		t.Fatalf("cold resolution cost %d queries, want 3", first.Queries)
	}
	if first.CacheHit {
		t.Error("a cold resolution reported a cache hit")
	}

	second := mustResolve(t, r, "example.com.", wire.TypeA)
	if second.Queries != 0 {
		t.Errorf("repeat resolution cost %d queries, want 0", second.Queries)
	}
	if !second.CacheHit {
		t.Error("repeat resolution did not report a cache hit")
	}
	if second.Stale {
		t.Error("a fresh cache hit was reported as stale")
	}
	if second.Reply.Protocol != ProtocolCache {
		t.Errorf("protocol = %q, want %q", second.Reply.Protocol, ProtocolCache)
	}
	if got := second.Reply.Msg.Answers[0].Data.(wire.A).Addr; got != netip.MustParseAddr("93.184.216.34") {
		t.Errorf("cached address = %v, want 93.184.216.34", got)
	}
	if n := root.Load() + tld.Load() + auth.Load(); n != 3 {
		t.Errorf("servers were asked %d times in total, want 3: the repeat went to the network", n)
	}
}

// This is the half of caching that distinguishes names rather than repeats. The
// second name has never been seen, so no answer is cached for it, and the only
// thing that can shorten its walk is the remembered zone cut.
func TestSiblingNameResumesFromTheCachedCut(t *testing.T) {
	var root, tld, auth atomic.Int64
	r := testResolver(t, hostZones(&root, &tld, &auth))
	r.Cache = cache.New(cache.Config{})

	mustResolve(t, r, "a.example.com.", wire.TypeA)
	if root.Load() != 1 || tld.Load() != 1 {
		t.Fatalf("cold walk asked root %d times and com %d, want 1 each", root.Load(), tld.Load())
	}

	second := mustResolve(t, r, "b.example.com.", wire.TypeA)
	if second.Queries != 1 {
		t.Errorf("sibling cost %d queries, want 1: the walk did not resume at example.com", second.Queries)
	}
	if second.CacheHit {
		t.Error("a resolution that still had to ask a server reported a cache hit")
	}
	if root.Load() != 1 {
		t.Errorf("the root was asked %d times, want 1: the sibling walked from the top again", root.Load())
	}
	if tld.Load() != 1 {
		t.Errorf("com was asked %d times, want 1", tld.Load())
	}
	if got := second.Reply.Msg.Answers[0].Name; got != "b.example.com." {
		t.Errorf("answer is for %q, want b.example.com.", got)
	}
	if n := r.Cache.Stats().Delegations; n != 2 {
		t.Errorf("cached %d delegations, want 2 for com. and example.com.", n)
	}
}

// A cached cut is a claim about where a zone lives, and zones move. When the
// shortcut fails the resolver has to start over from the root, or a single
// stale delegation becomes a hard failure for the whole subtree.
func TestStaleDelegationFallsBackToTheRoot(t *testing.T) {
	var root, tld, auth atomic.Int64
	zones := hostZones(&root, &tld, &auth)
	r := testResolver(t, zones)
	r.Cache = cache.New(cache.Config{})

	// 127.0.0.99 is bound by nobody, so the walk from this cut fails fast with
	// a refused datagram rather than a timeout.
	dead := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.99"), r.Hints[0].Port())
	r.Cache.StoreDelegation("example.com.", []netip.AddrPort{dead}, 3600)

	res := mustResolve(t, r, "www.example.com.", wire.TypeA)
	if res.Reply.Server.Addr() != netip.MustParseAddr("127.0.0.3") {
		t.Errorf("answered by %v, want the real example.com server", res.Reply.Server)
	}
	if root.Load() != 1 {
		t.Errorf("the root was asked %d times, want 1: the retry never happened", root.Load())
	}
}

// The fallback must not paper over a failure that was never the shortcut's
// fault, and it must not double every failing resolution into an unbounded
// retry. A walk that starts at the root has no shortcut to blame.
func TestFailureFromTheRootIsNotRetried(t *testing.T) {
	var asked atomic.Int64
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): counted(&asked, func(q wire.Question) *wire.Message {
			return &wire.Message{Header: wire.Header{Rcode: wire.RcodeServFail}}
		}),
	}
	r := testResolver(t, zones)
	r.Cache = cache.New(cache.Config{})

	if _, err := r.Resolve(context.Background(), wire.Question{
		Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN,
	}); err == nil {
		t.Fatal("Resolve() succeeded against a server that only answers SERVFAIL")
	}
	if asked.Load() != 1 {
		t.Errorf("the root was asked %d times, want 1: a rootless failure was retried anyway", asked.Load())
	}
}

func TestNegativeAnswersAreCached(t *testing.T) {
	var root, tld, auth atomic.Int64
	r := testResolver(t, hostZones(&root, &tld, &auth))
	r.Cache = cache.New(cache.Config{})

	q := wire.Question{Name: "nope.example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	first, err := r.Resolve(context.Background(), q)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if first.Reply.Msg.Header.Rcode != wire.RcodeNXDomain {
		t.Fatalf("rcode = %d, want NXDOMAIN", first.Reply.Msg.Header.Rcode)
	}

	before := auth.Load()
	second, err := r.Resolve(context.Background(), q)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !second.CacheHit || second.Queries != 0 {
		t.Errorf("repeat NXDOMAIN cost %d queries with hit=%v, want 0 and true", second.Queries, second.CacheHit)
	}
	if auth.Load() != before {
		t.Error("the repeat NXDOMAIN went back to the authoritative server")
	}
	// The SOA is what proved the denial, and a client doing its own negative
	// caching needs it replayed.
	if len(second.Reply.Msg.Authority) != 1 || second.Reply.Msg.Authority[0].Type != wire.TypeSOA {
		t.Errorf("cached denial replayed authority %v, want one SOA", second.Reply.Msg.Authority)
	}
}

// Serve-stale, RFC 8767: the answer has expired and the network has gone away,
// so the last known answer beats no answer. Real sockets rule out a fake clock,
// so the TTL is squeezed to one second instead.
func TestExpiredAnswerIsServedWhenResolutionFails(t *testing.T) {
	var down atomic.Bool
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			if down.Load() {
				return &wire.Message{Header: wire.Header{Rcode: wire.RcodeServFail}}
			}
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	}
	r := testResolver(t, zones)
	r.Cache = cache.New(cache.Config{MaxTTL: 1, StaleFor: time.Hour})

	mustResolve(t, r, "example.com.", wire.TypeA)
	time.Sleep(1100 * time.Millisecond)
	down.Store(true)

	res := mustResolve(t, r, "example.com.", wire.TypeA)
	if !res.Stale {
		t.Fatal("resolution failed and an expired entry was held, but nothing was served stale")
	}
	if !res.CacheHit {
		t.Error("a stale answer did not report a cache hit")
	}
	if got := res.Reply.Msg.Answers[0].Data.(wire.A).Addr; got != netip.MustParseAddr("93.184.216.34") {
		t.Errorf("stale address = %v, want the last known answer", got)
	}
	// Never zero: a zero TTL tells every client not to reuse the answer, which
	// turns one upstream failure into a storm.
	if ttl := res.Reply.Msg.Answers[0].TTL; ttl != 30 {
		t.Errorf("stale TTL = %d, want 30", ttl)
	}
}

func TestServeStaleOffMeansTheFailureIsReported(t *testing.T) {
	var down atomic.Bool
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			if down.Load() {
				return &wire.Message{Header: wire.Header{Rcode: wire.RcodeServFail}}
			}
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	}
	r := testResolver(t, zones)
	r.Cache = cache.New(cache.Config{MaxTTL: 1}) // StaleFor unset

	mustResolve(t, r, "example.com.", wire.TypeA)
	time.Sleep(1100 * time.Millisecond)
	down.Store(true)

	if _, err := r.Resolve(context.Background(), wire.Question{
		Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN,
	}); err == nil {
		t.Error("Resolve() served a stale answer with serve-stale disabled")
	}
}

// A caller that gave up is not a resolution failure, and answering one from the
// stale path reports success for work that was abandoned.
func TestCancelledContextIsNotServedStale(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	}
	r := testResolver(t, zones)
	r.Cache = cache.New(cache.Config{MaxTTL: 1, StaleFor: time.Hour})

	q := wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	mustResolve(t, r, "example.com.", wire.TypeA)
	time.Sleep(1100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Resolve(ctx, q); err == nil {
		t.Error("Resolve() answered a cancelled call from the stale cache")
	}
}

// The delegation cache stores what delegation returned after its bailiwick
// checks, never the referral's own contents. A referral that fails those checks
// must leave nothing behind.
func TestRejectedReferralIsNotCached(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		// The root refers com. sideways to a zone that does not contain the
		// name, which delegation rejects.
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			return referral("example.org.", "ns1.example.org.", "127.0.0.2")
		},
		netip.MustParseAddr("127.0.0.2"): func(q wire.Question) *wire.Message {
			return answerMsg(aRR("example.com.", "203.0.113.1"))
		},
	}
	r := testResolver(t, zones)
	r.Cache = cache.New(cache.Config{})

	if _, err := r.Resolve(context.Background(), wire.Question{
		Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN,
	}); err == nil {
		t.Fatal("Resolve() followed a referral that does not contain the name")
	}
	if n := r.Cache.Stats().Delegations; n != 0 {
		t.Errorf("cached %d delegations from a rejected referral, want 0", n)
	}
}

// The nil cache is the default, and every other test in this package relies on
// it staying inert. This states that reliance rather than leaving it implied.
func TestNilCacheResolvesNormally(t *testing.T) {
	r := testResolver(t, threeZones())
	if r.Cache != nil {
		t.Fatal("the zero Resolver has a cache")
	}
	for range 3 {
		res := mustResolve(t, r, "example.com.", wire.TypeA)
		if res.Queries != 3 {
			t.Errorf("Queries = %d, want 3 every time with no cache", res.Queries)
		}
		if res.CacheHit || res.Stale {
			t.Error("a resolver with no cache reported a cache hit")
		}
	}
}
