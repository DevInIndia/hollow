package cache

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

func question(name string) wire.Question {
	return wire.Question{Name: wire.Name(name), Type: wire.TypeA, Class: wire.ClassIN}
}

func aRecord(name string, ttl int32, addr string) wire.RR {
	return wire.RR{
		Name:  wire.Name(name),
		Type:  wire.TypeA,
		Class: wire.ClassIN,
		TTL:   ttl,
		Data:  wire.A{Addr: netip.MustParseAddr(addr)},
	}
}

func soaRecord(name string, ttl int32, minimum uint32) wire.RR {
	return wire.RR{
		Name:  wire.Name(name),
		Type:  wire.TypeSOA,
		Class: wire.ClassIN,
		TTL:   ttl,
		Data: wire.SOA{
			Primary: "ns.example.com.",
			Mailbox: "hostmaster.example.com.",
			Serial:  1,
			Minimum: minimum,
		},
	}
}

// answer builds a successful response carrying rrs.
func answer(q wire.Question, rrs ...wire.RR) *wire.Message {
	return &wire.Message{
		Header:    wire.Header{Response: true, Authoritative: true, Rcode: wire.RcodeSuccess},
		Questions: []wire.Question{q},
		Answers:   rrs,
	}
}

// denial builds a response with the given rcode and an authority section.
func denial(q wire.Question, rcode uint8, authority ...wire.RR) *wire.Message {
	return &wire.Message{
		Header:    wire.Header{Response: true, Authoritative: true, Rcode: rcode},
		Questions: []wire.Question{q},
		Authority: authority,
	}
}

func TestAnswerRoundTripsAndCountsDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(Config{})
		q := question("example.com.")
		c.StoreAnswer(q, answer(q, aRecord("example.com.", 300, "93.184.216.34")))

		got, ok := c.Answer(q)
		if !ok {
			t.Fatal("answer stored a moment ago is not in the cache")
		}
		if len(got.Answers) != 1 || got.Answers[0].TTL != 300 {
			t.Fatalf("immediately after store: got %d answers, first TTL %v, want 1 and 300",
				len(got.Answers), got.Answers[0].TTL)
		}

		time.Sleep(100 * time.Second)
		got, ok = c.Answer(q)
		if !ok {
			t.Fatal("answer with 200 seconds left is not in the cache")
		}
		if got.Answers[0].TTL != 200 {
			t.Errorf("after 100s of a 300s TTL: got TTL %d, want 200", got.Answers[0].TTL)
		}
		if got.Answers[0].Data.(wire.A).Addr.String() != "93.184.216.34" {
			t.Errorf("rdata came back as %v", got.Answers[0].Data)
		}
	})
}

// The boundary is exact rather than approximate because the bubble's clock is
// fake, so this asserts the thing a wall clock can only assert loosely: the last
// instant the entry is live and the first instant it is not.
func TestEntryExpiresExactlyWhenTheTTLRunsOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(Config{})
		q := question("example.com.")
		c.StoreAnswer(q, answer(q, aRecord("example.com.", 300, "93.184.216.34")))

		time.Sleep(299 * time.Second)
		got, ok := c.Answer(q)
		if !ok {
			t.Fatal("entry vanished one second before its TTL ran out")
		}
		if got.Answers[0].TTL != 1 {
			t.Errorf("one second before expiry: got TTL %d, want 1", got.Answers[0].TTL)
		}

		time.Sleep(time.Second)
		if _, ok := c.Answer(q); ok {
			t.Error("entry survived the instant its TTL ran out")
		}
	})
}

func TestUncacheableResponsesAreRejected(t *testing.T) {
	q := question("example.com.")

	truncated := answer(q, aRecord("example.com.", 300, "1.2.3.4"))
	truncated.Header.Truncated = true

	servfail := answer(q, aRecord("example.com.", 300, "1.2.3.4"))
	servfail.Header.Rcode = wire.RcodeServFail

	cases := []struct {
		name string
		msg  *wire.Message
		why  string
	}{
		{"nil message", nil, "there is nothing to store"},
		{"truncated", truncated, "the answer section is a prefix, not the answer"},
		{"servfail", servfail, "the code describes the server, not the name"},
		{"zero TTL", answer(q, aRecord("example.com.", 0, "1.2.3.4")), "use once and forget"},
		{"negative TTL", answer(q, aRecord("example.com.", -1, "1.2.3.4")), "not a duration"},
		{"denial with no SOA", denial(q, wire.RcodeNXDomain), "nothing proves the denial"},
		{"nodata with no SOA", denial(q, wire.RcodeSuccess), "nothing proves the denial"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Config{})
			c.StoreAnswer(q, tc.msg)
			if _, ok := c.Answer(q); ok {
				t.Errorf("cached a %s response, but %s", tc.name, tc.why)
			}
			if c.Len() != 0 {
				t.Errorf("cache holds %d entries, want 0", c.Len())
			}
		})
	}
}

// One TTL of zero poisons the whole set. The records were published together and
// are served together, so honouring the shortest is the only reading that never
// serves a record for longer than its owner allowed.
func TestZeroTTLInASetRejectsTheWholeSet(t *testing.T) {
	c := New(Config{})
	q := question("example.com.")
	c.StoreAnswer(q, answer(q,
		aRecord("example.com.", 300, "1.2.3.4"),
		aRecord("example.com.", 0, "5.6.7.8"),
	))
	if _, ok := c.Answer(q); ok {
		t.Error("cached a set containing a zero TTL")
	}
}

func TestKeysFoldCaseButRecordsKeepIt(t *testing.T) {
	c := New(Config{})
	stored := wire.Question{Name: "ExAmPlE.CoM.", Type: wire.TypeA, Class: wire.ClassIN}
	c.StoreAnswer(stored, answer(stored, aRecord("ExAmPlE.CoM.", 300, "1.2.3.4")))

	got, ok := c.Answer(question("example.com."))
	if !ok {
		t.Fatal("a differently cased spelling of the name missed the cache")
	}
	// The record keeps the case it arrived in. The 0x20 defence works by
	// checking that a response echoes the exact case that was sent, so a cache
	// that folded the records would disarm it for every cached name.
	if got.Answers[0].Name != "ExAmPlE.CoM." {
		t.Errorf("stored record name came back as %q, want the case it arrived in", got.Answers[0].Name)
	}
	// The question echoed is the caller's, not the one that filled the cache.
	if got.Questions[0].Name != "example.com." {
		t.Errorf("echoed question is %q, want the caller's spelling", got.Questions[0].Name)
	}
	if c.Len() != 1 {
		t.Errorf("two spellings produced %d entries, want 1", c.Len())
	}
}

func TestTTLIsClampedBothWays(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		ttl    int32
		expect int32
	}{
		{"ceiling applies", Config{MaxTTL: 60}, 3600, 60},
		{"floor applies", Config{MinTTL: 600}, 30, 600},
		{"untouched between", Config{MinTTL: 10, MaxTTL: 600}, 300, 300},
		{"default ceiling", Config{}, 999999, int32(defaultMaxTTL)},
		{"floor defaults off", Config{}, 5, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.cfg)
			q := question("example.com.")
			c.StoreAnswer(q, answer(q, aRecord("example.com.", tc.ttl, "1.2.3.4")))
			got, ok := c.Answer(q)
			if !ok {
				t.Fatal("entry missing")
			}
			if got.Answers[0].TTL != tc.expect {
				t.Errorf("TTL %d stored under %+v came back as %d, want %d",
					tc.ttl, tc.cfg, got.Answers[0].TTL, tc.expect)
			}
		})
	}
}

// Unknown.Data is the one rdata field that aliases the buffer it was decoded
// from, so it is the one field a cache must copy. Overwriting the caller's slice
// after the store stands in for the buffer being reused.
func TestUnknownRDataIsCopiedNotAliased(t *testing.T) {
	c := New(Config{})
	q := wire.Question{Name: "example.com.", Type: 99, Class: wire.ClassIN}
	payload := []byte{1, 2, 3, 4}
	c.StoreAnswer(q, answer(q, wire.RR{
		Name: "example.com.", Type: 99, Class: wire.ClassIN, TTL: 300,
		Data: wire.Unknown{Kind: 99, Data: payload},
	}))

	for i := range payload {
		payload[i] = 0x5A
	}

	got, ok := c.Answer(q)
	if !ok {
		t.Fatal("entry missing")
	}
	if stored := got.Answers[0].Data.(wire.Unknown).Data; string(stored) != string([]byte{1, 2, 3, 4}) {
		t.Errorf("cached rdata is %v, want %v: the cache aliased the caller's buffer",
			stored, []byte{1, 2, 3, 4})
	}
}

// OPT is per-transaction EDNS0 state, not zone data. Replaying one client's OPT
// to another would advertise somebody else's payload size and flags as ours.
func TestOPTIsStrippedBeforeStoring(t *testing.T) {
	c := New(Config{})
	q := question("example.com.")
	msg := answer(q, aRecord("example.com.", 300, "1.2.3.4"))
	msg.Answers = append(msg.Answers, wire.EDNS{UDPSize: 4096}.RR())

	c.StoreAnswer(q, msg)
	got, ok := c.Answer(q)
	if !ok {
		t.Fatal("entry missing")
	}
	for _, rr := range got.Answers {
		if rr.Type == wire.TypeOPT {
			t.Fatal("an OPT pseudo-record was stored and replayed")
		}
	}
	if len(got.Answers) != 1 {
		t.Errorf("got %d answers, want the one real record", len(got.Answers))
	}
}

func TestCachedAnswersAreNotAuthoritative(t *testing.T) {
	c := New(Config{})
	q := question("example.com.")
	// The upstream response was authoritative. Our copy of it is not.
	c.StoreAnswer(q, answer(q, aRecord("example.com.", 300, "1.2.3.4")))

	got, ok := c.Answer(q)
	if !ok {
		t.Fatal("entry missing")
	}
	if got.Header.Authoritative {
		t.Error("a cached answer claims to be authoritative")
	}
	if !got.Header.Response {
		t.Error("cached answer is not marked as a response")
	}
	if !got.Header.RecursionAvailable {
		t.Error("cached answer does not advertise recursion")
	}
}

func TestNegativeCachingUsesTheSOA(t *testing.T) {
	cases := []struct {
		name    string
		rcode   uint8
		soaTTL  int32
		minimum uint32
		expect  int32
	}{
		{"minimum is smaller", wire.RcodeNXDomain, 3600, 900, 900},
		{"record TTL is smaller", wire.RcodeNXDomain, 600, 900, 600},
		{"capped at three hours", wire.RcodeNXDomain, 86400, 86400, int32(maxNegativeTTL)},
		{"nodata caches the same way", wire.RcodeSuccess, 3600, 900, 900},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Config{})
			q := question("nope.example.com.")
			c.StoreAnswer(q, denial(q, tc.rcode, soaRecord("example.com.", tc.soaTTL, tc.minimum)))

			got, ok := c.Answer(q)
			if !ok {
				t.Fatal("denial was not cached")
			}
			if got.Header.Rcode != tc.rcode {
				t.Errorf("rcode came back as %d, want %d", got.Header.Rcode, tc.rcode)
			}
			// The SOA is replayed so the client can see the denial is proven,
			// and so a client that does its own negative caching can do it.
			if len(got.Authority) != 1 || got.Authority[0].Type != wire.TypeSOA {
				t.Fatalf("authority section is %v, want one SOA", got.Authority)
			}
			if got.Authority[0].TTL != tc.expect {
				t.Errorf("negative TTL is %d, want %d", got.Authority[0].TTL, tc.expect)
			}
		})
	}
}

// A denial reached through a CNAME chain keeps the chain: the aliases exist even
// though the name they lead to does not.
func TestNegativeEntryKeepsTheCNAMEChain(t *testing.T) {
	c := New(Config{})
	q := question("alias.example.com.")
	msg := denial(q, wire.RcodeNXDomain, soaRecord("example.com.", 3600, 900))
	msg.Answers = []wire.RR{{
		Name: "alias.example.com.", Type: wire.TypeCNAME, Class: wire.ClassIN, TTL: 3600,
		Data: wire.CNAME{Target: "gone.example.com."},
	}}
	c.StoreAnswer(q, msg)

	got, ok := c.Answer(q)
	if !ok {
		t.Fatal("denial was not cached")
	}
	if len(got.Answers) != 1 || got.Answers[0].Type != wire.TypeCNAME {
		t.Fatalf("answer section is %v, want the CNAME that led to the denial", got.Answers)
	}
	// The chain expires with the denial rather than on its own longer TTL.
	if got.Answers[0].TTL != 900 {
		t.Errorf("CNAME TTL is %d, want the negative TTL of 900", got.Answers[0].TTL)
	}
}

func TestServeStale(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(Config{StaleFor: time.Hour})
		q := question("example.com.")
		c.StoreAnswer(q, answer(q, aRecord("example.com.", 300, "1.2.3.4")))

		// While the entry is fresh, Stale declines: serving it here would mean
		// answering from the stale path something Answer should have served.
		if _, ok := c.Stale(q); ok {
			t.Error("Stale returned a fresh entry")
		}

		time.Sleep(400 * time.Second)
		if _, ok := c.Answer(q); ok {
			t.Fatal("expired entry is still being served as fresh")
		}
		got, ok := c.Stale(q)
		if !ok {
			t.Fatal("expired entry within the stale window was not served")
		}
		// Never zero. A zero TTL tells every client not to reuse the answer,
		// which turns one upstream failure into a storm.
		if got.Answers[0].TTL != staleTTL {
			t.Errorf("stale answer TTL is %d, want %d", got.Answers[0].TTL, staleTTL)
		}

		time.Sleep(2 * time.Hour)
		if _, ok := c.Stale(q); ok {
			t.Error("entry was served stale long past the stale window")
		}
	})
}

func TestServeStaleIsOffByDefault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(Config{})
		q := question("example.com.")
		c.StoreAnswer(q, answer(q, aRecord("example.com.", 300, "1.2.3.4")))
		time.Sleep(400 * time.Second)
		if _, ok := c.Stale(q); ok {
			t.Error("served a stale answer with StaleFor unset")
		}
	})
}

func TestEvictionBoundsTheCache(t *testing.T) {
	// One entry per shard, so the total cap is the shard count and every insert
	// past it must displace something.
	c := New(Config{Entries: shardCount})
	for i := range 20 * shardCount {
		q := question(fmt.Sprintf("host%d.example.com.", i))
		c.StoreAnswer(q, answer(q, aRecord(q.Name.String(), 300, "1.2.3.4")))
	}
	if n := c.Len(); n > shardCount {
		t.Errorf("cache holds %d entries, want at most %d", n, shardCount)
	}
	if c.Stats().Evictions == 0 {
		t.Error("nothing was counted as evicted after 20 times the capacity was inserted")
	}
}

func TestStatsCountHitsAndMisses(t *testing.T) {
	c := New(Config{})
	q := question("example.com.")

	if _, ok := c.Answer(q); ok {
		t.Fatal("empty cache returned an answer")
	}
	c.StoreAnswer(q, answer(q, aRecord("example.com.", 300, "1.2.3.4")))
	c.Answer(q)
	c.Answer(q)

	got := c.Stats()
	if got.Hits != 2 || got.Misses != 1 {
		t.Errorf("got %d hits and %d misses, want 2 and 1", got.Hits, got.Misses)
	}
	if got.Entries != 1 {
		t.Errorf("got %d entries, want 1", got.Entries)
	}
}

// The store is sharded and the LRU list is mutated on every read, so this is
// where a lock bug hides. It exists to be run under -race.
func TestConcurrentUseIsSafe(t *testing.T) {
	c := New(Config{Entries: 1000, StaleFor: time.Hour})
	var wg sync.WaitGroup
	for w := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				q := question(fmt.Sprintf("host%d.example.com.", (w*500+i)%700))
				c.StoreAnswer(q, answer(q, aRecord(q.Name.String(), 300, "1.2.3.4")))
				c.Answer(q)
				c.Stale(q)
				c.StoreDelegation("example.com.", []netip.AddrPort{
					netip.MustParseAddrPort("192.0.2.1:53"),
				}, 3600)
				c.Delegation(q.Name)
				c.Stats()
			}
		}()
	}
	wg.Wait()
}
