package stats

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func event(name string, opts ...func(*Event)) Event {
	e := Event{
		At:       time.Now(),
		Client:   netip.MustParseAddr("192.0.2.1"),
		Name:     name,
		Type:     1,
		Duration: time.Millisecond,
	}
	for _, o := range opts {
		o(&e)
	}
	return e
}

func blocked(e *Event)  { e.Blocked = true }
func hit(e *Event)      { e.CacheHit = true }
func stale(e *Event)    { e.Stale = true }
func servfail(e *Event) { e.Rcode = rcodeServFail }

func TestCountersAccumulate(t *testing.T) {
	c := New()
	c.Record(event("a.example.com."))
	c.Record(event("a.example.com.", hit))
	c.Record(event("b.example.com.", blocked))
	c.Record(event("c.example.com.", hit, stale))
	c.Record(event("d.example.com.", servfail))

	s := c.Snapshot()
	if s.QueriesTotal != 5 {
		t.Errorf("QueriesTotal = %d, want 5", s.QueriesTotal)
	}
	if s.QueriesBlocked != 1 {
		t.Errorf("QueriesBlocked = %d, want 1", s.QueriesBlocked)
	}
	// Blocked, hit and miss are one outcome each, not three flags that can all
	// be true. A blocked query never reached the cache, so counting it as a
	// miss would inflate the miss rate with queries that were never looked up.
	if s.CacheHits != 2 {
		t.Errorf("CacheHits = %d, want 2", s.CacheHits)
	}
	if s.CacheMisses != 2 {
		t.Errorf("CacheMisses = %d, want 2", s.CacheMisses)
	}
	if s.CacheHits+s.CacheMisses+s.QueriesBlocked != s.QueriesTotal {
		t.Errorf("hits %d + misses %d + blocked %d does not account for %d queries",
			s.CacheHits, s.CacheMisses, s.QueriesBlocked, s.QueriesTotal)
	}
	if s.StaleServed != 1 {
		t.Errorf("StaleServed = %d, want 1", s.StaleServed)
	}
	if s.UpstreamErrors != 1 {
		t.Errorf("UpstreamErrors = %d, want 1", s.UpstreamErrors)
	}
	if s.Uptime <= 0 {
		t.Error("Uptime is not advancing")
	}
}

// CacheEntries is a gauge and cannot be accumulated from events, so it is the
// one number that has to be asked for.
func TestCacheEntriesComesFromTheHook(t *testing.T) {
	c := New()
	if got := c.Snapshot().CacheEntries; got != 0 {
		t.Errorf("CacheEntries = %d with no hook set, want 0", got)
	}
	c.CacheEntries = func() int { return 42 }
	if got := c.Snapshot().CacheEntries; got != 42 {
		t.Errorf("CacheEntries = %d, want 42", got)
	}
}

// The rule the package is built around: a subscriber that has stopped reading
// must not stop the server. Nothing here reads from the channel.
func TestASlowSubscriberIsDroppedNotWaitedOn(t *testing.T) {
	c := New()
	ch, cancel := c.Subscribe()
	defer cancel()

	const extra = 50
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range subscriberBuffer + extra {
			c.Record(event(fmt.Sprintf("n%d.example.com.", i)))
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Record blocked on a subscriber that was not reading")
	}

	if got := len(ch); got != subscriberBuffer {
		t.Errorf("the subscriber holds %d events, want its buffer full at %d", got, subscriberBuffer)
	}
	if got := c.Snapshot().EventsDropped; got != extra {
		t.Errorf("EventsDropped = %d, want %d", got, extra)
	}
}

func TestSubscribersSeeEventsInOrder(t *testing.T) {
	c := New()
	ch, cancel := c.Subscribe()
	defer cancel()

	names := []string{"a.example.com.", "b.example.com.", "c.example.com."}
	for _, n := range names {
		c.Record(event(n))
	}
	for i, want := range names {
		select {
		case got := <-ch:
			if got.Name != want {
				t.Errorf("event %d is %q, want %q", i, got.Name, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("event %d never arrived", i)
		}
	}
}

// Two subscribers each get their own copy, and one going away does not affect
// the other.
func TestUnsubscribeIsIdempotentAndLeavesOthersAlone(t *testing.T) {
	c := New()
	first, cancelFirst := c.Subscribe()
	second, cancelSecond := c.Subscribe()
	defer cancelSecond()

	if c.Subscribers() != 2 {
		t.Fatalf("Subscribers() = %d, want 2", c.Subscribers())
	}

	c.Record(event("a.example.com."))
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("one event reached %d and %d subscribers, want both", len(first), len(second))
	}

	cancelFirst()
	cancelFirst() // must not panic on a second close
	if c.Subscribers() != 1 {
		t.Errorf("Subscribers() = %d after one cancel, want 1", c.Subscribers())
	}

	// A cancelled stream is closed, so a consumer ranging over it stops rather
	// than blocking forever.
	<-first // the buffered event
	if _, open := <-first; open {
		t.Error("the cancelled channel is still open")
	}

	c.Record(event("b.example.com."))
	if len(second) != 2 {
		t.Errorf("the surviving subscriber holds %d events, want 2", len(second))
	}
}

// Unsubscribing while events are being recorded is the race that a close in the
// wrong order turns into a panic in a worker goroutine.
func TestUnsubscribeDuringRecord(t *testing.T) {
	c := New()
	var wg sync.WaitGroup

	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					c.Record(event("a.example.com."))
				}
			}
		}()
	}

	for range 200 {
		ch, cancel := c.Subscribe()
		go func() {
			for range ch {
			}
		}()
		cancel()
	}

	close(stop)
	wg.Wait()
	if c.Subscribers() != 0 {
		t.Errorf("Subscribers() = %d after every cancel, want 0", c.Subscribers())
	}
}

func TestRecentIsNewestFirst(t *testing.T) {
	c := New()
	for i := range 5 {
		c.Record(event(fmt.Sprintf("n%d.example.com.", i)))
	}

	got := c.Recent(3)
	want := []string{"n4.example.com.", "n3.example.com.", "n2.example.com."}
	if len(got) != len(want) {
		t.Fatalf("Recent(3) returned %d events, want 3", len(got))
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Errorf("Recent()[%d] = %q, want %q", i, got[i].Name, want[i])
		}
	}

	if n := len(c.Recent(100)); n != 5 {
		t.Errorf("Recent(100) returned %d events, want the 5 that exist", n)
	}
	if c.Recent(0) != nil {
		t.Error("Recent(0) returned something")
	}
	if New().Recent(10) != nil {
		t.Error("Recent() on a fresh collector returned something")
	}
}

// The ring overwrites rather than growing, and the wrap must not scramble the
// order or resurrect an overwritten event.
func TestRecentWrapsWithoutLosingOrder(t *testing.T) {
	c := New()
	for i := range ringSize + 10 {
		c.Record(event(fmt.Sprintf("n%d.example.com.", i)))
	}

	got := c.Recent(ringSize + 100)
	if len(got) != ringSize {
		t.Fatalf("Recent() returned %d events, want the ring's %d", len(got), ringSize)
	}
	for i, e := range got {
		want := fmt.Sprintf("n%d.example.com.", ringSize+10-1-i)
		if e.Name != want {
			t.Fatalf("Recent()[%d] = %q, want %q", i, e.Name, want)
		}
	}
}

func TestTopListsAreSortedAndCapped(t *testing.T) {
	c := New()
	counts := map[string]int{
		"a.example.com.": 5,
		"b.example.com.": 3,
		"c.example.com.": 1,
	}
	for name, n := range counts {
		for range n {
			c.Record(event(name))
		}
	}
	for range 2 {
		c.Record(event("bad.example.com.", blocked))
	}

	s := c.Snapshot()
	if len(s.TopDomains) != 4 {
		t.Fatalf("TopDomains has %d entries, want 4", len(s.TopDomains))
	}
	if s.TopDomains[0].Name != "a.example.com." || s.TopDomains[0].Count != 5 {
		t.Errorf("TopDomains[0] = %+v, want a.example.com. with 5", s.TopDomains[0])
	}
	for i := 1; i < len(s.TopDomains); i++ {
		if s.TopDomains[i-1].Count < s.TopDomains[i].Count {
			t.Errorf("TopDomains is not sorted at %d: %+v", i, s.TopDomains)
		}
	}

	// Blocked names are counted in both lists: they are still domains that were
	// asked for, and a top-domains list that omitted them would understate what
	// the clients are doing.
	if len(s.TopBlocked) != 1 || s.TopBlocked[0].Name != "bad.example.com." || s.TopBlocked[0].Count != 2 {
		t.Errorf("TopBlocked = %+v, want bad.example.com. with 2", s.TopBlocked)
	}
	if len(s.TopClients) != 1 || s.TopClients[0].Count != 11 {
		t.Errorf("TopClients = %+v, want one client with 11", s.TopClients)
	}
}

func TestTopIsCappedAtTen(t *testing.T) {
	c := New()
	for i := range 30 {
		for range i + 1 {
			c.Record(event(fmt.Sprintf("n%02d.example.com.", i)))
		}
	}
	if got := len(c.Snapshot().TopDomains); got != topItems {
		t.Errorf("TopDomains has %d entries, want %d", got, topItems)
	}
}

// Equal counts have to break the same way every time, or a TUI redrawing twice
// a second shows a list that reorders itself for no reason.
func TestEqualCountsBreakTiesOnName(t *testing.T) {
	c := New()
	for _, n := range []string{"c.example.com.", "a.example.com.", "b.example.com."} {
		c.Record(event(n))
	}
	first := c.Snapshot().TopDomains
	for range 20 {
		got := c.Snapshot().TopDomains
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("two snapshots disagree at %d: %+v then %+v", i, first[i], got[i])
			}
		}
	}
	if first[0].Name != "a.example.com." {
		t.Errorf("ties broke to %q, want the first name alphabetically", first[0].Name)
	}
}

// The cardinality cap. A random subdomain flood must not be able to grow the
// statistics maps without bound, and the names that were already frequent must
// survive it.
func TestFloodOfUniqueNamesIsBoundedAndDoesNotEvictTheFrequent(t *testing.T) {
	c := newCounter(func(s string) string { return s })

	for range 500 {
		c.add("real.example.com.")
	}
	for i := range 100000 {
		c.add(fmt.Sprintf("%d.flood.example.com.", i))
	}

	if got, max := c.len(), topShards*topPerShard; got > max {
		t.Errorf("the counter tracks %d keys, want no more than %d", got, max)
	}
	if c.dropped.Load() == 0 {
		t.Error("100000 unique names were all admitted, so nothing is bounded")
	}

	// The point of refusing new keys rather than evicting old ones: the name
	// that was genuinely popular before the flood is still counted, and still
	// on top, because a flood consists of names seen once each.
	top := c.top(topItems)
	if len(top) == 0 {
		t.Fatal("the counter reports nothing at all")
	}
	if top[0].Name != "real.example.com." || top[0].Count != 500 {
		t.Errorf("top entry is %+v, want real.example.com. with 500", top[0])
	}
}

func TestSnapshotReportsWhatWasDropped(t *testing.T) {
	c := New()
	for i := range topShards*topPerShard + 20000 {
		c.Record(event(fmt.Sprintf("%d.example.com.", i)))
	}
	if c.Snapshot().NamesDropped == 0 {
		t.Error("NamesDropped = 0 after overflowing every shard")
	}
}

func TestConcurrentRecordAndSnapshot(t *testing.T) {
	c := New()
	c.CacheEntries = func() int { return 1 }

	ch, cancel := c.Subscribe()
	defer cancel()
	go func() {
		for range ch {
		}
	}()

	const writers, each = 16, 500
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				c.Record(event(fmt.Sprintf("n%d.example.com.", i%50),
					func(e *Event) {
						e.Client = netip.AddrFrom4([4]byte{192, 0, 2, byte(w)})
						e.Duration = time.Duration(i) * time.Microsecond
					}))
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				c.Snapshot()
				c.Recent(10)
			}
		}()
	}
	wg.Wait()

	if got := c.Snapshot().QueriesTotal; got != writers*each {
		t.Errorf("QueriesTotal = %d, want %d", got, writers*each)
	}
}
