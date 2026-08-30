// Package stats collects what the server is doing, without getting in its way.
//
// Every rule in here follows from one constraint: the query path must never
// wait on anything that exists only to be watched. A resolver that stalls
// because a monitor stopped reading has been made worse by being observed, and
// the observation is worth less than the answers. So counters are atomic rather
// than locked, the top-N lists are sorted when they are read rather than kept
// sorted while they are written, latency is sampled rather than recorded, and
// the event broadcast drops rather than blocks.
//
// The package imports nothing from this repository. It describes query outcomes
// in plain types, so nothing about DNS leaks into it and nothing about it leaks
// into the resolver.
package stats

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// topItems is how many entries each top-N list carries. Ten is what fits on a
// terminal beside everything else Tier 4 draws.
const topItems = 10

// subscriberBuffer is how far behind a consumer may fall before its events
// start being dropped. Deep enough to absorb a slow redraw, shallow enough that
// a consumer which has stopped reading entirely is noticed quickly rather than
// holding a megabyte of events nobody will look at.
const subscriberBuffer = 256

// ringSize is how many recent events are kept for a consumer that attaches
// after the fact.
const ringSize = 512

// rcodeServFail is the only rcode this package needs to know by name. Failing
// upstream is the one outcome that is a fault rather than an answer.
const rcodeServFail = 2

// CountedItem is one row of a top-N list.
//
// The tier file uses this type in Snapshot without ever defining it. It is
// defined here as a name and a count, with the key rendered to text at snapshot
// time rather than at count time, which is what lets client addresses stay
// netip.Addr on the path where that matters.
type CountedItem struct {
	Name  string
	Count uint64
}

// Snapshot is an immutable point-in-time view. Consumers poll this.
type Snapshot struct {
	Uptime         time.Duration
	QueriesTotal   uint64
	QueriesBlocked uint64
	CacheHits      uint64
	CacheMisses    uint64
	CacheEntries   int
	StaleServed    uint64
	UpstreamErrors uint64
	LatencyP50     time.Duration
	LatencyP99     time.Duration
	TopClients     []CountedItem
	TopDomains     []CountedItem
	TopBlocked     []CountedItem

	// EventsDropped and NamesDropped are not in the tier file's definition.
	// They are here because both of the mechanisms above discard data on
	// purpose, and a system that silently drops things is indistinguishable
	// from one that was never busy. A number nobody can read is a number nobody
	// checks.
	//
	// EventsDropped counts events a subscriber was too slow to receive.
	// NamesDropped counts sightings left out of the top-N lists because a
	// counter shard was full.
	EventsDropped uint64
	NamesDropped  uint64
}

// Event is a single query outcome. Consumers subscribe to a stream of these.
type Event struct {
	At       time.Time
	Client   netip.Addr
	Name     string
	Type     uint16
	Rcode    uint8
	Blocked  bool
	CacheHit bool
	Stale    bool
	Duration time.Duration
}

// Collector accumulates events. It is safe for concurrent use and the zero
// value is not usable; call New.
type Collector struct {
	started time.Time

	queries, blocked, hits, misses, stale, upstream atomic.Uint64
	dropped                                         atomic.Uint64

	clients *counter[netip.Addr]
	domains *counter[string]
	blocks  *counter[string]

	latency *reservoir

	mu     sync.Mutex
	ring   []Event
	next   int
	filled bool

	submu sync.RWMutex
	subs  map[chan Event]struct{}

	// CacheEntries reports how many entries the cache currently holds, or is
	// nil when there is no cache. It is a gauge rather than a counter, so
	// unlike everything else here it cannot be accumulated from events and has
	// to be asked for.
	//
	// Set it once before the first query and never after. It is read without a
	// lock, on the assumption that it is wired up during startup like every
	// other part of the server.
	CacheEntries func() int
}

// New returns a Collector whose uptime starts now.
func New() *Collector {
	return &Collector{
		started: time.Now(),
		clients: newCounter(netip.Addr.String),
		domains: newCounter(func(s string) string { return s }),
		blocks:  newCounter(func(s string) string { return s }),
		latency: newReservoir(),
		ring:    make([]Event, ringSize),
		subs:    make(map[chan Event]struct{}),
	}
}

// Record accounts for one query outcome.
//
// It is called once per query from the worker that answered it, so everything
// it does is either an atomic add, a sharded map update, or a send that cannot
// block. Nothing in here waits on anything.
func (c *Collector) Record(e Event) {
	c.queries.Add(1)
	switch {
	case e.Blocked:
		c.blocked.Add(1)
	case e.CacheHit:
		c.hits.Add(1)
	default:
		c.misses.Add(1)
	}
	if e.Stale {
		c.stale.Add(1)
	}
	if e.Rcode == rcodeServFail {
		c.upstream.Add(1)
	}

	if e.Client.IsValid() {
		c.clients.add(e.Client)
	}
	if e.Name != "" {
		c.domains.add(e.Name)
		if e.Blocked {
			c.blocks.add(e.Name)
		}
	}
	c.latency.add(e.Duration)

	c.remember(e)
	c.broadcast(e)
}

// remember writes the event into the ring, overwriting the oldest.
func (c *Collector) remember(e Event) {
	c.mu.Lock()
	c.ring[c.next] = e
	c.next++
	if c.next == len(c.ring) {
		c.next = 0
		c.filled = true
	}
	c.mu.Unlock()
}

// broadcast offers the event to every subscriber and gives up immediately on
// any that is not ready.
//
// This is the decision the whole package is arranged around. A blocking send
// here would let a consumer that stopped reading, or a terminal that was
// suspended with Ctrl-Z, stall the worker that is holding a client's query.
// One slow watcher would become every client's timeout. Dropping instead means
// the watcher misses events, which is a cost paid by the thing that exists to
// watch rather than by the thing being watched, and the drop is counted so the
// gap is visible rather than silent.
//
// The read lock is held across the sends, which is what makes unsubscribing
// safe: a channel is removed from the map under the write lock and only closed
// afterwards, so no send can reach a channel that is already closed.
func (c *Collector) broadcast(e Event) {
	c.submu.RLock()
	for ch := range c.subs {
		select {
		case ch <- e:
		default:
			c.dropped.Add(1)
		}
	}
	c.submu.RUnlock()
}

// Subscribe returns a stream of events and a function that ends it.
//
// The stream starts empty: it carries what happens from here, and a consumer
// that wants the recent past asks Recent for it. The cancel function may be
// called more than once and from any goroutine.
func (c *Collector) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subscriberBuffer)

	c.submu.Lock()
	c.subs[ch] = struct{}{}
	c.submu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			// Removed from the map first, then closed. Record holds the read
			// lock while it sends, so by the time this write lock is granted
			// no send is in progress, and after the delete no new one can
			// find this channel. Closing before removing would be a send on a
			// closed channel, which is a panic in the worker rather than an
			// error anywhere useful.
			c.submu.Lock()
			delete(c.subs, ch)
			c.submu.Unlock()
			close(ch)
		})
	}
}

// Recent returns up to n of the most recent events, newest first.
func (c *Collector) Recent(n int) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	held := c.next
	if c.filled {
		held = len(c.ring)
	}
	if n > held {
		n = held
	}
	if n <= 0 {
		return nil
	}

	out := make([]Event, 0, n)
	// Walking backwards from the write cursor is what makes this newest first,
	// and the wrap is why it is an index rather than a slice expression.
	for i := range n {
		j := c.next - 1 - i
		if j < 0 {
			j += len(c.ring)
		}
		out = append(out, c.ring[j])
	}
	return out
}

// Snapshot renders the current state.
//
// Everything expensive in this package happens here: three top-N lists get
// sorted and the reservoir gets copied and sorted. That is deliberate, and it
// is why Record can be as cheap as it is. Snapshot is called a few times a
// second by something drawing a screen; Record is called by every query.
//
// The result is a value, not a view. Nothing in it aliases the collector, so a
// consumer can hold one for as long as it likes.
func (c *Collector) Snapshot() Snapshot {
	s := Snapshot{
		Uptime:         time.Since(c.started),
		QueriesTotal:   c.queries.Load(),
		QueriesBlocked: c.blocked.Load(),
		CacheHits:      c.hits.Load(),
		CacheMisses:    c.misses.Load(),
		StaleServed:    c.stale.Load(),
		UpstreamErrors: c.upstream.Load(),
		EventsDropped:  c.dropped.Load(),
		TopClients:     c.clients.top(topItems),
		TopDomains:     c.domains.top(topItems),
		TopBlocked:     c.blocks.top(topItems),
	}
	s.NamesDropped = c.clients.dropped.Load() + c.domains.dropped.Load() + c.blocks.dropped.Load()
	s.LatencyP50, s.LatencyP99 = c.latency.percentiles()
	if c.CacheEntries != nil {
		s.CacheEntries = c.CacheEntries()
	}
	return s
}

// Subscribers reports how many streams are attached. It exists for tests and
// for a shutdown line, and is a reading over an interval rather than at an
// instant.
func (c *Collector) Subscribers() int {
	c.submu.RLock()
	defer c.submu.RUnlock()
	return len(c.subs)
}
