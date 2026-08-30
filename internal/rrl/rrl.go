// Package rrl is response rate limiting: a bound on how many answers this
// server will send to one client network per second.
//
// It exists for one attack. A DNS query is small and an answer is large, so a
// resolver reachable from the internet is a way to turn a 60-octet packet
// carrying somebody else's source address into a 500-octet packet aimed at
// them. The victim never asked and cannot refuse. Limiting how fast answers go
// to any one network is what takes the leverage away, and it is why the limit
// is on responses rather than on queries: what matters is what leaves here.
//
// The design follows BIND's RRL, including the part that makes it usable.
package rrl

import (
	"container/list"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults, which are BIND's.
const (
	DefaultPerSecond = 20
	DefaultWindow    = 15 * time.Second
	DefaultSlip      = 2
	DefaultEntries   = 10000

	// Clients are counted by network rather than by address, because an
	// attacker with a /64 of IPv6 has more addresses than this program has
	// memory, and because a real client that moves between two addresses in one
	// network is still one client.
	v4Bits = 24
	v6Bits = 56
)

// Action is what to do with a response.
type Action int

const (
	// Send is the ordinary case: under the limit, answer normally.
	Send Action = iota

	// Drop sends nothing at all. Not an error, not a REFUSED: an error is a
	// response, and a response is exactly what the attack wants. The client
	// that genuinely sent the query retries, which UDP already requires it to
	// be able to do.
	Drop

	// Truncate sends a header with TC set and no records, which costs a few
	// dozen octets and no amplification. It is the slip case below.
	Truncate
)

func (a Action) String() string {
	switch a {
	case Drop:
		return "drop"
	case Truncate:
		return "truncate"
	}
	return "send"
}

// Config is how the limiter is set up. The zero value uses the defaults above,
// which are the ones BIND ships.
type Config struct {
	// PerSecond is the sustained rate allowed to one client network.
	PerSecond int

	// Window bounds how much unused allowance a known client can build up while
	// it is quiet, expressed as the time it takes to fill. A client silent for
	// longer than this may then burst PerSecond times Window responses, which
	// is deliberate: a rate limiter that punishes a client for having been idle
	// fires on the traffic nobody complained about.
	//
	// A client seen for the first time gets one second's worth rather than the
	// window's, so that inventing a new source network is not a way to collect
	// a full window of free responses.
	Window time.Duration

	// Slip is the reciprocal of how often an over-limit response is answered
	// truncated instead of dropped: 2 means every second one. Zero drops
	// everything over the limit.
	Slip int

	// Trusted networks are exempt.
	Trusted []netip.Prefix

	// Entries caps how many client networks are tracked at once. The table is
	// itself an attack surface, so it is bounded and the least recently seen
	// network is evicted to make room.
	Entries int
}

// Limiter tracks one bucket per client network.
//
// One mutex, not the sharding the cache uses. The critical section is a map
// lookup and a few arithmetic operations, it runs once per UDP query rather
// than twice, and a limiter that needed sharding to keep up would be a limiter
// that is not limiting anything.
type Limiter struct {
	perSecond float64
	burst     float64
	slip      int
	trusted   []netip.Prefix
	entries   int

	// now is time.Now, replaced in tests. A rate limiter is all clock.
	now func() time.Time

	mu      sync.Mutex
	buckets map[netip.Prefix]*list.Element
	lru     *list.List // front is the most recently seen

	limited  atomic.Uint64 // responses that were not sent normally
	dropped  atomic.Uint64
	slipped  atomic.Uint64
	evicted  atomic.Uint64
	exempted atomic.Uint64
}

// bucket is one client network's allowance.
type bucket struct {
	prefix netip.Prefix
	tokens float64
	last   time.Time
	over   int // over-limit responses since this bucket was created, for slip
}

// New builds a limiter. A PerSecond of zero in the config means the default;
// callers wanting no limiting at all should hold a nil *Limiter, which allows
// everything.
func New(cfg Config) *Limiter {
	if cfg.PerSecond <= 0 {
		cfg.PerSecond = DefaultPerSecond
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Slip < 0 {
		cfg.Slip = DefaultSlip
	}
	if cfg.Entries <= 0 {
		cfg.Entries = DefaultEntries
	}
	return &Limiter{
		perSecond: float64(cfg.PerSecond),
		burst:     float64(cfg.PerSecond) * cfg.Window.Seconds(),
		slip:      cfg.Slip,
		trusted:   cfg.Trusted,
		entries:   cfg.Entries,
		now:       time.Now,
		buckets:   make(map[netip.Prefix]*list.Element),
		lru:       list.New(),
	}
}

// Allow decides what to do with one response to one client.
//
// A nil Limiter allows everything, which is what makes the feature switchable
// without a flag check at the call site.
func (l *Limiter) Allow(from netip.Addr) Action {
	if l == nil {
		return Send
	}
	if !from.IsValid() {
		// No address means no client to account against: a test harness, or a
		// transport that does not carry one. Counting all of those together
		// would be counting nothing together.
		return Send
	}
	for _, p := range l.trusted {
		if p.Contains(from) {
			l.exempted.Add(1)
			return Send
		}
	}

	key := network(from)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.bucket(key, now)

	// Tokens accrue at the configured rate and stop at the window's worth. This
	// is the sliding part: there is no boundary at which a counter resets and a
	// client gets a fresh allowance for free.
	b.tokens += now.Sub(b.last).Seconds() * l.perSecond
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return Send
	}

	l.limited.Add(1)
	b.over++
	// Slip is what keeps this from being a denial of service against the
	// server's own clients. A truncated reply tells a real client to ask again
	// over TCP, which it will do and which will work, because TCP is exempt. A
	// spoofed source cannot complete the handshake and gets nothing out of it.
	// Without slip, a legitimate client behind a busy network simply stops
	// being served with no way to recover.
	if l.slip > 0 && b.over%l.slip == 0 {
		l.slipped.Add(1)
		return Truncate
	}
	l.dropped.Add(1)
	return Drop
}

// bucket finds or creates the bucket for a network, evicting the least recently
// seen one if the table is full.
func (l *Limiter) bucket(key netip.Prefix, now time.Time) *bucket {
	if el, ok := l.buckets[key]; ok {
		l.lru.MoveToFront(el)
		return el.Value.(*bucket)
	}

	if len(l.buckets) >= l.entries {
		// The least recently seen network goes. Under a flood from many forged
		// sources this evicts the forgeries, because the network actually being
		// answered is touched on every packet and stays at the front.
		if back := l.lru.Back(); back != nil {
			l.lru.Remove(back)
			delete(l.buckets, back.Value.(*bucket).prefix)
			l.evicted.Add(1)
		}
	}

	// A new client starts with one second's allowance, not the window's worth
	// that a long-established one can accrue. Enough that the handful of
	// parallel lookups a browser opens with is not mistaken for an attack, and
	// not so much that an attacker rotating source networks collects a full
	// window of free responses for each one it invents.
	b := &bucket{prefix: key, tokens: l.perSecond, last: now}
	l.buckets[key] = l.lru.PushFront(b)
	return b
}

// network is the client network a bucket accounts for.
func network(a netip.Addr) netip.Prefix {
	bits := v4Bits
	if a.Is6() && !a.Is4In6() {
		bits = v6Bits
	}
	p, err := a.Unmap().Prefix(bits)
	if err != nil {
		// Only possible for a bit count wider than the address, which the two
		// constants above rule out. Falling back to the whole address is still
		// a correct bucket, just a narrower one.
		return netip.PrefixFrom(a, a.BitLen())
	}
	return p
}

// Stats reports what the limiter has done. Counting exemptions matters as much
// as counting drops: a limiter that is exempting everything is not running.
func (l *Limiter) Stats() (limited, dropped, slipped, exempted, evicted uint64, tracked int) {
	if l == nil {
		return 0, 0, 0, 0, 0, 0
	}
	l.mu.Lock()
	tracked = len(l.buckets)
	l.mu.Unlock()
	return l.limited.Load(), l.dropped.Load(), l.slipped.Load(),
		l.exempted.Load(), l.evicted.Load(), tracked
}
