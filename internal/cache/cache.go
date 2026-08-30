// Package cache holds DNS answers for the length of time their owners said to,
// so that a name resolved once is not walked from the root again.
//
// The gap it closes is the difference between a toy and a tool. Iterative
// resolution from the root costs several round trips and a few hundred
// milliseconds, and without a cache every query pays it, including the queries a
// resolver makes of itself while chasing nameserver addresses. The zone
// operators already published how long each answer may be reused. This package
// is the part of the resolver that takes them up on it.
//
// Two things are cached, at two depths. Final answers are the obvious half.
// Delegations are the half that makes the difference between names: caching only
// answers still walks root, com and example.com for every distinct host under
// example.com, while a cached delegation lets the walk start at the deepest zone
// already known. See delegation.go.
//
// Everything here is safe for concurrent use.
package cache

import (
	"sync/atomic"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

// DefaultEntries is the answer cache's size when Config leaves it unset.
//
// 100000 entries is roughly 30 MB at the average answer size measured on this
// implementation, which is a reasonable resident set for a resolver and holds
// far more than a single host's working set of names.
const DefaultEntries = 100000

const (
	// defaultMaxTTL caps how long any single answer is held. A day is well past
	// the point where a zone operator's intent is still meaningful, and the cap
	// exists so that one record with a TTL of ten years cannot pin an entry for
	// the life of the process.
	defaultMaxTTL uint32 = 86400

	// maxNegativeTTL is the ceiling RFC 2308 section 5 places on negative
	// caching, regardless of what the SOA asks for. A name that does not exist
	// today is the kind of thing that changes, and a zone claiming a week of
	// non-existence should not be believed for a week.
	maxNegativeTTL uint32 = 10800

	// staleTTL is the TTL attached to a stale answer, RFC 8767 section 4. It is
	// deliberately not zero: a zero TTL tells the client never to reuse the
	// answer, which turns one upstream failure into a query storm from every
	// client that was relying on the name.
	staleTTL int32 = 30
)

// Key identifies a cached answer.
//
// Name is folded to lower case, because DNS matching is case-insensitive per RFC
// 4343 and two spellings of one name must not become two entries. The folding
// stops at the key: the records inside an entry keep the case they arrived with,
// which is what leaves room for the 0x20 defence to be added above this package
// without the cache quietly undoing it.
type Key struct {
	Name  wire.Name
	Type  wire.Type
	Class wire.Class
}

func keyFor(q wire.Question) Key {
	return Key{Name: q.Name.Fold(), Type: q.Type, Class: q.Class}
}

// Config configures a Cache. The zero value is valid and gives the defaults.
//
// This is a value passed to New rather than a set of exported fields on Cache,
// because a Cache is read by every worker in the pool concurrently and a knob
// that can be turned after that starts is a data race with no lock to point at.
type Config struct {
	// Entries is the answer cache's capacity. Zero means DefaultEntries.
	Entries int

	// MinTTL raises TTLs below it, in seconds. Zero, the default, disables the
	// floor and is the honest setting: raising a TTL serves an answer for longer
	// than its operator permitted, which is a choice an operator of this
	// resolver may make deliberately but should never get by accident.
	MinTTL uint32

	// MaxTTL caps TTLs, in seconds. Zero means defaultMaxTTL.
	MaxTTL uint32

	// StaleFor is how long past expiry an answer may still be served when
	// resolution fails, RFC 8767. Zero disables serve-stale entirely.
	StaleFor time.Duration
}

// Cache is a bounded, sharded store of DNS answers and delegations.
type Cache struct {
	answers     *store[Key, *entry]
	delegations *store[wire.Name, *delegationEntry]

	minTTL, maxTTL uint32
	staleFor       time.Duration

	hits, misses, stale atomic.Uint64
}

// New returns a cache configured by cfg.
func New(cfg Config) *Cache {
	entries := cfg.Entries
	if entries <= 0 {
		entries = DefaultEntries
	}
	maxTTL := cfg.MaxTTL
	if maxTTL == 0 {
		maxTTL = defaultMaxTTL
	}
	return &Cache{
		answers:     newStore[Key, *entry](entries, func(k Key) string { return string(k.Name) }),
		delegations: newStore[wire.Name, *delegationEntry](delegationEntries, func(n wire.Name) string { return string(n) }),
		minTTL:      cfg.MinTTL,
		maxTTL:      maxTTL,
		staleFor:    cfg.StaleFor,
	}
}

// entry is one cached response, reduced to the parts worth replaying.
//
// A positive entry holds the answer section alone. A negative one holds the
// authority section, whose SOA is the proof of the denial, and keeps the answer
// section too, because a denial may be reached through a CNAME chain and the
// chain is part of the answer even when its destination does not exist.
//
// Neither holds the additional section or the question. Both are rebuilt from
// the query being served rather than from the query that filled the cache, which
// is what lets one entry answer a client that asked in different case, with a
// different message ID, and with different EDNS0 capabilities.
//
// The TTLs on these records are the values as stored, already clamped. Remaining
// time is computed against the slot's insert time on the way out.
type entry struct {
	rcode     uint8
	answers   []wire.RR
	authority []wire.RR
}

// Answer returns a cached response to q whose TTLs have not run out.
func (c *Cache) Answer(q wire.Question) (*wire.Message, bool) {
	sl, ok := c.answers.get(keyFor(q))
	if !ok || !time.Now().Before(sl.expires) {
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return sl.value.reply(q, elapsed(sl.stored)), true
}

// Stale returns an expired answer to q, if one is held and serve-stale is on.
//
// This is the RFC 8767 path and is only correct as a response to a resolution
// that has already failed. It deliberately returns nothing for an entry that is
// still fresh, so that a caller which reaches for it out of order gets a miss
// rather than an answer Answer should have served.
//
// What this does not do is refresh the name in the background, which RFC 8767
// section 6 recommends. An unbounded set of detached resolutions is the exact
// failure the server's bounded worker pool exists to prevent, and the next query
// for the name retries anyway. The cost is one client seeing a stale answer that
// a background refresh would have replaced sooner.
func (c *Cache) Stale(q wire.Question) (*wire.Message, bool) {
	if c.staleFor <= 0 {
		return nil, false
	}
	sl, ok := c.answers.get(keyFor(q))
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.Before(sl.expires) || now.Sub(sl.expires) > c.staleFor {
		return nil, false
	}
	c.stale.Add(1)
	return sl.value.reply(q, -1), true
}

// StoreAnswer files msg as the response to q, if it is the kind of response that
// may be cached at all.
//
// Rejected outright: a truncated message, because what it holds is a prefix of
// the answer and caching a prefix serves it as though it were whole; and any
// rcode other than success or NXDOMAIN, because a SERVFAIL or REFUSED describes
// the server that produced it rather than the name that was asked about.
func (c *Cache) StoreAnswer(q wire.Question, msg *wire.Message) {
	if msg == nil || msg.Header.Truncated {
		return
	}
	if msg.Header.Rcode != wire.RcodeSuccess && msg.Header.Rcode != wire.RcodeNXDomain {
		return
	}

	e := &entry{rcode: msg.Header.Rcode}
	var ttl uint32

	answers := cacheable(msg.Answers)
	if msg.Header.Rcode == wire.RcodeSuccess && len(answers) > 0 {
		low, ok := lowestTTL(answers)
		if !ok {
			return // a TTL of zero means use once and forget, so we do
		}
		ttl = c.clamp(low)
		e.answers = retimed(answers, ttl)
	} else {
		// NXDOMAIN, or success with nothing in the answer section, which is
		// NODATA: the name exists and the type does not. Both are denials, and
		// RFC 2308 caches a denial only on the authority of the SOA that proves
		// it. No SOA, no entry.
		authority := cacheable(msg.Authority)
		low, ok := negativeTTL(authority)
		if !ok {
			return
		}
		ttl = low
		e.answers = retimed(answers, ttl)
		e.authority = retimed(authority, ttl)
	}

	now := time.Now()
	c.answers.put(keyFor(q), e, now, now.Add(time.Duration(ttl)*time.Second))
}

// reply rebuilds a response to q from the entry, with age seconds already spent.
// A negative age asks for the stale form, where every TTL is staleTTL.
//
// The header is built here rather than stored, and two flags in it are the
// reason. Authoritative is never set, because a cached answer is a copy and
// claiming otherwise misleads anything that trusts the bit. RecursionAvailable
// is always set, because reaching this cache means a recursive resolver is what
// answered.
//
// The rdata inside the returned records is shared with the cache, not copied.
// Callers pack these messages and never write to them, and copying every record
// on every hit would spend the time the cache exists to save. Treat the result
// as read-only.
func (e *entry) reply(q wire.Question, age int32) *wire.Message {
	msg := &wire.Message{
		Header:    wire.Header{Response: true, RecursionAvailable: true, Rcode: e.rcode},
		Questions: []wire.Question{q},
	}
	msg.Answers = aged(e.answers, age)
	msg.Authority = aged(e.authority, age)
	return msg
}

// Len reports how many answers are held, expired ones included.
func (c *Cache) Len() int { return c.answers.len() }

// Stats is a reading of the cache's counters.
type Stats struct {
	Entries     int
	Delegations int
	Hits        uint64
	Misses      uint64
	Stale       uint64
	Evictions   uint64
}

// Stats samples the counters. The fields are read independently, so they are
// consistent with each other only to within the time the read takes.
func (c *Cache) Stats() Stats {
	return Stats{
		Entries:     c.answers.len(),
		Delegations: c.delegations.len(),
		Hits:        c.hits.Load(),
		Misses:      c.misses.Load(),
		Stale:       c.stale.Load(),
		Evictions:   c.answers.evictions.Load() + c.delegations.evictions.Load(),
	}
}

// clamp applies the configured TTL floor and ceiling.
func (c *Cache) clamp(ttl uint32) uint32 {
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	return min(ttl, c.maxTTL)
}

// elapsed reports whole seconds since t, saturating at the range of a TTL.
func elapsed(t time.Time) int32 {
	secs := int64(time.Since(t) / time.Second)
	if secs < 0 {
		return 0
	}
	return int32(min(secs, 1<<31-1))
}

// cacheable drops the records that must not be stored and copies the rdata that
// would otherwise outlive the buffer it was decoded from.
//
// OPT is dropped because it is not zone data. The pseudo-record carries the
// EDNS0 state of one transaction, the payload size and flags of the party that
// sent it, and replaying another party's OPT to a client would advertise
// somebody else's capabilities as our own. The responder builds its own.
//
// Unknown.Data is copied because it is the one field left that aliases the
// message buffer. That was established by inspecting every RData type and then
// checking at runtime: a message carrying one record of every type was packed,
// unpacked, and the source buffer overwritten. Only Unknown.Data and Option.Data
// moved. TXT.Strings survives because decodeRData converts with string(b), which
// copies, and every Name survives because the decoder builds a fresh escape
// buffer. Option.Data cannot reach this far, since OPT is dropped just above.
//
// Retaining the alias would pin an entire message buffer in memory for the life
// of one small record, and on any path where that buffer is reused it would not
// be a leak but a record that silently changes after it was stored.
func cacheable(rrs []wire.RR) []wire.RR {
	out := make([]wire.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Type == wire.TypeOPT {
			continue
		}
		if u, ok := rr.Data.(wire.Unknown); ok {
			rr.Data = wire.Unknown{Kind: u.Kind, Data: append([]byte(nil), u.Data...)}
		}
		out = append(out, rr)
	}
	return out
}

// lowestTTL returns the smallest TTL in rrs, reporting false if any record must
// not be cached at all.
//
// A TTL of zero means use this answer for the transaction in hand and do not
// reuse it, so a set containing one is not cacheable as a set. A negative TTL is
// not a duration: the field is signed on the wire only by an accident of RFC
// 1035, and RFC 2181 section 8 says to treat the top bit as zero, which in
// practice means distrusting the record.
func lowestTTL(rrs []wire.RR) (uint32, bool) {
	if len(rrs) == 0 {
		return 0, false
	}
	low := uint32(1<<31 - 1)
	for _, rr := range rrs {
		if rr.TTL <= 0 {
			return 0, false
		}
		low = min(low, uint32(rr.TTL))
	}
	return low, true
}

// negativeTTL derives how long a denial may be cached from the SOA that proves
// it, per RFC 2308 section 5, reporting false if there is no usable SOA.
//
// The value is the smaller of the SOA's MINIMUM field and the TTL of the SOA
// record itself, capped at three hours. Those two are different types: MINIMUM
// is an unsigned 32-bit field of the rdata, while a record's TTL is signed. The
// conversion is deliberate and is guarded by the check above it, because a
// negative TTL would otherwise become an enormous unsigned one and cache a
// denial for a lifetime.
func negativeTTL(rrs []wire.RR) (uint32, bool) {
	for _, rr := range rrs {
		soa, ok := rr.Data.(wire.SOA)
		if !ok || rr.TTL <= 0 {
			continue
		}
		return min(soa.Minimum, uint32(rr.TTL), maxNegativeTTL), true
	}
	return 0, false
}

// retimed returns rrs with every TTL set to ttl.
//
// The whole set is stored under one deadline, so storing each record's original
// TTL alongside it would be a second, disagreeing account of when it expires.
// The one value is the smallest of them, so no record is ever served for longer
// than its own TTL allowed; a record with a longer TTL simply expires early,
// which costs a lookup and is always safe.
func retimed(rrs []wire.RR, ttl uint32) []wire.RR {
	for i := range rrs {
		rrs[i].TTL = int32(ttl)
	}
	return rrs
}

// aged returns rrs with age seconds deducted from every TTL, or with the stale
// TTL substituted when age is negative.
//
// Counting down is the point of the whole structure. A cache that replays the
// TTL it stored tells every client the answer is as fresh as the moment it was
// fetched, which defeats their caches as well as being a visible lie: two dig
// calls a minute apart showing the same TTL is the first thing anyone notices.
func aged(rrs []wire.RR, age int32) []wire.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]wire.RR, len(rrs))
	copy(out, rrs)
	for i := range out {
		switch {
		case age < 0:
			out[i].TTL = staleTTL
		case out[i].TTL > age:
			out[i].TTL -= age
		default:
			out[i].TTL = 0
		}
	}
	return out
}
