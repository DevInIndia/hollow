package stats

import (
	"cmp"
	"hash/maphash"
	"slices"
	"sync"
	"sync/atomic"
)

const (
	// Sixteen shards rather than the cache's 256. This is touched three times
	// per query where the cache is touched on every lookup during a walk, and
	// each shard carries a map whose memory is paid for whether or not anything
	// lands in it.
	topShards = 16

	// Entries admitted per shard, so 16384 in total across a counter.
	topPerShard = 1024
)

// counter tracks how often each key has been seen, without keeping anything
// sorted while queries are being answered.
//
// Sorting happens in top, which a TUI calls a few times a second, against an
// add that runs on every query. Keeping a heap or a sorted list current in the
// hot path would move that cost onto the path that must not pay it.
//
// The key stays a typed value rather than a string all the way to top: client
// addresses are counted as netip.Addr, which is comparable and needs no
// allocation to be used as a map key, and the conversion to text happens once
// per snapshot instead of once per query.
type counter[K comparable] struct {
	seed   maphash.Seed
	name   func(K) string
	shards [topShards]counterShard[K]

	// dropped counts keys refused because their shard was full. See add.
	dropped atomic.Uint64
}

type counterShard[K comparable] struct {
	mu     sync.Mutex
	counts map[K]uint64
}

func newCounter[K comparable](name func(K) string) *counter[K] {
	c := &counter[K]{seed: maphash.MakeSeed(), name: name}
	for i := range c.shards {
		c.shards[i].counts = make(map[K]uint64)
	}
	return c
}

// add records one sighting of k.
//
// A shard that has reached its cap stops admitting new keys and counts the
// refusal instead. This is the answer to unbounded cardinality: a random
// subdomain flood, which is a real and common attack on recursive resolvers,
// otherwise turns a statistics map into a memory exhaustion bug. Refusing new
// keys is O(1), where evicting the smallest would be a scan of the shard on
// every query during exactly the flood that must stay cheap.
//
// The bias this introduces is the useful direction. Keys already admitted keep
// counting, so a name that is genuinely frequent was almost certainly admitted
// long before any flood began, while the one-off names a flood consists of are
// precisely what a top-ten list should be leaving out. The count of refusals is
// reported, so a snapshot says when it is incomplete rather than implying it is
// exact.
func (c *counter[K]) add(k K) {
	s := &c.shards[maphash.Comparable(c.seed, k)%topShards]
	s.mu.Lock()
	if n, ok := s.counts[k]; ok {
		s.counts[k] = n + 1
	} else if len(s.counts) < topPerShard {
		s.counts[k] = 1
	} else {
		c.dropped.Add(1)
	}
	s.mu.Unlock()
}

// top returns the n most frequent keys, most frequent first.
//
// Ties break on the name so that two snapshots taken between the same two
// queries agree. Map iteration order would otherwise reorder equal counts on
// every call, which in a TUI refreshing several times a second reads as the
// list flickering for no reason.
func (c *counter[K]) top(n int) []CountedItem {
	var items []CountedItem
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, count := range s.counts {
			items = append(items, CountedItem{Name: c.name(k), Count: count})
		}
		s.mu.Unlock()
	}

	slices.SortFunc(items, func(a, b CountedItem) int {
		if d := cmp.Compare(b.Count, a.Count); d != 0 {
			return d
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// len reports how many distinct keys are being tracked.
func (c *counter[K]) len() int {
	var n int
	for i := range c.shards {
		c.shards[i].mu.Lock()
		n += len(c.shards[i].counts)
		c.shards[i].mu.Unlock()
	}
	return n
}
