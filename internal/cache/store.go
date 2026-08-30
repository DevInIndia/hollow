package cache

import (
	"container/list"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// shardCount is the number of independent locks the store is divided into.
//
// 256 is chosen against the server's worker pool, which is 64 goroutines wide.
// With four times as many shards as possible concurrent writers, uniform hashing
// puts the chance of any two workers colliding on a lock low enough that the
// mutex is not the bottleneck, while the fixed cost stays trivial: an empty
// shard is a nil map and an empty list, so the array costs a few kilobytes
// whether the cache holds ten entries or a hundred thousand.
const shardCount = 256

// store is a sharded, size-bounded map with least-recently-used eviction and
// per-entry absolute expiry.
//
// It is generic because there are two of them with genuinely different shapes:
// the answer cache maps a question to a message, and the delegation cache maps a
// zone to a list of addresses. They share every line of the locking, eviction
// and expiry logic and none of the DNS semantics, so the split falls here.
type store[K comparable, V any] struct {
	shards [shardCount]shard[K, V]

	// key projects a shard key to the string that is hashed. Both instances
	// project to a domain name, and both conversions are free because Name's
	// underlying type is string.
	key func(K) string

	// seed is per store and randomly chosen by the runtime.
	//
	// This is a defence, not a detail. Shard selection with a fixed hash is
	// attacker-controlled: a client that can name arbitrary domains can compute
	// a set that all land in one shard and collapse the cache to a single lock,
	// turning a 256-way structure into a queue. A random seed makes that set
	// unknowable and unstable across restarts.
	seed maphash.Seed

	// limit is the per-shard entry cap, not the total.
	limit int

	evictions atomic.Uint64
}

type shard[K comparable, V any] struct {
	// A read moves an entry to the front of the LRU list, so every lookup is a
	// mutation and a sync.RWMutex would hand out read locks that cannot be
	// honoured. The cheaper lock is the wrong lock here.
	mu    sync.Mutex
	index map[K]*list.Element
	lru   list.List // front is most recently used
}

// slot is one stored entry. Nothing writes to a slot after it is linked into a
// shard: an overwrite allocates a new slot and replaces the old one. That is
// what makes it safe for get to return a slot and for the caller to read it
// after the shard lock has been dropped.
type slot[K comparable, V any] struct {
	key     K
	value   V
	stored  time.Time
	expires time.Time
}

func newStore[K comparable, V any](entries int, key func(K) string) *store[K, V] {
	// Round the per-shard cap up, so a cache configured smaller than the shard
	// count still holds one entry per shard rather than zero and evicting
	// everything it is asked to remember.
	limit := (entries + shardCount - 1) / shardCount
	if limit < 1 {
		limit = 1
	}
	return &store[K, V]{key: key, seed: maphash.MakeSeed(), limit: limit}
}

func (s *store[K, V]) shard(k K) *shard[K, V] {
	return &s.shards[maphash.String(s.seed, s.key(k))%shardCount]
}

// get returns the slot held for k, whether or not it has expired.
//
// Expiry is the caller's decision because the two callers disagree: a normal
// lookup wants fresh entries only, and a serve-stale lookup wants exactly the
// expired ones. Reporting presence and letting the caller compare the deadline
// keeps that policy out of the storage layer.
func (s *store[K, V]) get(k K) (*slot[K, V], bool) {
	sh := s.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	el, ok := sh.index[k]
	if !ok {
		return nil, false
	}
	sh.lru.MoveToFront(el)
	return el.Value.(*slot[K, V]), true
}

// put stores v under k, replacing any existing entry, and evicts the least
// recently used entry of that shard if the shard is over its cap.
func (s *store[K, V]) put(k K, v V, stored, expires time.Time) {
	sh := s.shard(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if sh.index == nil {
		sh.index = make(map[K]*list.Element)
	}
	fresh := &slot[K, V]{key: k, value: v, stored: stored, expires: expires}
	if el, ok := sh.index[k]; ok {
		el.Value = fresh
		sh.lru.MoveToFront(el)
		return
	}
	sh.index[k] = sh.lru.PushFront(fresh)

	for len(sh.index) > s.limit {
		back := sh.lru.Back()
		if back == nil {
			break
		}
		sh.lru.Remove(back)
		delete(sh.index, back.Value.(*slot[K, V]).key)
		s.evictions.Add(1)
	}
}

// len counts entries across every shard, expired ones included.
//
// The count is a sum of independently locked shards, so it is a reading taken
// over an interval rather than at an instant. That is what a size gauge wants,
// and stopping the world to make it exact would cost more than the number is
// worth.
func (s *store[K, V]) len() int {
	var n int
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		n += len(sh.index)
		sh.mu.Unlock()
	}
	return n
}
