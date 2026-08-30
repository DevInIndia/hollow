// Package single collapses concurrent identical calls into one.
//
// A cache answers the second query for a name. It does nothing for the second
// query that arrives while the first is still in flight, and that is the case a
// DNS server sees constantly: a page load fires a dozen lookups for the same
// host at once, and a cold name under a worker pool sixty-four wide can start
// sixty-four identical walks from the root. Each of those walks costs several
// round trips, and every one of them ends by storing the same answer the others
// were about to store.
//
// The window this closes is exactly the length of one resolution, which is also
// the most expensive thing this program does.
package single

import (
	"errors"
	"sync"
)

// ErrAbandoned is returned to waiters when the call they were waiting on ended
// without producing a result, which in practice means fn panicked.
//
// The panic itself is left to unwind the caller that caused it, because a panic
// is a bug and swallowing it here would hide the bug in every goroutine except
// the one nobody is looking at. What must not happen is waiters receiving a
// zero value and a nil error, which reads as a successful call that returned
// nothing.
var ErrAbandoned = errors.New("single: call ended without a result")

// Group deduplicates calls by key.
//
// The zero value is ready to use. It is generic over the key as well as the
// value so that callers key on whatever they already have, which for this
// program is a wire.Question and needs no string built for it on every query.
type Group[K comparable, V any] struct {
	mu    sync.Mutex
	calls map[K]*call[V]
}

type call[V any] struct {
	done chan struct{}

	// val and err are written once by the caller that owns the call, before
	// done is closed, and read by waiters only after done is closed. The
	// channel close is the happens-before edge that makes that safe without a
	// lock around the fields themselves.
	val V
	err error

	// waiters is guarded by the group's mutex, not by the channel, because it
	// is incremented while the call is still running.
	waiters int
}

// Do runs fn under key, or waits for the call already running under it.
//
// The third return reports that the result went to more than one caller. It
// describes the result rather than the role, so the caller that ran fn sees it
// too: an answer handed to sixty-four callers is a shared answer whichever of
// them fetched it.
//
// This is not a cache and holds nothing after the call ends: a key is live only
// while work is in flight under it. Two calls that do not overlap in time both
// run fn.
//
// The context is deliberately not a parameter. The first caller's fn carries
// whatever context that caller chose, and waiters receive its outcome including
// its cancellation. That is the honest shape of sharing one piece of work, and
// the alternative, giving the shared call a context detached from every caller,
// would let work outlive everyone who wanted it.
func (g *Group[K, V]) Do(key K, fn func() (V, error)) (V, error, bool) {
	g.mu.Lock()
	if c, ok := g.calls[key]; ok {
		c.waiters++
		g.mu.Unlock()
		<-c.done
		return c.val, c.err, true
	}
	c := &call[V]{done: make(chan struct{})}
	if g.calls == nil {
		g.calls = make(map[K]*call[V])
	}
	g.calls[key] = c
	g.mu.Unlock()

	// finished distinguishes fn returning from fn panicking. The deferred
	// close has to run either way, because a call that never closes its channel
	// parks every waiter on it for the life of the process.
	var finished bool
	defer func() {
		if !finished {
			c.err = ErrAbandoned
		}
		g.finish(key, c)
	}()

	c.val, c.err = fn()
	finished = true

	g.mu.Lock()
	shared := c.waiters > 0
	g.mu.Unlock()
	return c.val, c.err, shared
}

// finish retires a call: out of the map first, then the channel closed.
//
// The order is the whole correctness argument. Closing first leaves a window in
// which the map still holds a finished call, so a caller arriving in that
// window attaches to it and is handed a result computed before it asked,
// silently stretching the coalescing window past the work it was meant to
// cover. Removing it first means such a caller finds nothing and starts a fresh
// call, which is what it came for.
//
// The map entry is compared before deleting rather than deleted by key alone.
// By the time this runs another caller may already have installed its own call
// under the same key, and deleting that one would leave it unreachable to every
// caller that follows while it is still running.
func (g *Group[K, V]) finish(key K, c *call[V]) {
	g.mu.Lock()
	if g.calls[key] == c {
		delete(g.calls, key)
	}
	g.mu.Unlock()
	close(c.done)
}

// Len reports how many calls are in flight. It exists for tests and for a stats
// snapshot, and is a reading over an interval rather than at an instant.
func (g *Group[K, V]) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.calls)
}

// Waiting reports how many callers are queued behind in-flight calls, which is
// the work this package is currently saving.
func (g *Group[K, V]) Waiting() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	var n int
	for _, c := range g.calls {
		n += c.waiters
	}
	return n
}
