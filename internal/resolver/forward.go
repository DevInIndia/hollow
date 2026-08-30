package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/DevInIndia/hollow/internal/cache"
	"github.com/DevInIndia/hollow/internal/wire"
)

// ErrNoForwarder reports a Forwarder with nothing to forward to.
var ErrNoForwarder = errors.New("no forwarder configured")

// Forwarder answers by asking someone else, which is what every stub resolver
// and most home routers do.
//
// It exists because the iterative walk needs outbound UDP port 53 to arbitrary
// addresses on the internet, and a great many networks do not allow that.
// University and corporate networks routinely permit port 53 only to their own
// resolvers, and on such a network hollow would look broken rather than
// blocked. --forward is the answer, and it is a different program: the
// delegation path is not walked, so none of the checks that make the walk safe
// apply. What replaces them is the operator naming a server they trust.
//
// Forwarder satisfies the same method as Resolver, so everything above it, the
// blocklist, the coalescing map, the statistics and the reply construction, is
// unchanged and unaware of which one it is holding.
type Forwarder struct {
	// Transport carries each exchange. Resolve works on a copy with
	// RecursionDesired set, since the whole point is to have the other end do
	// the work.
	Transport Transport

	// Servers are tried in the order given. Not shuffled, unlike the root
	// hints: an operator writing two of these is expressing a preference, and
	// the second is a fallback rather than a peer.
	Servers []netip.AddrPort

	// Cache, when set, is the same cache the recursive path uses. A forwarded
	// answer is cached exactly as a resolved one is, so a second query for a
	// name costs nothing even though the first cost a round trip to somebody
	// else.
	Cache *cache.Cache
}

// Resolve answers one question by forwarding it.
//
// The signature and the Result are Resolver's, deliberately, so that a caller
// can hold either. The fields that describe a walk are the ones a walk would
// have filled in: Queries counts the exchanges this actually made, and CNAMEs
// is always empty because a forwarder returns the whole chain in one message
// and there is nothing collected across earlier exchanges to put back.
func (f *Forwarder) Resolve(ctx context.Context, q wire.Question) (*Result, error) {
	if q.Class == 0 {
		q.Class = wire.ClassIN
	}
	if len(f.Servers) == 0 {
		return nil, fmt.Errorf("resolver: %w", ErrNoForwarder)
	}

	if f.Cache != nil {
		if msg, ok := f.Cache.Answer(q); ok {
			return &Result{
				Reply:    &Reply{Msg: msg, Protocol: ProtocolCache},
				CacheHit: true,
			}, nil
		}
	}

	t := f.Transport
	t.RecursionDesired = true

	var (
		queries int
		last    error
	)
	for _, server := range f.Servers {
		queries++
		reply, err := t.Exchange(ctx, server, q)
		if err != nil {
			// A cancelled or expired context is the caller leaving, not this
			// server failing, and trying the next one would ignore the deadline
			// and report the wrong cause.
			if ctx.Err() != nil {
				return nil, err
			}
			last = err
			continue
		}
		if classify(reply.Msg, q) == KindFailure {
			// SERVFAIL and REFUSED both mean try the next one. A referral is
			// not in this set: a forwarder that hands back a delegation is
			// answering a question we did not ask, but it is still an answer
			// and passing it on beats inventing a failure.
			last = fmt.Errorf("%v answered rcode %d", server, reply.Msg.Header.Rcode)
			continue
		}
		if f.Cache != nil {
			f.Cache.StoreAnswer(q, reply.Msg)
		}
		return &Result{Reply: reply, Queries: queries}, nil
	}

	// Every forwarder failed. The same serve-stale trade the walk makes applies
	// here and for a stronger reason: when the only route off this network is
	// down, an expired answer may be the only answer there is.
	if f.Cache != nil && ctx.Err() == nil {
		if msg, ok := f.Cache.Stale(q); ok {
			return &Result{
				Reply:    &Reply{Msg: msg, Protocol: ProtocolCache},
				Queries:  queries,
				CacheHit: true,
				Stale:    true,
			}, nil
		}
	}
	return nil, fmt.Errorf("resolver: %d forwarders tried, last: %v: %w", len(f.Servers), last, ErrNoNameserver)
}
