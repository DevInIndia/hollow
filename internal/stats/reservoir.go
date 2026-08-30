package stats

import (
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// reservoirSize is how many durations are kept. 1024 samples put the p99 on
// roughly ten of them, which is enough for the figure to mean something and
// small enough that sorting it on every snapshot is free.
const reservoirSize = 1024

// reservoir holds a bounded uniform sample of every latency seen.
//
// The alternative, keeping every duration, is unbounded memory in exchange for
// a precision nobody reads: a p99 quoted to the microsecond over a million
// samples answers no question that a p99 over a thousand does not. The
// alternative in the other direction, a running average, hides exactly the tail
// that percentiles exist to expose.
//
// Algorithm R, Vitter 1985. Every duration ever seen has an equal chance of
// being among the samples held, which is what makes the percentiles a claim
// about the whole run rather than about the recent past.
type reservoir struct {
	mu      sync.Mutex
	samples []time.Duration
	seen    uint64
	rand    *rand.Rand
}

func newReservoir() *reservoir {
	// Seeded from the global source, which is randomly seeded per process and
	// is safe to call concurrently. The local generator is not, which is why it
	// lives under the mutex below rather than beside it.
	return &reservoir{
		samples: make([]time.Duration, 0, reservoirSize),
		rand:    rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	}
}

// add offers one duration to the sample.
//
// This is the one lock on the query path that is not sharded. The critical
// section is a compare, a random number and a store, with no allocation and no
// system call, so it is shorter than the atomic counter increments that
// surround it are likely to make anyone believe. If it ever shows up in a
// profile the fix is to shard it and merge at snapshot, and until it does that
// would be complexity bought with nothing.
func (r *reservoir) add(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.seen++
	if len(r.samples) < cap(r.samples) {
		r.samples = append(r.samples, d)
		return
	}
	// Past the point where the reservoir is full, the nth duration replaces a
	// uniformly chosen sample with probability size/n. That decaying
	// probability is the whole of Algorithm R, and it is what keeps every
	// duration equally likely to be held no matter how many have been seen.
	if j := r.rand.Uint64N(r.seen); j < uint64(len(r.samples)) {
		r.samples[j] = d
	}
}

// percentiles returns the 50th and 99th by nearest rank.
//
// Both come out of one sort because the caller wants both, and sorting a copy
// rather than the samples themselves keeps add from having to care what order
// the reservoir is in.
func (r *reservoir) percentiles() (p50, p99 time.Duration) {
	r.mu.Lock()
	held := slices.Clone(r.samples)
	r.mu.Unlock()

	if len(held) == 0 {
		return 0, 0
	}
	slices.Sort(held)
	return nearestRank(held, 0.50), nearestRank(held, 0.99)
}

// nearestRank picks the sample at the given quantile without interpolating.
//
// Interpolating between two samples would invent a duration that was never
// measured. Reporting one that was is the more honest of the two, and at this
// sample size the difference is noise.
func nearestRank(sorted []time.Duration, q float64) time.Duration {
	i := int(q * float64(len(sorted)))
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// count reports how many durations have been offered, which is not the same as
// how many are held once the reservoir is full.
func (r *reservoir) count() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen
}
