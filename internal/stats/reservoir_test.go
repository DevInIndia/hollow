package stats

import (
	"sync"
	"testing"
	"time"
)

// Below the reservoir's capacity nothing is sampled away, so the percentiles
// are exact and can be asserted rather than bounded.
func TestPercentilesUnderCapacityAreExact(t *testing.T) {
	r := newReservoir()
	for i := 1; i <= 1000; i++ {
		r.add(time.Duration(i) * time.Millisecond)
	}

	p50, p99 := r.percentiles()
	if want := 501 * time.Millisecond; p50 != want {
		t.Errorf("p50 = %v, want %v", p50, want)
	}
	if want := 991 * time.Millisecond; p99 != want {
		t.Errorf("p99 = %v, want %v", p99, want)
	}
	if p50 >= p99 {
		t.Errorf("p50 %v is not below p99 %v", p50, p99)
	}
}

func TestEmptyReservoirReportsZero(t *testing.T) {
	p50, p99 := newReservoir().percentiles()
	if p50 != 0 || p99 != 0 {
		t.Errorf("percentiles() = %v, %v on an empty reservoir, want 0, 0", p50, p99)
	}
}

func TestSingleSampleIsBothPercentiles(t *testing.T) {
	r := newReservoir()
	r.add(7 * time.Millisecond)
	p50, p99 := r.percentiles()
	if p50 != 7*time.Millisecond || p99 != 7*time.Millisecond {
		t.Errorf("percentiles() = %v, %v, want both 7ms", p50, p99)
	}
}

// Memory is bounded no matter how many durations are offered, which is the
// reason a reservoir is here instead of a slice of everything.
func TestReservoirStopsGrowing(t *testing.T) {
	r := newReservoir()
	const offered = 100000
	for i := range offered {
		r.add(time.Duration(i) * time.Microsecond)
	}

	r.mu.Lock()
	held := len(r.samples)
	r.mu.Unlock()

	if held != reservoirSize {
		t.Errorf("the reservoir holds %d samples, want %d", held, reservoirSize)
	}
	if got := r.count(); got != offered {
		t.Errorf("count() = %d, want %d: the count is of what was offered", got, offered)
	}
}

// The sample has to cover the whole run rather than the start of it. Ten
// thousand durations are offered in ascending order, so a reservoir that stopped
// replacing once it filled would hold nothing above the first thousand and its
// p99 would be far too low.
func TestLaterSamplesStillReachTheReservoir(t *testing.T) {
	r := newReservoir()
	const offered = 10000
	for i := 1; i <= offered; i++ {
		r.add(time.Duration(i) * time.Millisecond)
	}

	_, p99 := r.percentiles()

	// The true p99 of 1..10000 is 9900. A reservoir holding only the first
	// thousand would top out at 1000. The bound is loose because this is a
	// random sample and the test must not be flaky, but the two hypotheses are
	// nowhere near each other.
	if p99 < 5000*time.Millisecond {
		t.Errorf("p99 = %v, want something near 9.9s: late durations are not being sampled", p99)
	}
	if p99 > time.Duration(offered)*time.Millisecond {
		t.Errorf("p99 = %v, above the largest duration ever offered", p99)
	}
}

func TestConcurrentReservoirUse(t *testing.T) {
	r := newReservoir()
	var wg sync.WaitGroup
	for w := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 1000 {
				r.add(time.Duration(w*1000+i) * time.Microsecond)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 500 {
			r.percentiles()
		}
	}()
	wg.Wait()

	if got := r.count(); got != 16000 {
		t.Errorf("count() = %d, want 16000", got)
	}
}
