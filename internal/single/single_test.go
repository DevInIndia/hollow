package single

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// awaitWaiters blocks until at least n callers are queued behind the call under
// key, and reports whether they arrived.
//
// It reaches into the group's own state, which is what makes these tests
// deterministic rather than dependent on the scheduler. Arriving at Do and
// being registered as a waiter are different moments, and only the second one
// says the coalescing actually happened. A test that released the work after
// the first is asserting nothing: the stragglers find the call already retired
// and start their own, which is correct behaviour that looks like a bug.
//
// It cannot call t.Fatal, because it runs on the goroutine that owns the call
// rather than on the test's own. The caller asserts instead.
func awaitWaiters[K comparable, V any](g *Group[K, V], key K, n int) bool {
	for range 2000 {
		g.mu.Lock()
		c, ok := g.calls[key]
		var got int
		if ok {
			got = c.waiters
		}
		g.mu.Unlock()
		if got >= n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// The case the package exists for: many callers want one name at once, and only
// one of them should go and get it.
func TestConcurrentCallsRunTheWorkOnce(t *testing.T) {
	var g Group[string, int]
	var runs atomic.Int64

	// The call is held open until every other caller has queued behind it, so
	// the assertion below is about coalescing rather than about which
	// goroutine the scheduler happened to run first.
	const callers = 64
	var queued atomic.Bool
	var wg sync.WaitGroup
	results := make([]int, callers)
	sharedFlags := make([]bool, callers)

	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err, shared := g.Do("example.com.", func() (int, error) {
				runs.Add(1)
				queued.Store(awaitWaiters(&g, "example.com.", callers-1))
				return 42, nil
			})
			if err != nil {
				t.Errorf("caller %d: unexpected error %v", i, err)
			}
			results[i], sharedFlags[i] = v, shared
		}()
	}
	wg.Wait()

	if !queued.Load() {
		t.Fatalf("only some of the %d callers ever queued behind the call", callers)
	}

	if n := runs.Load(); n != 1 {
		t.Errorf("the work ran %d times, want 1", n)
	}
	for i, v := range results {
		if v != 42 {
			t.Errorf("caller %d got %d, want 42", i, v)
		}
	}
	// Every caller is told the result was shared, the one that owned the call
	// included. The flag describes the result, not the role: an answer handed
	// to sixty-four callers is a shared answer no matter which of them fetched
	// it, and a caller that wants to know it did the work can see that from the
	// side effects of its own fn.
	var shared int
	for _, s := range sharedFlags {
		if s {
			shared++
		}
	}
	if shared != callers {
		t.Errorf("%d callers reported sharing, want all %d", shared, callers)
	}
	if g.Len() != 0 {
		t.Errorf("%d calls still registered after all of them finished", g.Len())
	}
}

// A Group is not a cache. It holds a key only while work is in flight under it,
// so two calls that do not overlap both run.
func TestSequentialCallsBothRun(t *testing.T) {
	var g Group[string, int]
	var runs atomic.Int64
	fn := func() (int, error) { runs.Add(1); return 1, nil }

	for range 3 {
		if _, _, shared := g.Do("k", fn); shared {
			t.Error("a call with nobody else waiting reported that it was shared")
		}
	}
	if n := runs.Load(); n != 3 {
		t.Errorf("the work ran %d times, want 3: a finished call was still being attached to", n)
	}
}

func TestDifferentKeysDoNotCoalesce(t *testing.T) {
	var g Group[string, string]
	var wg sync.WaitGroup
	release := make(chan struct{})
	got := make([]string, 2)

	for i, key := range []string{"a.example.com.", "b.example.com."} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _, _ = g.Do(key, func() (string, error) {
				<-release
				return key, nil
			})
		}()
	}
	// Both must be able to run at once, so releasing them together deadlocks
	// if the group serialised on the wrong thing.
	close(release)
	wg.Wait()

	if got[0] != "a.example.com." || got[1] != "b.example.com." {
		t.Errorf("got %q and %q, want each key its own result", got[0], got[1])
	}
}

func TestErrorsAreShared(t *testing.T) {
	var g Group[string, int]
	want := errors.New("upstream is down")

	var wg sync.WaitGroup
	errs := make([]error, 8)

	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err, _ := g.Do("k", func() (int, error) {
				awaitWaiters(&g, "k", 7)
				return 0, want
			})
			errs[i] = err
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, want) {
			t.Errorf("caller %d got error %v, want %v", i, err, want)
		}
	}
}

// A panic must not park every waiter for the life of the process, and it must
// not reach them as a zero value with a nil error, which reads as a call that
// succeeded and returned nothing.
func TestPanicUnblocksWaitersWithAnError(t *testing.T) {
	var g Group[string, int]
	var wg sync.WaitGroup

	// started is closed from inside fn, so the waiter below is only launched
	// once this goroutine is definitely the one that owns the call. Launching
	// both and hoping would let the waiter win the race and become the leader,
	// at which point the test would be exercising nothing.
	started := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The panic belongs to the caller that caused it. Recovering here is
		// what this test asserts the package does not do for it.
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed instead of reaching the caller that caused it")
			}
		}()
		g.Do("k", func() (int, error) {
			close(started)
			if !awaitWaiters(&g, "k", 1) {
				t.Error("no waiter ever queued behind the call that panicked")
			}
			panic("resolver fell over")
		})
	}()

	<-started
	waited := make(chan error, 1)
	go func() {
		_, err, _ := g.Do("k", func() (int, error) { return 99, nil })
		waited <- err
	}()

	wg.Wait()

	if err := <-waited; !errors.Is(err, ErrAbandoned) {
		t.Errorf("waiter got %v, want %v", err, ErrAbandoned)
	}
	if g.Len() != 0 {
		t.Errorf("%d calls left registered after a panic", g.Len())
	}
}

// The zero Group is usable, which matters because it is embedded in a struct
// literal rather than constructed.
func TestZeroGroupIsUsable(t *testing.T) {
	var g Group[int, string]
	v, err, shared := g.Do(1, func() (string, error) { return "ok", nil })
	if v != "ok" || err != nil || shared {
		t.Errorf("Do() = %q, %v, %v, want \"ok\", nil, false", v, err, shared)
	}
}
