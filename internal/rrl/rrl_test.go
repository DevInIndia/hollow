package rrl

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// The clock is injected rather than waited on. A rate limiter tested against
// the real clock either sleeps for seconds or asserts within a tolerance, and
// neither is necessary when the only thing the limiter reads is time.Now.
func testLimiter(t *testing.T, cfg Config) (*Limiter, func(time.Duration)) {
	t.Helper()
	l := New(cfg)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	l.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	return l, func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// The shape of the whole feature in one test: under the limit everything is
// sent, over it the responses stop, and every second one over is a truncated
// reply rather than silence.
func TestOverTheLimitRespondsWithSilenceAndEverySecondOneTruncated(t *testing.T) {
	l, _ := testLimiter(t, Config{PerSecond: 10, Window: time.Second, Slip: 2})

	// A new client starts with one second's worth, which at ten a second is
	// ten responses.
	for i := range 10 {
		if got := l.Allow(addr("192.0.2.7")); got != Send {
			t.Fatalf("response %d = %v, want %v while under the limit", i, got, Send)
		}
	}

	want := []Action{Drop, Truncate, Drop, Truncate}
	for i, w := range want {
		if got := l.Allow(addr("192.0.2.7")); got != w {
			t.Errorf("over-limit response %d = %v, want %v", i, got, w)
		}
	}

	limited, dropped, slipped, _, _, tracked := l.Stats()
	if limited != 4 || dropped != 2 || slipped != 2 {
		t.Errorf("limited/dropped/slipped = %d/%d/%d, want 4/2/2", limited, dropped, slipped)
	}
	if tracked != 1 {
		t.Errorf("tracked networks = %d, want 1", tracked)
	}
}

// Slip off means everything over the limit is dropped. Worth its own case
// because it is the configuration that turns the limiter into a denial of
// service against the server's own clients, and an operator choosing it should
// be choosing it.
func TestSlipZeroDropsEverythingOverTheLimit(t *testing.T) {
	l, _ := testLimiter(t, Config{PerSecond: 1, Window: time.Second, Slip: 0})
	l.Allow(addr("192.0.2.7"))
	for range 4 {
		if got := l.Allow(addr("192.0.2.7")); got != Drop {
			t.Fatalf("over-limit response = %v, want %v", got, Drop)
		}
	}
}

// The allowance refills with time rather than resetting at a boundary. A client
// that waits gets exactly what it waited for, not a whole new window.
func TestAllowanceRefillsWithTime(t *testing.T) {
	l, advance := testLimiter(t, Config{PerSecond: 10, Window: time.Second, Slip: 0})
	for range 10 {
		l.Allow(addr("192.0.2.7"))
	}
	if got := l.Allow(addr("192.0.2.7")); got != Drop {
		t.Fatalf("response = %v, want %v with the allowance spent", got, Drop)
	}

	// Two tenths of a second at ten a second is two responses, and no more.
	advance(200 * time.Millisecond)
	for i := range 2 {
		if got := l.Allow(addr("192.0.2.7")); got != Send {
			t.Errorf("response %d after refill = %v, want %v", i, got, Send)
		}
	}
	if got := l.Allow(addr("192.0.2.7")); got != Drop {
		t.Errorf("a third response = %v, want %v", got, Drop)
	}
}

// The allowance stops accruing at a window's worth. Without the cap, a client
// silent for an hour would arrive with an hour of credit, which is not a rate
// limit.
func TestUnusedAllowanceStopsAtOneWindow(t *testing.T) {
	l, advance := testLimiter(t, Config{PerSecond: 10, Window: 2 * time.Second, Slip: 0})
	l.Allow(addr("192.0.2.7"))
	advance(time.Hour)

	sent := 0
	for l.Allow(addr("192.0.2.7")) == Send {
		sent++
		if sent > 100 {
			t.Fatal("the allowance never ran out, so it is not capped")
		}
	}
	if sent != 20 {
		t.Errorf("responses after an hour idle = %d, want the 20 one window holds", sent)
	}
}

// Clients are counted by network, so an attacker cannot walk addresses inside
// one to get a fresh allowance for each.
func TestAddressesInOneNetworkShareABucket(t *testing.T) {
	l, _ := testLimiter(t, Config{PerSecond: 2, Window: time.Second, Slip: 0})
	l.Allow(addr("192.0.2.1"))
	l.Allow(addr("192.0.2.99"))
	if got := l.Allow(addr("192.0.2.250")); got != Drop {
		t.Errorf("a third address in 192.0.2.0/24 = %v, want %v", got, Drop)
	}

	// A different /24 is a different client.
	if got := l.Allow(addr("198.51.100.1")); got != Send {
		t.Errorf("another network = %v, want %v", got, Send)
	}
}

func TestIPv6IsCountedByItsFiftySixBitNetwork(t *testing.T) {
	l, _ := testLimiter(t, Config{PerSecond: 1, Window: time.Second, Slip: 0})
	l.Allow(addr("2001:db8:1:2::1"))
	if got := l.Allow(addr("2001:db8:1:2:ffff::9")); got != Drop {
		t.Errorf("the same /56 = %v, want %v", got, Drop)
	}
	if got := l.Allow(addr("2001:db8:1:ff00::1")); got != Send {
		t.Errorf("a different /56 = %v, want %v", got, Send)
	}
}

// A trusted network is not counted at all, which is what keeps a limiter that
// defaults to on from limiting the operator's own testing.
func TestATrustedNetworkIsExempt(t *testing.T) {
	l, _ := testLimiter(t, Config{
		PerSecond: 1,
		Window:    time.Second,
		Trusted:   []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	})
	for range 50 {
		if got := l.Allow(addr("127.0.0.1")); got != Send {
			t.Fatalf("a trusted client was limited: %v", got)
		}
	}
	if _, _, _, exempted, _, tracked := l.Stats(); exempted != 50 || tracked != 0 {
		t.Errorf("exempted = %d, tracked = %d, want 50 and 0", exempted, tracked)
	}
}

// The tracking table is itself an attack surface, so it is bounded. Under a
// flood from many forged sources the network actually being answered is touched
// on every packet, so it stays and the forgeries are what get evicted.
func TestTheTableStaysBoundedUnderAFloodOfSources(t *testing.T) {
	l, _ := testLimiter(t, Config{PerSecond: 1, Window: time.Second, Entries: 64})

	victim := addr("192.0.2.1")
	l.Allow(victim)
	for i := range 4096 {
		l.Allow(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))
		l.Allow(victim)
	}

	_, _, _, _, evicted, tracked := l.Stats()
	if tracked > 64 {
		t.Errorf("tracked = %d, want no more than the 64 cap", tracked)
	}
	if evicted == 0 {
		t.Error("nothing was evicted, so the cap was never reached")
	}
	// The victim is still being limited, which is the whole point of surviving
	// the flood.
	if got := l.Allow(victim); got == Send {
		t.Error("the network under attack was evicted and its allowance reset")
	}
}

// A nil limiter is the off switch, so the call site needs no condition around
// it.
func TestANilLimiterAllowsEverything(t *testing.T) {
	var l *Limiter
	for range 100 {
		if got := l.Allow(addr("192.0.2.1")); got != Send {
			t.Fatalf("nil limiter returned %v", got)
		}
	}
	if limited, _, _, _, _, tracked := l.Stats(); limited != 0 || tracked != 0 {
		t.Error("a nil limiter counted something")
	}
}

// A query whose transport could not report an address is not accounted against
// a client, because there is no client to account it against.
func TestAQueryWithNoClientAddressIsNotLimited(t *testing.T) {
	l, _ := testLimiter(t, Config{PerSecond: 1, Window: time.Second})
	for range 10 {
		if got := l.Allow(netip.Addr{}); got != Send {
			t.Fatalf("an address-less query was limited: %v", got)
		}
	}
}

// The limiter runs on every UDP query from every worker at once, so it has to
// be safe for that and is checked under the race detector.
func TestConcurrentClientsDoNotRaceOrLoseCount(t *testing.T) {
	l, _ := testLimiter(t, Config{PerSecond: 1, Window: time.Second, Slip: 0, Entries: 8})

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				l.Allow(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
				l.Allow(addr("198.51.100.1"))
			}
		}()
	}
	wg.Wait()

	limited, dropped, slipped, _, _, _ := l.Stats()
	if limited != dropped+slipped {
		t.Errorf("limited = %d, dropped + slipped = %d, so a response was counted twice or not at all",
			limited, dropped+slipped)
	}
	if limited == 0 {
		t.Error("nothing was limited by a limit of one a second under 2048 responses")
	}
}
