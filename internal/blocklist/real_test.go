package blocklist

import (
	"os"
	"runtime"
	"testing"
)

// TestTheRealList loads an actual published blocklist and reports what it cost.
//
// It is skipped unless HOLLOW_HOSTS names a file, because the repository does
// not carry a 2 MB copy of somebody else's list and a test that downloads one
// is a test that fails on a train. The numbers in the README come from here:
//
//	curl -o /tmp/hosts https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
//	HOLLOW_HOSTS=/tmp/hosts go test ./internal/blocklist -run TestTheRealList -v
//
// The assertions are the ones that matter whatever list is pointed at: the
// preamble did not become rules, something did load, and the machine's own name
// still resolves.
func TestTheRealList(t *testing.T) {
	path := os.Getenv("HOLLOW_HOSTS")
	if path == "" {
		t.Skip("set HOLLOW_HOSTS to a hosts file to measure a real list")
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	l, err := Load([]string{path}, nil)
	if err != nil {
		t.Fatalf("Load(%s): %v", path, err)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	exact, wildcard, allowed, skipped := l.Counts()
	t.Logf("%s: %d exact, %d wildcard, %d allowed, %d lines skipped",
		path, exact, wildcard, allowed, skipped)
	t.Logf("heap: %.1f MB for %d entries, %d bytes each",
		float64(after.HeapAlloc-before.HeapAlloc)/(1<<20),
		exact+wildcard,
		(after.HeapAlloc-before.HeapAlloc)/uint64(max(exact+wildcard, 1)))

	if exact+wildcard == 0 {
		t.Fatal("the list loaded no rules at all")
	}
	for _, n := range []string{"localhost.", "localhost.localdomain.", "local.", "broadcasthost."} {
		if l.Blocked(name(t, n)) {
			t.Errorf("%s is blocked; this resolver would break its own machine", n)
		}
	}

	runtime.KeepAlive(l)
}
