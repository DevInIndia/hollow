package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/control"
	"github.com/DevInIndia/hollow/internal/stats"
)

// controlServer starts a control socket over a collector the test controls, and
// returns its address.
func controlServer(t *testing.T, col *stats.Collector) string {
	t.Helper()

	ln, err := control.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("control.Listen() error = %v", err)
	}
	s := &control.Server{Collector: col, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(ctx, ln); err != nil {
			t.Errorf("control Serve() error = %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

func TestStatsPrintsWhatTheServerCounted(t *testing.T) {
	col := stats.New()
	col.CacheEntries = func() int { return 3 }
	col.Record(stats.Event{Name: "example.com.", CacheHit: true, Duration: 400 * time.Microsecond})
	col.Record(stats.Event{Name: "ads.example.", Blocked: true})
	addr := controlServer(t, col)

	var stdout, stderr strings.Builder
	if got := Stats([]string{"--target", addr}, &stdout, &stderr); got != ExitOK {
		t.Fatalf("Stats() = %d, want %d; stderr: %s", got, ExitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"2 queries", "1 blocked", "top names", "example.com.", "hit rate"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	// A p50 of 0.4 ms has to survive as a fraction. Rendered as an integer it
	// reads as zero, and a resolver that reports zero latency is not believable.
	if strings.Contains(out, "p50 0ms") {
		t.Errorf("a sub-millisecond p50 was rounded away:\n%s", out)
	}
}

func TestStatsJSONIsMachineReadable(t *testing.T) {
	col := stats.New()
	col.Record(stats.Event{Name: "example.com."})
	addr := controlServer(t, col)

	var stdout, stderr strings.Builder
	if got := Stats([]string{"--target", addr, "--json"}, &stdout, &stderr); got != ExitOK {
		t.Fatalf("Stats() = %d, want %d; stderr: %s", got, ExitOK, stderr.String())
	}
	var snap control.Snapshot
	if err := json.Unmarshal([]byte(stdout.String()), &snap); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if snap.QueriesTotal != 1 {
		t.Errorf("queries_total = %d, want 1", snap.QueriesTotal)
	}
}

// The most likely first experience of this verb is running it against a server
// started without --control, and "connection refused" on its own does not tell
// anybody what to do about that.
func TestStatsNamesTheFlagWhenNothingIsListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	var stdout, stderr strings.Builder
	if got := Stats([]string{"--target", addr}, &stdout, &stderr); got != ExitFailure {
		t.Errorf("Stats() = %d, want %d", got, ExitFailure)
	}
	if !strings.Contains(stderr.String(), "--control") {
		t.Errorf("the failure does not name the flag that fixes it:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("a failed stats wrote to stdout: %q", stdout.String())
	}
}

// An idle server divides nothing by nothing. The hit rate line is omitted rather
// than printed as a percentage of no lookups.
func TestStatsOnAnIdleServerPrintsNoRates(t *testing.T) {
	addr := controlServer(t, stats.New())

	var stdout, stderr strings.Builder
	if got := Stats([]string{"--target", addr}, &stdout, &stderr); got != ExitOK {
		t.Fatalf("Stats() = %d, want %d; stderr: %s", got, ExitOK, stderr.String())
	}
	out := stdout.String()
	if strings.Contains(out, "hit rate") {
		t.Errorf("a hit rate was computed over no lookups:\n%s", out)
	}
	if !strings.Contains(out, "0 queries") {
		t.Errorf("an idle server does not report itself:\n%s", out)
	}
}

func TestStatsRejectsBadArguments(t *testing.T) {
	tests := map[string][]string{
		"unrecognised flag":         {"--nope"},
		"a positional":              {"example.com"},
		"a timeout that is not one": {"--timeout", "soon"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if got := Stats(args, &stdout, &stderr); got != ExitFailure {
				t.Errorf("Stats() = %d, want %d", got, ExitFailure)
			}
			if stderr.Len() == 0 {
				t.Error("a failed stats explained nothing on stderr")
			}
		})
	}
}

func TestReportControlSaysWhereToAttach(t *testing.T) {
	var b strings.Builder
	reportControl(&b, nil)
	if b.Len() != 0 {
		t.Errorf("a server with no control socket announced one: %q", b.String())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	reportControl(&b, ln)
	if !strings.Contains(b.String(), ln.Addr().String()) {
		t.Errorf("the line does not carry the address: %q", b.String())
	}
}
